"""
ephemeral_tor_manager.py
========================

Dynamic Ephemeral Tor Job Architecture for GHOST Protocol.

Provides per-job isolation across five distinct layers:
1. Tor Daemon Isolation (dedicated DataDirectory & torrc per job)
2. SOCKS Port Isolation (unique TCP port pair per job via PortAllocator)
3. Browser Process Isolation (separate Playwright/browser instances per job)
4. Browser Profile Isolation (dedicated user_data_dir path per job)
5. Observation-Job Isolation (isolated job state, evidence, and session ID)

Components:
- PortAllocator: Thread-safe allocator for unique TCP SOCKS and Control port pairs.
- TorInstance: Manages a dedicated Tor daemon instance or container lifecycle.
- TorInstanceManager: Registry for creating, tracking, and cleaning up Tor instances.
- ObservationJob: Encapsulates the entire lifecycle of a single GHOST observation job.
- ObservationJobManager: High-level registry for multi-job orchestration.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import enum
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.observer.tor_observation_controller import (
    AccessState,
    ControllerConfig,
    ControllerError,
    Engine,
    ObservationResult,
    TorObservationController,
    check_tor_gateway,
)

logger = logging.getLogger("ephemeral_tor_manager")
logger.addHandler(logging.NullHandler())

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SCRATCH_DIR = PROJECT_ROOT / "scratch"
TOR_INSTANCES_DIR = SCRATCH_DIR / "tor_instances"
PROFILES_DIR = SCRATCH_DIR / "profiles"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# PortAllocator: Thread-safe TCP port pair management
# --------------------------------------------------------------------------- #

class PortAllocator:
    """Thread-safe allocator for unique TCP SOCKS and Control port pairs.
    Default range: SOCKS 9100-9800, Control 9200-9900."""

    def __init__(self, start_socks_port: int = 9102, max_ports: int = 200) -> None:
        self.start_socks_port = start_socks_port
        self.max_ports = max_ports
        self._lock = threading.Lock()
        self._allocated_socks: set[int] = set()

    @staticmethod
    def is_port_available(port: int, host: str = "127.0.0.1") -> bool:
        """Tests whether a TCP port is free on host."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return True
            except OSError:
                return False

    def allocate_port_pair(self) -> Tuple[int, int]:
        """Finds and allocates the next available (SOCKS_port, Control_port) pair."""
        with self._lock:
            for offset in range(0, self.max_ports * 2, 2):
                socks_port = self.start_socks_port + offset
                control_port = socks_port + 100
                if socks_port in self._allocated_socks:
                    continue
                if self.is_port_available(socks_port) and self.is_port_available(control_port):
                    self._allocated_socks.add(socks_port)
                    logger.info("Allocated port pair: SOCKS=%d, Control=%d", socks_port, control_port)
                    return socks_port, control_port
            raise RuntimeError("No available TCP port pairs in allocation range")

    def release_port_pair(self, socks_port: int, control_port: int) -> None:
        """Releases allocated ports back to the pool."""
        with self._lock:
            self._allocated_socks.discard(socks_port)
            logger.info("Released port pair: SOCKS=%d, Control=%d", socks_port, control_port)


# Global singleton PortAllocator
_global_port_allocator = PortAllocator()


# --------------------------------------------------------------------------- #
# TorInstance: Dedicated Tor daemon process or container manager
# --------------------------------------------------------------------------- #

class TorInstanceStatus(str, enum.Enum):
    UNINITIALIZED = "UNINITIALIZED"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    READY = "READY"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class TorInstance:
    """Manages an isolated temporary Tor daemon for a specific observation job."""

    def __init__(self, job_id: str, socks_port: int, control_port: int,
                 base_dir: Optional[Path] = None) -> None:
        self.job_id = job_id
        self.socks_port = socks_port
        self.control_port = control_port
        self.base_dir = base_dir or (TOR_INSTANCES_DIR / job_id)
        self.data_dir = self.base_dir / "data"
        self.torrc_path = self.base_dir / "torrc"
        self.pid_file = self.base_dir / "tor.pid"
        self.proc: Optional[subprocess.Popen] = None
        self.container_name: Optional[str] = None
        self.status = TorInstanceStatus.UNINITIALIZED
        self.error: Optional[str] = None

    @property
    def proxy_url(self) -> str:
        return f"socks5h://127.0.0.1:{self.socks_port}"

    def generate_torrc(self) -> str:
        """Generates a strict, job-specific torrc configuration string."""
        self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        torrc_content = (
            f"# Tor Configuration for GHOST Job: {self.job_id}\n"
            f"SocksPort 127.0.0.1:{self.socks_port}\n"
            f"ControlPort 127.0.0.1:{self.control_port}\n"
            f"DataDirectory {self.data_dir.resolve()}\n"
            f"PidFile {self.pid_file.resolve()}\n"
            f"CookieAuthentication 1\n"
            f"AvoidDisjointSockets 1\n"
        )
        self.torrc_path.write_text(torrc_content, encoding="utf-8")
        return torrc_content

    async def verify_socks_readiness(self, timeout: float = 15.0) -> bool:
        """Polls SOCKS5 port until SOCKS5 handshake succeeds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            res = await check_tor_gateway(self.proxy_url, timeout=2.0, verify_exit=False)
            if res.ok:
                return True
            await asyncio.sleep(0.5)
        return False

    async def start(self, timeout: float = 30.0) -> bool:
        """Launches the dedicated Tor daemon and waits for SOCKS5 readiness."""
        if self.status in (TorInstanceStatus.BOOTSTRAPPING, TorInstanceStatus.READY):
            return True

        self.status = TorInstanceStatus.BOOTSTRAPPING
        self.generate_torrc()

        # 1. Try launching native tor binary if installed on system
        tor_binary = shutil.which("tor")
        if tor_binary and os.path.exists(tor_binary):
            logger.info("[%s] Launching native Tor process: %s -f %s", self.job_id, tor_binary, self.torrc_path)
            try:
                cmd = [tor_binary, "-f", str(self.torrc_path.resolve())]
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
            except Exception as exc:
                logger.warning("[%s] Failed to launch native tor: %s", self.job_id, exc)

        # 2. Fallback to Docker container if native binary is unavailable
        if self.proc is None:
            c_name = f"ghost-tor-{self.job_id.lower().replace('_', '-')}"
            logger.info("[%s] Spawning Docker Tor instance container: %s", self.job_id, c_name)
            cmd = [
                "docker", "run", "-d",
                "--name", c_name,
                "--network", "darkwatch_labs_darkwatch-net",
                "-p", f"127.0.0.1:{self.socks_port}:9050",
                "-p", f"127.0.0.1:{self.control_port}:9051",
                "darkwatch_labs-darkwatch-tor-router:latest"
            ]
            try:
                subprocess.run(["docker", "rm", "-f", c_name], capture_output=True, timeout=5)
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    self.container_name = c_name
                else:
                    logger.warning("[%s] Docker container launch returned %d: %s", self.job_id, res.returncode, res.stderr)
            except Exception as exc:
                logger.warning("[%s] Docker container launch failed: %s", self.job_id, exc)

        # Wait for SOCKS5 socket readiness
        ready = await self.verify_socks_readiness(timeout=timeout)
        if ready:
            self.status = TorInstanceStatus.READY
            logger.info("[%s] Tor instance READY on %s", self.job_id, self.proxy_url)
            return True

        # Secondary check: if port 9050 is active as system gateway, fallback to proxy 9050
        fallback_check = await check_tor_gateway("socks5h://127.0.0.1:9050", timeout=2.0)
        if fallback_check.ok:
            logger.info("[%s] Fallback to primary Tor SOCKS gateway 127.0.0.1:9050", self.job_id)
            self.socks_port = 9050
            self.status = TorInstanceStatus.READY
            return True

        self.status = TorInstanceStatus.FAILED
        self.error = f"Tor SOCKS5 port {self.socks_port} did not become ready within {timeout}s"
        logger.error("[%s] Tor instance start failed: %s", self.job_id, self.error)
        await self.stop()
        return False

    async def stop(self) -> bool:
        """Terminates process/container and removes temporary directories."""
        self.status = TorInstanceStatus.STOPPED
        # Terminate subprocess if active
        if self.proc is not None:
            try:
                self.proc.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    self.proc.wait(timeout=3)
            except Exception:
                with contextlib.suppress(Exception):
                    self.proc.kill()
            self.proc = None

        # Stop Docker container if active
        if self.container_name:
            c_name, self.container_name = self.container_name, None
            try:
                subprocess.run(["docker", "rm", "-f", c_name], capture_output=True, timeout=5)
            except Exception as exc:
                logger.debug("[%s] Error stopping container %s: %s", self.job_id, c_name, exc)

        # Cleanup temporary files
        with contextlib.suppress(Exception):
            if self.base_dir.exists():
                shutil.rmtree(self.base_dir, ignore_errors=True)

        logger.info("[%s] Tor instance stopped and cleaned up", self.job_id)
        return True


# --------------------------------------------------------------------------- #
# TorInstanceManager: Global manager for Tor daemons
# --------------------------------------------------------------------------- #

class TorInstanceManager:
    """Registry for creating, tracking, and cleaning up Tor instances."""

    def __init__(self, allocator: Optional[PortAllocator] = None) -> None:
        self.allocator = allocator or _global_port_allocator
        self.instances: Dict[str, TorInstance] = {}

    async def create_instance(self, job_id: str) -> TorInstance:
        """Allocates ports and initializes a new TorInstance for job_id."""
        if job_id in self.instances:
            return self.instances[job_id]

        socks_port, control_port = self.allocator.allocate_port_pair()
        instance = TorInstance(job_id, socks_port, control_port)
        self.instances[job_id] = instance
        return instance

    async def stop_instance(self, job_id: str) -> bool:
        """Stops and cleans up TorInstance for job_id."""
        instance = self.instances.pop(job_id, None)
        if instance is None:
            return False
        success = await instance.stop()
        self.allocator.release_port_pair(instance.socks_port, instance.control_port)
        return success

    def cleanup_orphans(self) -> None:
        """Scans scratch/tor_instances for orphaned DataDirectory folders."""
        if not TOR_INSTANCES_DIR.exists():
            return
        for child in TOR_INSTANCES_DIR.iterdir():
            if child.is_dir():
                pid_file = child / "tor.pid"
                if pid_file.exists():
                    with contextlib.suppress(Exception):
                        pid = int(pid_file.read_text().strip())
                        os.kill(pid, signal.SIGKILL)
                shutil.rmtree(child, ignore_errors=True)


# --------------------------------------------------------------------------- #
# ObservationJob State & Core Class
# --------------------------------------------------------------------------- #

class JobState(str, enum.Enum):
    CREATED = "CREATED"
    TOR_BOOTSTRAPPING = "TOR_BOOTSTRAPPING"
    READY = "READY"
    OBSERVING = "OBSERVING"
    BROWSER_REQUIRED = "BROWSER_REQUIRED"
    STOPPED = "STOPPED"
    CLEANED_UP = "CLEANED_UP"
    ERROR = "ERROR"


class ObservationJob:
    """Encapsulates the complete five-layer isolated lifecycle of a single GHOST observation job."""

    def __init__(self, target_url: str, job_id: Optional[str] = None,
                 instance_manager: Optional[TorInstanceManager] = None,
                 enable_browser: bool = True, human_timeout: float = 900.0) -> None:
        self.job_id = job_id or f"JOB-{uuid.uuid4().hex[:8].upper()}"
        self.target_url = target_url
        self.manager = instance_manager or TorInstanceManager()
        self.enable_browser = enable_browser
        self.human_timeout = human_timeout
        self.profile_dir = PROFILES_DIR / self.job_id
        self.lock_path = SCRATCH_DIR / "locks" / f"{self.job_id}.lock"
        self.state = JobState.CREATED
        self.created_at = _utcnow()
        self.tor_instance: Optional[TorInstance] = None
        self.controller: Optional[TorObservationController] = None
        self.last_result: Optional[ObservationResult] = None
        self.error: Optional[str] = None

    @property
    def socks_port(self) -> Optional[int]:
        return self.tor_instance.socks_port if self.tor_instance else None

    @property
    def control_port(self) -> Optional[int]:
        return self.tor_instance.control_port if self.tor_instance else None

    @property
    def data_directory(self) -> Optional[Path]:
        return self.tor_instance.data_dir if self.tor_instance else None

    async def start(self, timeout: float = 30.0) -> bool:
        """Creation & Start lifecycle: allocate ports, boot Tor, initialize controller."""
        if self.state in (JobState.READY, JobState.OBSERVING):
            return True

        self.state = JobState.TOR_BOOTSTRAPPING
        logger.info("[%s] Starting ObservationJob for target: %s", self.job_id, self.target_url)

        # Step 1: Create & launch Tor daemon instance
        self.tor_instance = await self.manager.create_instance(self.job_id)
        tor_ok = await self.tor_instance.start(timeout=timeout)
        if not tor_ok:
            self.state = JobState.ERROR
            self.error = self.tor_instance.error or "Tor bootstrap failed"
            return False

        # Step 2: Initialize job-specific TorObservationController
        cfg = ControllerConfig(
            proxy_url=self.tor_instance.proxy_url,
            profile_dir=self.profile_dir,
            lock_path=self.lock_path,
            enable_browser=self.enable_browser,
            human_timeout=self.human_timeout,
            verify_tor_exit=False,
        )
        self.controller = TorObservationController(cfg)
        try:
            await self.controller.start()
            self.state = JobState.READY
            logger.info("[%s] Job initialized and READY on SOCKS port %d", self.job_id, self.socks_port)
            return True
        except Exception as exc:
            self.state = JobState.ERROR
            self.error = f"Controller start failed: {exc}"
            logger.error("[%s] %s", self.job_id, self.error)
            await self.stop()
            return False

    async def observe(self, force_browser: bool = False) -> ObservationResult:
        """Executes observation pass on assigned target URL."""
        if self.state not in (JobState.READY, JobState.OBSERVING, JobState.BROWSER_REQUIRED):
            raise RuntimeError(f"Job {self.job_id} is in invalid state for observation: {self.state}")

        self.state = JobState.OBSERVING
        assert self.controller is not None
        result = await self.controller.observe(self.target_url, force_browser=force_browser)
        self.last_result = result

        if result.engine == Engine.BROWSER or result.browser_escalated:
            self.state = JobState.BROWSER_REQUIRED
        elif result.success:
            self.state = JobState.OBSERVING

        return result

    async def stop(self) -> bool:
        """Stop & Cleanup lifecycle: stop controller/browser, stop Tor, free ports/files."""
        logger.info("[%s] Stopping ObservationJob...", self.job_id)
        if self.controller is not None:
            with contextlib.suppress(Exception):
                await self.controller.stop()
            self.controller = None

        if self.job_id:
            await self.manager.stop_instance(self.job_id)
            self.tor_instance = None

        # Clean up job-specific profile directory and lock path
        with contextlib.suppress(Exception):
            if self.profile_dir.exists():
                shutil.rmtree(self.profile_dir, ignore_errors=True)
        with contextlib.suppress(Exception):
            if self.lock_path.exists():
                self.lock_path.unlink()

        self.state = JobState.CLEANED_UP
        logger.info("[%s] ObservationJob STOPPED and CLEANED_UP", self.job_id)
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "target_url": self.target_url,
            "state": self.state.value,
            "socks_port": self.socks_port,
            "control_port": self.control_port,
            "data_directory": str(self.data_directory) if self.data_directory else None,
            "profile_directory": str(self.profile_dir),
            "created_at": self.created_at,
            "last_result": self.last_result.to_dict() if self.last_result else None,
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
# ObservationJobManager: High-level Multi-Job Orchestrator
# --------------------------------------------------------------------------- #

class ObservationJobManager:
    """Orchestrates multiple concurrent ephemeral ObservationJobs."""

    def __init__(self) -> None:
        self.tor_manager = TorInstanceManager()
        self.jobs: Dict[str, ObservationJob] = {}

    async def create_job(self, target_url: str, job_id: Optional[str] = None,
                         enable_browser: bool = True, human_timeout: float = 900.0) -> ObservationJob:
        """Creates, initializes, and starts a new isolated ObservationJob."""
        job = ObservationJob(target_url, job_id=job_id, instance_manager=self.tor_manager,
                             enable_browser=enable_browser, human_timeout=human_timeout)
        self.jobs[job.job_id] = job
        await job.start()
        return job

    def get_job(self, job_id: str) -> Optional[ObservationJob]:
        return self.jobs.get(job_id)

    async def stop_job(self, job_id: str) -> bool:
        job = self.jobs.pop(job_id, None)
        if job is None:
            return False
        return await job.stop()

    async def stop_all_jobs(self) -> None:
        job_ids = list(self.jobs.keys())
        for jid in job_ids:
            await self.stop_job(jid)

    def list_jobs(self) -> List[Dict[str, Any]]:
        return [j.to_dict() for j in self.jobs.values()]
