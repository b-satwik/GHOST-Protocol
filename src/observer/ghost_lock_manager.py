"""
GHOST Protocol — Process & Observation Session Lock Manager.
Enforces single-instance behavior to prevent multiple concurrent GHOST observers
from corrupting or terminating an active Tor Browser session.
"""

import os
import sys
import json
import datetime
from typing import Dict, Any, Tuple, Optional

LOCK_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "ghost_observer.lock")


class GhostLockManager:
    """
    Manages process & observation session lock file (data/ghost_observer.lock).
    """

    @staticmethod
    def get_lock_info() -> Optional[Dict[str, Any]]:
        if not os.path.exists(LOCK_FILE_PATH):
            return None
        try:
            with open(LOCK_FILE_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return None

    @staticmethod
    def is_lock_active() -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Checks if a valid GHOST observer process is currently active.
        Removes stale lock files if the owner process is no longer running.
        Returns (is_active, lock_data_dict_or_none).
        """
        data = GhostLockManager.get_lock_info()
        if not data:
            return False, None

        pid = data.get("pid")
        if not pid:
            return False, None

        # Verify whether owner PID is currently running on the Linux host
        proc_alive = os.path.exists(f"/proc/{pid}")
        if proc_alive:
            return True, data

        # Lock is stale -> remove stale lock safely
        GhostLockManager.release_lock()
        return False, None

    @staticmethod
    def acquire_lock(pid: int, target_url: str, profile_path: Optional[str] = None, mode: str = "LIVE_OBSERVATION") -> bool:
        """
        Acquires observation session lock for the current GHOST process.
        """
        os.makedirs(os.path.dirname(LOCK_FILE_PATH), exist_ok=True)
        lock_data = {
            "pid": pid,
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target_url": target_url,
            "profile_path": profile_path or "",
            "mode": mode
        }
        try:
            with open(LOCK_FILE_PATH, "w") as f:
                json.dump(lock_data, f, indent=2)
            return True
        except Exception:
            return False

    @staticmethod
    def release_lock(owner_pid: Optional[int] = None) -> bool:
        """
        Releases observation session lock if owned by owner_pid or if owner_pid is None.
        """
        if not os.path.exists(LOCK_FILE_PATH):
            return True
        try:
            if owner_pid:
                data = GhostLockManager.get_lock_info()
                if data and data.get("pid") != owner_pid:
                    return False
            os.remove(LOCK_FILE_PATH)
            return True
        except Exception:
            return False
