"""
Re-export module to support darkwatch/resolution/session_manager.py imports.
"""
from src.resolution.session_manager import ThreatSession, ThreatSessionManager

__all__ = ["ThreatSession", "ThreatSessionManager"]
