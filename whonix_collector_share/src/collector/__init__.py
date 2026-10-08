"""
DarkWatch Collector & Source Verification Package (Phase 1).
Provides isolated Dark Web collection, content sanitization, state classification,
and SQLite evidence recording before interfacing with the DarkWatch AI pipeline.
"""

from .sanitizer import ContentSanitizer
from .state_engine import StateEngine, SourceState
from .evidence_store import EvidenceStore
from .verifier import DarkWatchVerifier

__all__ = [
    "ContentSanitizer",
    "StateEngine",
    "SourceState",
    "EvidenceStore",
    "DarkWatchVerifier",
]
