"""
Observation Record Schema for DarkWatch Stage 1 Discovery & Observation Layer.
Represents an observed payload alongside provenance, network state, and hashing metadata.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import datetime


@dataclass
class ObservationRecord:
    source_id: str
    url: str
    timestamp: str
    status: str
    raw_sha256: str
    clean_sha256: str
    minhash_signature: List[int] = field(default_factory=list)
    discovery_provenance: Dict[str, Any] = field(default_factory=dict)
    raw_html: str = ""
    clean_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass instance to a plain dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObservationRecord":
        """Construct ObservationRecord from dictionary."""
        return cls(
            source_id=data.get("source_id", ""),
            url=data.get("url", ""),
            timestamp=data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
            status=data.get("status", "UNKNOWN"),
            raw_sha256=data.get("raw_sha256", ""),
            clean_sha256=data.get("clean_sha256", ""),
            minhash_signature=data.get("minhash_signature", []),
            discovery_provenance=data.get("discovery_provenance", {}),
            raw_html=data.get("raw_html", ""),
            clean_text=data.get("clean_text", ""),
            metadata=data.get("metadata", {})
        )
