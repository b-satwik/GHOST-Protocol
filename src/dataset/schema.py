"""
Gold Dataset Schema Specification for DarkWatch.
Defines schema versions, annotation tiers, categorical taxonomies, and GoldRecord dataclass.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
import datetime
import uuid


SCHEMA_VERSION = "1.0.0"


class AnnotationTier(str, Enum):
    AUTOMATED = "AUTOMATED"
    WEAK_SUPERVISION = "WEAK_SUPERVISION"
    HUMAN_VERIFIED = "HUMAN_VERIFIED"


class ActivityCategory(str, Enum):
    MALWARE_SALES = "MALWARE_SALES"
    EXPLOIT_DISTRIBUTION = "EXPLOIT_DISTRIBUTION"
    CREDENTIAL_LEAK = "CREDENTIAL_LEAK"
    RANSOMWARE_LEAK = "RANSOMWARE_LEAK"
    ACCESS_BROKERAGE = "ACCESS_BROKERAGE"
    RECRUITMENT_FORUM = "RECRUITMENT_FORUM"
    CHAT_DISCUSSION = "CHAT_DISCUSSION"
    BENIGN_OR_OTHER = "BENIGN_OR_OTHER"


class Intent(str, Enum):
    ILLICIT_SALE = "ILLICIT_SALE"
    THREAT_EXCHANGE = "THREAT_EXCHANGE"
    INFORMATIONAL = "INFORMATIONAL"
    RECRUITMENT = "RECRUITMENT"
    BENIGN = "BENIGN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TargetSector(str, Enum):
    FINANCIAL = "FINANCIAL"
    HEALTHCARE = "HEALTHCARE"
    CRITICAL_INFRASTRUCTURE = "CRITICAL_INFRASTRUCTURE"
    GOVERNMENT = "GOVERNMENT"
    TECHNOLOGY = "TECHNOLOGY"
    UNKNOWN = "UNKNOWN"


class GoldRecord:
    """
    Gold Dataset Record encapsulating sanitized evidence, provenance,
    CTI entities, MITRE mappings, and multi-tier annotation metadata.
    """

    def __init__(
        self,
        sanitized_text: str,
        provenance: Dict[str, Any],
        record_id: Optional[str] = None,
        schema_version: str = SCHEMA_VERSION,
        activity_categories: Optional[List[str]] = None,
        intent: str = Intent.INFORMATIONAL.value,
        severity: str = Severity.INFO.value,
        target_sector: Optional[List[str]] = None,
        cti_entities: Optional[Dict[str, Any]] = None,
        mitre_mappings: Optional[List[Dict[str, Any]]] = None,
        annotation_metadata: Optional[Dict[str, Any]] = None,
    ):
        self.record_id = record_id or f"gold_{uuid.uuid4().hex[:12]}"
        self.schema_version = schema_version
        self.provenance = provenance or {}
        self.sanitized_text = sanitized_text or ""
        self.activity_categories = activity_categories or [ActivityCategory.BENIGN_OR_OTHER.value]
        self.intent = intent
        self.severity = severity
        self.target_sector = target_sector or [TargetSector.UNKNOWN.value]
        self.cti_entities = cti_entities or {
            "malware": [], "vulnerabilities": [], "cves": [],
            "credentials_access": [], "attack_tools": [], "iocs": {}
        }
        self.mitre_mappings = mitre_mappings or []
        
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        default_meta = {
            "annotation_tier": AnnotationTier.AUTOMATED.value,
            "annotator_id": "system_init",
            "confidence": 0.50,
            "disputed": False,
            "created_at": now_iso,
            "updated_at": now_iso,
            "review_notes": None
        }
        if annotation_metadata:
            default_meta.update(annotation_metadata)
        self.annotation_metadata = default_meta

    def to_dict(self) -> Dict[str, Any]:
        """Serializes record to a dictionary."""
        return {
            "record_id": self.record_id,
            "schema_version": self.schema_version,
            "provenance": self.provenance,
            "sanitized_text": self.sanitized_text,
            "activity_categories": self.activity_categories,
            "intent": self.intent,
            "severity": self.severity,
            "target_sector": self.target_sector,
            "cti_entities": self.cti_entities,
            "mitre_mappings": self.mitre_mappings,
            "annotation_metadata": self.annotation_metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GoldRecord":
        """Deserializes record from a dictionary."""
        return cls(
            record_id=data.get("record_id"),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            provenance=data.get("provenance", {}),
            sanitized_text=data.get("sanitized_text", ""),
            activity_categories=data.get("activity_categories", []),
            intent=data.get("intent", Intent.INFORMATIONAL.value),
            severity=data.get("severity", Severity.INFO.value),
            target_sector=data.get("target_sector", []),
            cti_entities=data.get("cti_entities", {}),
            mitre_mappings=data.get("mitre_mappings", []),
            annotation_metadata=data.get("annotation_metadata", {})
        )

    def validate(self) -> List[str]:
        """Validates schema conformance and returns list of error messages."""
        errors = []
        if not self.record_id:
            errors.append("Missing record_id")
        if not self.sanitized_text:
            errors.append("Missing sanitized_text")
        if not self.provenance or not isinstance(self.provenance, dict):
            errors.append("Invalid provenance dictionary")

        tier = self.annotation_metadata.get("annotation_tier")
        valid_tiers = [t.value for t in AnnotationTier]
        if tier not in valid_tiers:
            errors.append(f"Invalid annotation_tier '{tier}', expected one of {valid_tiers}")

        if not self.activity_categories or not isinstance(self.activity_categories, list):
            errors.append("activity_categories must be a non-empty list")

        return errors
