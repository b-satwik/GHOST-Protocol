"""
Weak Supervision Engine for DarkWatch Gold Dataset Pipeline.
Applies domain heuristic rules and reuses existing ThreatExtractor, STIXExtractor,
MITREMapper, and MITREEnricher to generate candidate semantic annotations.

CRITICAL INVARIANT: Weak supervision annotations are candidate labels only and
are NEVER treated as ground truth. They are stored under the WEAK_SUPERVISION tier.
"""

from typing import Dict, Any, List, Tuple
from src.extraction.threat_extractor import ThreatExtractor
from src.cti.stix_extractor import STIXExtractor
from src.cti.mitre_mapper import MITREMapper
from src.cti.mitre_enricher import MITREEnricher
from src.dataset.schema import (
    GoldRecord,
    AnnotationTier,
    ActivityCategory,
    Intent,
    Severity,
    TargetSector
)


class WeakSupervisionEngine:
    """
    Candidate semantic annotator utilizing existing DarkWatch CTI pipelines
    and heuristic domain rule sets.
    """

    # Keyword Taxonomies for Category Inference
    SALE_KEYWORDS = {
        "selling", "sell", "sales", "for sale", "buy", "price", "usd", "btc", "xmr",
        "crypto", "telegram", "jabber", "contact", "pm", "shop", "vendor", "discount"
    }
    EXPLOIT_KEYWORDS = {
        "zero-day", "0day", "0-day", "rce", "cve", "exploit", "vulnerability",
        "remote code execution", "privilege escalation", "bypass"
    }
    CREDENTIAL_KEYWORDS = {
        "combo list", "combolist", "credentials", "logins", "stealer log", "fullz",
        "credit card", "cvv", "cards", "bank account", "passport", "dump", "dumps"
    }
    ACCESS_KEYWORDS = {
        "rdp access", "rdp", "vpn access", "citrix", "network access", "admin access",
        "domain admin", "shell access", "root access"
    }
    RANSOMWARE_KEYWORDS = {
        "ransomware", "leak site", "encrypted", "ransom", "double extortion",
        "lockbit", "alphv", "blackcat", "clop"
    }
    RECRUITMENT_KEYWORDS = {
        "hiring", "coder needed", "dev needed", "spammer wanted", "recruiting",
        "join our team", "looking for partner", "work with us"
    }

    # Sector Taxonomies
    FINANCIAL_SECTOR = {"bank", "banking", "swift", "credit card", "cvv", "crypto", "bin", "atm", "financial"}
    HEALTHCARE_SECTOR = {"hospital", "health", "medical", "patient", "pharma", "clinic", "hipaa"}
    CRITICAL_INFRASTRUCTURE = {"scada", "power", "grid", "water", "energy", "utility", "industrial", "pipeline"}
    GOVERNMENT_SECTOR = {"gov", "government", "military", "defense", "police", "agency", "state"}
    TECHNOLOGY_SECTOR = {"server", "cloud", "software", "code", "admin", "rdp", "vpn", "database", "api"}

    def __init__(self):
        self.threat_extractor = ThreatExtractor()
        self.stix_extractor = STIXExtractor()
        self.mitre_mapper = MITREMapper()
        self.mitre_enricher = MITREEnricher()

    def generate_candidate_record(
        self,
        sanitized_text: str,
        provenance: Dict[str, Any],
        record_id: str = None
    ) -> GoldRecord:
        """
        Processes sanitized text and provenance through the weak supervision pipeline
        to build a candidate GoldRecord.

        Args:
            sanitized_text (str): Clean text from sanitizer
            provenance (Dict[str, Any]): Collector evidence provenance metadata
            record_id (str, optional): Preserved record ID

        Returns:
            GoldRecord: Candidate record with WEAK_SUPERVISION annotation tier
        """
        lower_text = (sanitized_text or "").lower()

        # 1. Extract CTI Entities & STIX Indicators
        extracted_threats = self.threat_extractor.extract(sanitized_text)
        stix_indicators = self.stix_extractor.extract_indicators(sanitized_text)

        cti_entities = dict(extracted_threats.get("entities", {}))
        cti_entities["stix_indicators"] = stix_indicators

        # 2. Extract & Enrich MITRE Mappings
        raw_mappings = self.mitre_mapper.map_threats(extracted_threats, sanitized_text)
        enriched_mitre = []
        for m in raw_mappings:
            tech_id = m.get("technique_id")
            if tech_id:
                enriched = self.mitre_enricher.enrich_technique(
                    technique_id=tech_id,
                    mapping_method=m.get("mapping_method", "EXPLICIT_EVIDENCE"),
                    confidence=m.get("confidence", 0.85),
                    matched_evidence=[e.strip() for e in m.get("evidence", "").split(",") if e.strip()]
                )
                if enriched:
                    enriched_mitre.append(enriched)
                else:
                    enriched_mitre.append(m)

        # 3. Infer Candidate Activity Categories
        categories, cat_confidence = self._infer_activity_categories(lower_text, cti_entities)

        # 4. Infer Candidate Intent
        intent, intent_confidence = self._infer_intent(lower_text, categories)

        # 5. Infer Candidate Severity
        severity = self._infer_severity(lower_text, categories, cti_entities, enriched_mitre)

        # 6. Infer Candidate Target Sectors
        target_sectors = self._infer_target_sectors(lower_text)

        # Overall Weak Supervision Confidence
        overall_confidence = round(min(0.85, (cat_confidence + intent_confidence) / 2.0), 2)

        annotation_meta = {
            "annotation_tier": AnnotationTier.WEAK_SUPERVISION.value,
            "annotator_id": "weak_supervision_engine_v1",
            "confidence": overall_confidence,
            "disputed": False,
            "review_notes": "Candidate labels generated via weak supervision rules engine and CTI enrichment."
        }

        record = GoldRecord(
            record_id=record_id,
            sanitized_text=sanitized_text,
            provenance=provenance,
            activity_categories=categories,
            intent=intent,
            severity=severity,
            target_sector=target_sectors,
            cti_entities=cti_entities,
            mitre_mappings=enriched_mitre,
            annotation_metadata=annotation_meta
        )

        return record

    def _infer_activity_categories(
        self, lower_text: str, cti_entities: Dict[str, Any]
    ) -> Tuple[List[str], float]:
        categories = set()
        confidence = 0.70

        is_sale = any(kw in lower_text for kw in self.SALE_KEYWORDS)
        has_malware = bool(cti_entities.get("malware"))
        has_cves = bool(cti_entities.get("cves") or cti_entities.get("vulnerabilities"))
        has_creds = bool(cti_entities.get("credentials_access"))

        if is_sale and (has_malware or "botnet" in lower_text or "source code" in lower_text):
            categories.add(ActivityCategory.MALWARE_SALES.value)
            confidence = 0.85

        if any(kw in lower_text for kw in self.EXPLOIT_KEYWORDS) or has_cves:
            categories.add(ActivityCategory.EXPLOIT_DISTRIBUTION.value)
            confidence = max(confidence, 0.80)

        if any(kw in lower_text for kw in self.CREDENTIAL_KEYWORDS) or has_creds:
            categories.add(ActivityCategory.CREDENTIAL_LEAK.value)
            confidence = max(confidence, 0.80)

        if any(kw in lower_text for kw in self.ACCESS_KEYWORDS):
            categories.add(ActivityCategory.ACCESS_BROKERAGE.value)
            confidence = max(confidence, 0.82)

        if any(kw in lower_text for kw in self.RANSOMWARE_KEYWORDS):
            categories.add(ActivityCategory.RANSOMWARE_LEAK.value)
            confidence = max(confidence, 0.85)

        if any(kw in lower_text for kw in self.RECRUITMENT_KEYWORDS):
            categories.add(ActivityCategory.RECRUITMENT_FORUM.value)
            confidence = max(confidence, 0.75)

        if not categories:
            if has_malware or cti_entities.get("attack_tools"):
                categories.add(ActivityCategory.CHAT_DISCUSSION.value)
                confidence = 0.65
            else:
                categories.add(ActivityCategory.BENIGN_OR_OTHER.value)
                confidence = 0.60

        return list(categories), confidence

    def _infer_intent(self, lower_text: str, categories: List[str]) -> Tuple[str, float]:
        if any(c in categories for c in [
            ActivityCategory.MALWARE_SALES.value,
            ActivityCategory.ACCESS_BROKERAGE.value
        ]) or any(kw in lower_text for kw in self.SALE_KEYWORDS):
            return Intent.ILLICIT_SALE.value, 0.85

        if ActivityCategory.RECRUITMENT_FORUM.value in categories:
            return Intent.RECRUITMENT.value, 0.80

        if any(c in categories for c in [
            ActivityCategory.EXPLOIT_DISTRIBUTION.value,
            ActivityCategory.CREDENTIAL_LEAK.value,
            ActivityCategory.RANSOMWARE_LEAK.value
        ]):
            return Intent.THREAT_EXCHANGE.value, 0.80

        if ActivityCategory.BENIGN_OR_OTHER.value in categories:
            return Intent.BENIGN.value, 0.70

        return Intent.INFORMATIONAL.value, 0.65

    def _infer_severity(
        self,
        lower_text: str,
        categories: List[str],
        cti_entities: Dict[str, Any],
        mitre_mappings: List[Dict[str, Any]]
    ) -> str:
        has_cve = bool(cti_entities.get("cves"))
        has_zero_day = "zero-day" in lower_text or "0day" in lower_text or "0-day" in lower_text
        has_rce = "rce" in lower_text or "remote code execution" in lower_text

        if (has_zero_day and (has_rce or has_cve)) or ActivityCategory.RANSOMWARE_LEAK.value in categories:
            return Severity.CRITICAL.value

        if (
            ActivityCategory.MALWARE_SALES.value in categories or
            ActivityCategory.ACCESS_BROKERAGE.value in categories or
            ActivityCategory.EXPLOIT_DISTRIBUTION.value in categories or
            has_cve
        ):
            return Severity.HIGH.value

        if ActivityCategory.CREDENTIAL_LEAK.value in categories or bool(cti_entities.get("malware")):
            return Severity.MEDIUM.value

        if mitre_mappings or bool(cti_entities.get("attack_tools")):
            return Severity.LOW.value

        return Severity.INFO.value

    def _infer_target_sectors(self, lower_text: str) -> List[str]:
        sectors = []
        if any(kw in lower_text for kw in self.FINANCIAL_SECTOR):
            sectors.append(TargetSector.FINANCIAL.value)
        if any(kw in lower_text for kw in self.HEALTHCARE_SECTOR):
            sectors.append(TargetSector.HEALTHCARE.value)
        if any(kw in lower_text for kw in self.CRITICAL_INFRASTRUCTURE):
            sectors.append(TargetSector.CRITICAL_INFRASTRUCTURE.value)
        if any(kw in lower_text for kw in self.GOVERNMENT_SECTOR):
            sectors.append(TargetSector.GOVERNMENT.value)
        if any(kw in lower_text for kw in self.TECHNOLOGY_SECTOR):
            sectors.append(TargetSector.TECHNOLOGY.value)

        if not sectors:
            sectors.append(TargetSector.UNKNOWN.value)

        return sectors
