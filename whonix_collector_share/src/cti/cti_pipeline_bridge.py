"""
CTI Pipeline Bridge for DarkWatch.
Bridges Phase 1 collector evidence stored in SQLite with CTI extraction,
STIX 2.1 normalization, MISP categorization, and official local MITRE ATT&CK STIX 2.1 enrichment.
"""

from typing import Dict, Any, Optional, List
from src.collector.evidence_store import EvidenceStore
from src.cti.stix_extractor import STIXExtractor
from src.cti.misp_mitre_correlator import MISPMITRECorrelator
from src.cti.mitre_enricher import MITREEnricher
from src.cti.stix_generator import STIXGenerator
from src.cti.cti_store import CTIStore


class CTIPipelineBridge:
    """
    Main bridge orchestrator connecting Phase 1 collector evidence with CTI processing and MITRE STIX 2.1 enrichment.
    """

    def __init__(
        self,
        db_path: str = "data/collector_evidence.db",
        kb_path: Optional[str] = None,
        evidence_store: Optional[EvidenceStore] = None
    ):
        self.db_path = db_path
        self.evidence_store = evidence_store or EvidenceStore(db_path=db_path)
        self.cti_store = CTIStore(
            db_path=db_path,
            conn=self.evidence_store._persistent_conn if self.evidence_store else None
        )
        self.extractor = STIXExtractor()
        self.correlator = MISPMITRECorrelator(kb_path=kb_path)
        self.enricher = MITREEnricher(kb=self.correlator.mitre_mapper.kb)
        self.stix_generator = STIXGenerator()

    def process_text_evidence(
        self,
        sanitized_text: str,
        onion_address: str,
        source_record_id: int = 1,
        timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Processes a raw/sanitized text payload through the CTI pipeline with local MITRE ATT&CK enrichment.

        Args:
            sanitized_text (str): Clean text payload
            onion_address (str): Target onion source address
            source_record_id (int): ID of original verification attempt in SQLite
            timestamp (Optional[str]): Observation timestamp

        Returns:
            Dict[str, Any]: Structured CTI extraction, STIX 2.1 serialization, and MITRE enrichment result
        """
        ts = timestamp or "2026-09-26T18:00:00Z"

        # 1. Extract & Normalize Indicators
        raw_indicators = self.extractor.extract_indicators(sanitized_text)

        # 2. Correlate with MISP & MITRE ATT&CK KB
        correlation = self.correlator.correlate(raw_indicators, sanitized_text)
        correlated_indicators = correlation["correlated_indicators"]
        mitre_mappings = correlation["mitre_mappings"]

        # 3. Enrich MITRE Mappings with Official STIX 2.1 Metadata & Mitigations
        enrichment_payload = {
            "sanitized_text": sanitized_text,
            "correlated_indicators": correlated_indicators,
            "mitre_mappings": mitre_mappings
        }
        enriched = self.enricher.enrich_cti_observation(enrichment_payload)
        enriched_mitre = enriched.get("enriched_mitre_techniques", [])

        # 4. Generate STIX 2.1 Objects, Courses of Action, and Bundle
        stix_bundle = self.stix_generator.build_stix_bundle(
            onion_address=onion_address,
            timestamp=ts,
            correlated_indicators=correlated_indicators,
            mitre_mappings=mitre_mappings
        )

        # 5. Save CTI Evidence and STIX Bundle into SQLite
        self.cti_store.save_cti_results(
            source_record_id=source_record_id,
            onion_address=onion_address,
            timestamp=ts,
            stix_bundle=stix_bundle,
            correlated_indicators=correlated_indicators,
            mitre_mappings=mitre_mappings
        )

        return {
            "source_record_id": source_record_id,
            "onion_address": onion_address,
            "timestamp": ts,
            "extracted_indicators_count": len(correlated_indicators),
            "mitre_mappings_count": len(mitre_mappings),
            "enriched_mitre_count": len(enriched_mitre),
            "stix_bundle_id": stix_bundle["id"],
            "stix_objects_count": len(stix_bundle["objects"]),
            "correlated_indicators": correlated_indicators,
            "mitre_mappings": mitre_mappings,
            "enriched_mitre_techniques": enriched_mitre,
            "stix_bundle": stix_bundle
        }

    def process_collector_record(self, record_id: int) -> Optional[Dict[str, Any]]:
        """
        Processes a specific verification attempt record from the SQLite collector database.
        """
        with self.evidence_store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM verification_attempts WHERE id = ?;
            """, (record_id,))
            row = cursor.fetchone()
            if not row:
                return None

            record = dict(row)
            sanitized_text = record.get("sanitized_text", "")
            if not sanitized_text:
                return None

            return self.process_text_evidence(
                sanitized_text=sanitized_text,
                onion_address=record["onion_address"],
                source_record_id=record["id"],
                timestamp=record["timestamp"]
            )
