"""
Historical Correlation Engine for DarkWatch Stage 1 & Controlled GHOST Protocol Lab.
Searches historical observation records for recurring threat entities (CVEs, malware names,
URLs, domains, .onion addresses, synthetic actors, targets, infrastructure) and generates structured
recurrence timelines and STIX relationship edges.
"""

from typing import Dict, Any, List, Optional
from src.discovery.observation_history import ObservationHistoryStore


class HistoricalCorrelator:
    """
    Correlates current threat observations against long-term historical observation records.
    """

    def __init__(self, history_store: Optional[ObservationHistoryStore] = None):
        self.history_store = history_store or ObservationHistoryStore()

    def correlate_entity(self, entity_query: str) -> Dict[str, Any]:
        """
        Queries historical observation database for an entity string (CVE, malware, URL, handle, victim).
        Returns a structured recurrence timeline summary.
        """
        if not entity_query or not entity_query.strip():
            return {
                "entity_query": "",
                "match_found": False,
                "first_seen_utc": None,
                "last_seen_utc": None,
                "observation_count": 0,
                "unique_sources_count": 0,
                "sources": [],
                "timeline": [],
                "relationship": "NONE"
            }

        cleaned_query = entity_query.strip()
        records = self.history_store.get_observations_by_entity(cleaned_query)

        if not records:
            return {
                "entity_query": cleaned_query,
                "match_found": False,
                "first_seen_utc": None,
                "last_seen_utc": None,
                "observation_count": 0,
                "unique_sources_count": 0,
                "sources": [],
                "timeline": [],
                "relationship": "NONE"
            }

        first_seen = records[0]["timestamp_utc"]
        last_seen = records[-1]["timestamp_utc"]
        sources_set = set(r.get("canonical_url") or r.get("source_id") for r in records)

        actors = set()
        companies = set()
        malware = set()
        infra_map = {}
        timeline = []
        relationships = []

        for r in records:
            cves = r.get("extracted_cves", [])
            mw_list = r.get("extracted_malware", [])
            for m in mw_list:
                malware.add(m)

            text = (r.get("clean_text") or "").lower()
            
            # Synthetic Storyline Actors
            if "vipersec" in text:
                actors.add("ViperSec")
            if "viper_x" in text:
                actors.add("Viper_X")
            if "crypticghost" in text:
                actors.add("CrypticGhost")
            if "bytetrader" in text:
                actors.add("ByteTrader")
            if "shadowfox_lab" in text or "shadowfox" in text:
                actors.add("ShadowFox_lab")
            if "devops_dan" in text:
                actors.add("DevOps_Dan")
            if "securitynerd99" in text:
                actors.add("SecurityNerd99")

            # Synthetic Storyline Victims / Targets
            if "apexglobal" in text or "apexglobal financial" in text:
                companies.add("ApexGlobal Financial")
            if "biohealth" in text or "biohealth dynamics" in text:
                companies.add("BioHealth Dynamics")
            if "hellguardian" in text:
                companies.add("HellGuardian")
            if "acme corp" in text:
                companies.add("Acme Corp")

            # Synthetic Storyline Malware / Ransomware
            if "phantomlocker" in text:
                malware.add("PhantomLocker")
            if "stealerx" in text:
                malware.add("StealerX")

            # Infrastructure tracking
            if "phantom-c2" in text or "phantom-c2.lab.onion" in text:
                infra_map["phantom-c2.lab.onion"] = {
                    "onion": "phantom-c2.lab.onion",
                    "status": "ACTIVE_C2",
                    "first_seen": r["timestamp_utc"],
                    "last_seen": r["timestamp_utc"]
                }
            if "shadowforum" in text:
                infra_map["shadowforum.lab.onion"] = {
                    "onion": "shadowforum.lab.onion",
                    "status": "PUBLIC_FORUM",
                    "first_seen": r["timestamp_utc"],
                    "last_seen": r["timestamp_utc"]
                }
            if "dreadlab" in text:
                infra_map["dreadlab.lab.onion"] = {
                    "onion": "dreadlab.lab.onion",
                    "status": "SESSION_GATED",
                    "first_seen": r["timestamp_utc"],
                    "last_seen": r["timestamp_utc"]
                }

            timeline.append({
                "observation_id": r.get("observation_id"),
                "timestamp_utc": r.get("timestamp_utc"),
                "source_id": r.get("source_id"),
                "canonical_url": r.get("canonical_url"),
                "fusion_risk_score": r.get("fusion_risk_score", 0.0),
                "risk_severity": r.get("risk_severity", "LOW"),
                "change_state": r.get("change_state", "UNCHANGED")
            })

        if "ViperSec" in actors or "Viper_X" in actors:
            relationships.append({
                "source": "ViperSec / Viper_X",
                "relation": "TARGETS",
                "target": "ApexGlobal Financial",
                "confidence": 0.92,
                "evidence": "ViperSec/Viper_X cross-source threat postings targeting ApexGlobal Financial database and network access."
            })

        if "CrypticGhost" in actors and "PhantomLocker" in malware:
            relationships.append({
                "source": "CrypticGhost",
                "relation": "USES_MALWARE",
                "target": "PhantomLocker",
                "confidence": 0.95,
                "evidence": "CrypticGhost deployment discussion involving PhantomLocker ransomware."
            })

        return {
            "entity_query": cleaned_query,
            "match_found": True,
            "first_seen_utc": first_seen,
            "last_seen_utc": last_seen,
            "observation_count": len(records),
            "unique_sources_count": len(sources_set),
            "sources": sorted(list(sources_set)),
            "associated_actors": sorted(list(actors)),
            "associated_companies": sorted(list(companies)),
            "associated_malware": sorted(list(malware)),
            "infrastructure_history": list(infra_map.values()),
            "relationships": relationships,
            "timeline": timeline,
            "relationship_summary": relationships[0]["evidence"] if relationships else "HISTORICAL_INDICATOR_RECURRENCE"
        }
