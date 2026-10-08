"""
DarkWatch CTI Package.
Provides threat indicator extraction, normalization, STIX 2.1 serialization,
MISP & MITRE ATT&CK correlation, and official local MITRE ATT&CK STIX 2.1 enrichment.
"""

from .mitre_mapper import MITREMapper
from .mitre_kb import MITREKnowledgeBase
from .mitre_enricher import MITREEnricher
from .stix_extractor import STIXExtractor
from .misp_mitre_correlator import MISPMITRECorrelator
from .stix_generator import STIXGenerator
from .cti_store import CTIStore
from .cti_pipeline_bridge import CTIPipelineBridge

__all__ = [
    "MITREMapper",
    "MITREKnowledgeBase",
    "MITREEnricher",
    "STIXExtractor",
    "MISPMITRECorrelator",
    "STIXGenerator",
    "CTIStore",
    "CTIPipelineBridge",
]
