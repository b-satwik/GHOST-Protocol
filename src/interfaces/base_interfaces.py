"""
Base Interfaces for DarkWatch XAI Architecture Extension Points.
Provides abstract base classes for modular components so future research models
(e.g., DarkBERT, GNNs, BiLSTM, HM-TIF, VTT-LLM) can be added as drop-in replacements.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class TextEncoderInterface(ABC):
    """Abstract interface for text classification / encoding models."""
    
    @abstractmethod
    def predict(self, text: str) -> Dict[str, Any]:
        """
        Returns prediction containing:
        - predicted_class: str
        - predicted_class_id: int
        - confidence: float
        - class_probabilities: Dict[str, float]
        """
        pass

class BehaviorEncoderInterface(ABC):
    """Abstract interface for tabular behavioral anomaly detection models."""
    
    @abstractmethod
    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Returns anomaly evaluation containing:
        - anomaly_score: float (reconstruction MSE)
        - is_anomaly_95: bool
        - is_anomaly_99: bool
        """
        pass

class TemporalEncoderInterface(ABC):
    """Abstract interface for temporal vendor/marketplace dynamics models."""
    
    @abstractmethod
    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Returns temporal anomaly evaluation containing:
        - anomaly_score: float
        - is_anomaly_95: bool
        - is_anomaly_99: bool
        """
        pass

class FusionEngineInterface(ABC):
    """Abstract interface for multi-modal decision risk fusion."""
    
    @abstractmethod
    def fuse(self, behavioral_score: float, temporal_score: float, text_confidence: float) -> Dict[str, Any]:
        """
        Returns fused risk score and band:
        - fusion_score: float
        - risk_band: str ("LOW", "MODERATE", "ELEVATED", "HIGH")
        """
        pass

class ThreatExtractorInterface(ABC):
    """Abstract interface for threat entity extraction from dark web text."""
    
    @abstractmethod
    def extract(self, text: str) -> Dict[str, Any]:
        """
        Returns extracted entities dictionary containing:
        - malware: List[str]
        - vulnerabilities: List[str]
        - credentials_access: List[str]
        - iocs: Dict[str, List[str]] (IPs, domains, hashes, emails)
        - attack_tools: List[str]
        - threat_actors: List[str]
        """
        pass

class CTIMapperInterface(ABC):
    """Abstract interface for CTI & MITRE ATT&CK correlation."""
    
    @abstractmethod
    def map_threats(self, extracted_entities: Dict[str, Any], text: str) -> List[Dict[str, Any]]:
        """
        Returns list of MITRE ATT&CK technique mappings:
        - technique_id: str
        - technique_name: str
        - tactic: str
        - evidence: str
        - method: str
        - confidence: float
        """
        pass

class RiskEngineInterface(ABC):
    """Abstract interface for transparent policy risk assessment."""
    
    @abstractmethod
    def evaluate_risk(
        self,
        fusion_score: float,
        text_prediction: Dict[str, Any],
        mitre_mappings: List[Dict[str, Any]],
        extracted_threats: Dict[str, Any],
        behavioral_result: Dict[str, Any],
        temporal_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Returns transparent risk evaluation:
        - risk_score: float
        - severity: str ("LOW", "MODERATE", "ELEVATED", "HIGH")
        - contributing_factors: List[str]
        - rationale: str
        """
        pass

class XAIEngineInterface(ABC):
    """Abstract interface for multi-modal explainability generation."""
    
    @abstractmethod
    def explain(
        self,
        record: Dict[str, Any],
        model_results: Dict[str, Any],
        risk_result: Dict[str, Any],
        deep_explain: bool = False
    ) -> Dict[str, Any]:
        """
        Returns structured XAI explanation object.
        """
        pass
