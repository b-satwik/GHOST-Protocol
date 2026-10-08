"""
Unified End-to-End Inference Engine for DarkWatch XAI.
Loads and executes:
1. HuggingFace DistilBERT Text Model (HackerSignal preferred from models/distilbert_hackersignal/final_model, dwdata_text_model fallback)
2. PyTorch 39-feature Tabular Autoencoder (models/dwdata_tabular_model/)
3. PyTorch 14-feature Temporal Autoencoder (models/temporal_v2/ preferred, dwdata_temporal_model fallback)
4. XGBoost 79-feature Multiclass Classifier (models/xgboost_multiclass_model.joblib)
5. Dynamic Multi-Modal HM-TIF Fusion Engine with explicit modality availability and dynamic weight renormalization
6. Regex CTI Extractor & Evidence-Aware MITRE ATT&CK Mapper
7. Transparent Risk & Severity Engine
8. Conditional XAI Engine
9. Standard Alert Object Generator
"""

import os
import json
import math
import numpy as np
from typing import Dict, Any, Union

import torch
import joblib
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from src.interfaces.base_interfaces import (
    TextEncoderInterface,
    BehaviorEncoderInterface,
    TemporalEncoderInterface,
    FusionEngineInterface,
)
from src.extraction.threat_extractor import ThreatExtractor
from src.cti.mitre_mapper import MITREMapper
from src.risk.risk_engine import RiskEngine
from src.xai.conditional_xai import ConditionalXAIEngine
from src.alerts.alert_generator import AlertGenerator


class ExactTabularAutoencoder(torch.nn.Module):
    """Exact 39-feature Tabular Autoencoder PyTorch Architecture."""
    def __init__(self, input_dim=39):
        super().__init__()
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(input_dim, 78),
            torch.nn.ReLU(),
            torch.nn.Linear(78, 39),
            torch.nn.ReLU(),
            torch.nn.Linear(39, 19),
            torch.nn.ReLU()
        )
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(19, 39),
            torch.nn.ReLU(),
            torch.nn.Linear(39, 78),
            torch.nn.ReLU(),
            torch.nn.Linear(78, input_dim),
            torch.nn.Sigmoid()
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))


class ExactTemporalAutoencoder(torch.nn.Module):
    """Exact 14-feature Temporal Autoencoder PyTorch Architecture (v2 compatible)."""
    def __init__(self, input_dim=14):
        super().__init__()
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(input_dim, 32),
            torch.nn.ReLU(),
            torch.nn.Linear(32, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 8)
        )
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(8, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, 32),
            torch.nn.ReLU(),
            torch.nn.Linear(32, input_dim)
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))


class InferenceEngine:
    """
    Main Orchestrator for DarkWatch XAI Research Pipeline.
    Loads real ML model artifacts and performs genuine multi-modal inference.
    """
    
    def __init__(self, models_dir: str = None):
        if models_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            models_dir = os.path.join(base_dir, "models")
            
        self.models_dir = models_dir
        self.device = torch.device("cpu")
        
        # Load Sub-Modules
        from src.pipeline.threat_filter import ThreatFilter
        self.threat_filter = ThreatFilter()
        self.threat_extractor = ThreatExtractor()
        self.mitre_mapper = MITREMapper()
        self.risk_engine = RiskEngine()
        self.xai_engine = ConditionalXAIEngine()
        
        # Load Model Weights and Metadata
        self._load_models()
        
    def _load_models(self):
        """Load pre-trained PyTorch, XGBoost, and Transformers model weights."""
        # 1. Text Model (HackerSignal preferred, dwdata_text_model fallback)
        hs_model_dir = os.path.join(self.models_dir, "distilbert_hackersignal", "final_model")
        hs_tok_dir = os.path.join(self.models_dir, "distilbert_hackersignal", "tokenizer")
        hs_label_map = os.path.join(self.models_dir, "distilbert_hackersignal", "metrics", "label_mapping.json")
        fallback_text_dir = os.path.join(self.models_dir, "dwdata_text_model")
        
        if os.path.exists(hs_model_dir) and os.path.exists(hs_tok_dir):
            self.text_model_dir = hs_model_dir
            self.tokenizer_dir = hs_tok_dir
        elif os.path.exists(fallback_text_dir):
            self.text_model_dir = fallback_text_dir
            self.tokenizer_dir = fallback_text_dir
        else:
            raise RuntimeError(f"Text model directory missing in {self.models_dir}")
            
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.tokenizer_dir)
            self.text_model = AutoModelForSequenceClassification.from_pretrained(self.text_model_dir)
            self.text_model.to(self.device)
            self.text_model.eval()
            if os.path.exists(hs_label_map):
                with open(hs_label_map, "r", encoding="utf-8") as f:
                    self.id2label = json.load(f).get("id2label", self.text_model.config.id2label)
            else:
                self.id2label = self.text_model.config.id2label
        except Exception as e:
            raise RuntimeError(f"Failed to load DistilBERT text model from {self.text_model_dir}: {e}")

        # 2. Tabular Model & Scaler
        self.tab_model_dir = os.path.join(self.models_dir, "dwdata_tabular_model")
        scaler_path = os.path.join(self.tab_model_dir, "scaler.joblib")
        tab_weight_path = os.path.join(self.tab_model_dir, "model.pt")
        
        if not os.path.exists(scaler_path) or not os.path.exists(tab_weight_path):
            raise RuntimeError(f"Tabular model artifacts missing in {self.tab_model_dir}")
            
        try:
            self.tab_scaler = joblib.load(scaler_path)
            tab_ckpt = torch.load(tab_weight_path, map_location=self.device, weights_only=False)
            self.tab_features = tab_ckpt.get("features", [])
            self.tab_input_dim = tab_ckpt.get("input_dim", 39)
            
            self.tab_model = ExactTabularAutoencoder(self.tab_input_dim)
            self.tab_model.load_state_dict(tab_ckpt["model_state_dict"])
            self.tab_model.to(self.device)
            self.tab_model.eval()
        except Exception as e:
            raise RuntimeError(f"Failed to load Tabular Autoencoder: {e}")

        # 3. Temporal Model & Scaler (temporal_v2 preferred, dwdata_temporal_model fallback)
        temp_v2_dir = os.path.join(self.models_dir, "temporal_v2")
        temp_v2_scaler = os.path.join(temp_v2_dir, "temporal_scaler.joblib")
        temp_v2_weight = os.path.join(temp_v2_dir, "temporal_autoencoder_v2.pt")
        temp_v2_feat = os.path.join(temp_v2_dir, "temporal_features.json")
        
        fallback_temp_dir = os.path.join(self.models_dir, "dwdata_temporal_model")
        fallback_temp_scaler = os.path.join(fallback_temp_dir, "temporal_scaler.npz")
        fallback_temp_weight = os.path.join(fallback_temp_dir, "temporal_autoencoder.pt")
        
        self.temp_scaler = None
        self.temp_mean = None
        self.temp_scale = None
        
        if os.path.exists(temp_v2_weight) and os.path.exists(temp_v2_scaler):
            self.temp_model_dir = temp_v2_dir
            try:
                self.temp_scaler = joblib.load(temp_v2_scaler)
                temp_ckpt = torch.load(temp_v2_weight, map_location=self.device, weights_only=False)
                if os.path.exists(temp_v2_feat):
                    with open(temp_v2_feat, "r", encoding="utf-8") as f:
                        self.temp_features = json.load(f)
                else:
                    self.temp_features = temp_ckpt.get("feature_columns", [])
                self.temp_input_dim = temp_ckpt.get("input_dim", len(self.temp_features) if self.temp_features else 14)
                
                self.temp_model = ExactTemporalAutoencoder(self.temp_input_dim)
                self.temp_model.load_state_dict(temp_ckpt["model_state_dict"])
                self.temp_model.to(self.device)
                self.temp_model.eval()
            except Exception as e:
                raise RuntimeError(f"Failed to load Temporal Autoencoder v2: {e}")
        elif os.path.exists(fallback_temp_weight) and os.path.exists(fallback_temp_scaler):
            self.temp_model_dir = fallback_temp_dir
            try:
                scaler_data = np.load(fallback_temp_scaler)
                self.temp_mean = scaler_data["mean"]
                self.temp_scale = scaler_data["scale"]
                
                temp_ckpt = torch.load(fallback_temp_weight, map_location=self.device, weights_only=False)
                self.temp_features = temp_ckpt.get("feature_columns", [])
                self.temp_input_dim = temp_ckpt.get("input_dim", 14)
                
                self.temp_model = ExactTemporalAutoencoder(self.temp_input_dim)
                self.temp_model.load_state_dict(temp_ckpt["model_state_dict"])
                self.temp_model.to(self.device)
                self.temp_model.eval()
            except Exception as e:
                raise RuntimeError(f"Failed to load Temporal Autoencoder fallback: {e}")
        else:
            raise RuntimeError(f"Temporal model artifacts missing in {self.models_dir}")

        # 4. XGBoost Network Multiclass Classifier
        self.xgb_model_path = os.path.join(self.models_dir, "xgboost_multiclass_model.joblib")
        self.xgb_model = None
        self.xgb_features = []
        if os.path.exists(self.xgb_model_path):
            import warnings
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self.xgb_model = joblib.load(self.xgb_model_path)
                    if hasattr(self.xgb_model, "feature_names_in_"):
                        self.xgb_features = list(self.xgb_model.feature_names_in_)
            except Exception as e:
                print(f"Warning: Failed to load XGBoost model from {self.xgb_model_path}: {e}")

    def predict(
        self,
        input_data: Union[str, Dict[str, Any]],
        deep_explain: bool = False,
        stix_bundle_id: str = None
    ) -> Dict[str, Any]:
        """
        Run complete end-to-end pipeline over a raw text string or dictionary record.
        """
        # Standardize Input
        is_historical_record = isinstance(input_data, dict) and any(k in input_data for k in self.tab_features)
        is_temporal_record = isinstance(input_data, dict) and any(k in input_data for k in self.temp_features)
        is_network_record = isinstance(input_data, dict) and any(k in input_data for k in self.xgb_features)
        
        if isinstance(input_data, str):
            record = {"text": input_data, "listing_name": input_data}
        elif isinstance(input_data, dict):
            record = dict(input_data)
            if "text" not in record and "listing_name" in record:
                record["text"] = record["listing_name"]
            elif "text" not in record and "sanitized_text" in record:
                record["text"] = record["sanitized_text"]
        else:
            record = {"text": str(input_data)}
            
        text = record.get("text", "")
        
        # 1. Text Model Inference
        text_prediction = self._predict_text(text)
        
        # 2. Tabular Model Inference (Behavioral)
        behavioral_result = self._predict_tabular(record, is_historical_record)
        
        # 3. Temporal Model Inference
        temporal_result = self._predict_temporal(record, is_historical_record or is_temporal_record)

        # 4. XGBoost Network Classifier Inference
        network_result = self._predict_xgboost(record, is_network_record)
        
        # 5. Tri-Modal HM-TIF Risk Fusion with Dynamic Weight Renormalization
        text_available = text_prediction.get("text_available", True)
        behavior_available = behavioral_result["behavior_available"]
        temporal_available = temporal_result["temporal_available"]
        network_available = network_result["network_available"]
        
        available_modalities = {
            "text": text_available,
            "behavioral": behavior_available,
            "temporal": temporal_available,
            "network": network_available
        }
        
        base_weights = {
            "behavioral": 0.40,
            "temporal": 0.35,
            "text": 0.25,
            "network": 0.20
        }
        
        if text_available:
            if not text_prediction.get("is_threat", True) or text_prediction.get("predicted_class") == "NORMAL":
                text_semantic_risk = 0.0
            else:
                text_conf = text_prediction["confidence"]
                text_class = str(text_prediction["predicted_class"]).lower()
                is_high_threat_class = any(k in text_class for k in [
                    "malware", "botnet", "exploit", "cvv", "rce", "injection",
                    "dos", "xss", "info_disclosure", "auth_access", "file_inclusion",
                    "memory_corruption", "cracked", "hacking"
                ])
                text_semantic_risk = text_conf if is_high_threat_class else (1.0 - text_conf)
        else:
            text_semantic_risk = 0.0

        scores = {}
        if text_available:
            scores["text"] = text_semantic_risk
        if behavior_available:
            scores["behavioral"] = behavioral_result["anomaly_score"]
        if temporal_available:
            scores["temporal"] = temporal_result["anomaly_score"]
        if network_available:
            net_conf = network_result.get("confidence", 0.0)
            net_cls = str(network_result.get("predicted_class", "")).lower()
            scores["network"] = net_conf if net_cls != "0" else (1.0 - net_conf)

        if not scores:
            fusion_score = 0.0
            active_weights = {m: 0.0 for m in base_weights}
            fusion_desc = "No active modalities available."
        else:
            raw_weights = {m: base_weights[m] for m in scores}
            total_w = sum(raw_weights.values())
            active_weights = {m: 0.0 for m in base_weights}
            for m, w in raw_weights.items():
                active_weights[m] = round(w / total_w, 4)
            fusion_score = round(sum(active_weights[m] * scores[m] for m in scores), 4)
            fusion_score = max(0.0, min(1.0, fusion_score))
            fusion_desc = f"HM-TIF Multi-Modal Fusion over active modalities ({', '.join(scores.keys())})"

        fusion_result = {
            "fusion_score": fusion_score,
            "available_modalities": available_modalities,
            "active_weights": active_weights,
            "fusion_formula_description": fusion_desc
        }
        
        model_results = {
            "text_prediction": text_prediction,
            "behavioral_result": behavioral_result,
            "temporal_result": temporal_result,
            "network_result": network_result,
            "fusion_result": fusion_result
        }
        
        # 6. Threat Extraction
        extracted_threats = self.threat_extractor.extract(text) if text_available else {"entities": {}, "cves": [], "wallets": []}
        
        # 7. CTI & MITRE ATT&CK Mapping
        mitre_mappings = self.mitre_mapper.map_threats(extracted_threats, text) if text_available else []
        
        # 8. Transparent Risk & Severity Engine
        risk_result = self.risk_engine.evaluate_risk(
            fusion_score=fusion_score,
            text_prediction=text_prediction,
            mitre_mappings=mitre_mappings,
            extracted_threats=extracted_threats,
            behavioral_result=behavioral_result,
            temporal_result=temporal_result
        )
        
        # 9. Conditional Performance-Aware XAI
        xai_result = self.xai_engine.explain(
            record=record,
            model_results=model_results,
            risk_result=risk_result,
            deep_explain=deep_explain
        )
        
        # 10. Standard Security Alert Object Generation
        alert_object = AlertGenerator.generate_alert(
            record=record,
            model_results=model_results,
            extracted_threats=extracted_threats,
            mitre_mappings=mitre_mappings,
            risk_result=risk_result,
            xai_result=xai_result,
            stix_bundle_id=stix_bundle_id
        )
        
        return {
            "input": record,
            "text_model": text_prediction,
            "behavior_model": behavioral_result,
            "temporal_model": temporal_result,
            "network_model": network_result,
            "fusion": fusion_result,
            "cti_entities": extracted_threats.get("entities", {}),
            "mitre": mitre_mappings,
            "risk": risk_result,
            "xai": xai_result,
            "alert": alert_object
        }

    def predict_collector_record(
        self,
        record_id_or_dict: Union[int, Dict[str, Any]],
        db_path: str = "data/collector_evidence.db",
        deep_explain: bool = False
    ) -> Dict[str, Any]:
        """
        Ingests a Phase 1 collector verification attempt record from SQLite,
        executes CTI indicator extraction, STIX 2.1 serialization, and local MITRE ATT&CK enrichment,
        then feeds the evidence through ML text/risk fusion, XAI, and Security Alert generation.
        """
        from src.cti.cti_pipeline_bridge import CTIPipelineBridge
        
        bridge = CTIPipelineBridge(db_path=db_path)
        
        if isinstance(record_id_or_dict, int):
            record_id = record_id_or_dict
            cti_res = bridge.process_collector_record(record_id)
            if not cti_res:
                raise ValueError(f"No valid collector record with sanitized_text found for record_id={record_id}")
            
            with bridge.evidence_store._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM verification_attempts WHERE id = ?", (record_id,))
                row = cursor.fetchone()
                record_dict = dict(row) if row else {}
        elif isinstance(record_id_or_dict, dict):
            record_dict = dict(record_id_or_dict)
            sanitized_text = record_dict.get("sanitized_text", record_dict.get("text", ""))
            onion_address = record_dict.get("onion_address", "http://unknown.onion")
            source_record_id = record_dict.get("id", 1)
            
            cti_res = bridge.process_text_evidence(
                sanitized_text=sanitized_text,
                onion_address=onion_address,
                source_record_id=source_record_id
            )
        else:
            raise TypeError("record_id_or_dict must be an int record_id or a dict")

        record_dict["text"] = record_dict.get("sanitized_text", record_dict.get("text", ""))
        stix_bundle_id = cti_res.get("stix_bundle_id")
        
        # Run ML Inference pipeline
        prediction = self.predict(record_dict, deep_explain=deep_explain, stix_bundle_id=stix_bundle_id)
        
        # Attach detailed CTI bridge & STIX 2.1 metadata
        prediction["cti_bridge"] = {
            "source_record_id": cti_res.get("source_record_id"),
            "stix_bundle_id": stix_bundle_id,
            "extracted_indicators_count": cti_res.get("extracted_indicators_count", 0),
            "mitre_mappings_count": cti_res.get("mitre_mappings_count", 0),
            "enriched_mitre_count": cti_res.get("enriched_mitre_count", 0),
            "enriched_mitre_techniques": cti_res.get("enriched_mitre_techniques", [])
        }
        
        # Persist generated Security Alert payload into SQLite
        try:
            source_rec_id = cti_res.get("source_record_id", 1)
            onion_addr = record_dict.get("onion_address", "http://unknown.onion")
            bridge.cti_store.save_security_alert(
                alert_object=prediction["alert"],
                source_record_id=source_rec_id,
                onion_address=onion_addr
            )
        except Exception as e:
            print(f"Warning: Failed to persist security alert to SQLite: {e}")

        return prediction

    def _predict_text(self, text: str) -> Dict[str, Any]:
        """Perform genuine HuggingFace DistilBERT text classification with Threat Filter Gate."""
        if not text or not str(text).strip():
            return {
                "text_available": False,
                "is_threat": False,
                "threat_filter_decision": "EMPTY_CONTENT",
                "predicted_class": "MISSING_TEXT_MODALITY",
                "confidence": 0.0,
                "class_probabilities": {},
                "model_artifact": os.path.basename(self.text_model_dir)
            }

        # 1. Threat Filter Gate Evaluation
        filter_eval = self.threat_filter.evaluate(text)
        if not filter_eval["is_threat"]:
            return {
                "text_available": True,
                "is_threat": False,
                "threat_filter_decision": "ROUTINE_CONTENT",
                "predicted_class": "NORMAL",
                "confidence": 1.0,
                "class_probabilities": {"NORMAL": 1.0},
                "model_artifact": os.path.basename(self.text_model_dir),
                "filter_reason": filter_eval["reason"]
            }
            
        # 2. DistilBERT Model Inference for Threat-Relevant Content
        inputs = self.tokenizer(str(text), return_tensors="pt", truncation=True, max_length=512).to(self.device)
        with torch.no_grad():
            outputs = self.text_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)[0]
            pred_idx = torch.argmax(probs).item()
            pred_class = self.id2label.get(str(pred_idx), self.id2label.get(pred_idx, f"CLASS_{pred_idx}"))
            confidence = float(probs[pred_idx].item())
            
            # Format class probabilities
            top_k = torch.topk(probs, min(5, len(probs)))
            class_probs = {}
            for val, idx in zip(top_k.values, top_k.indices):
                label_str = self.id2label.get(str(idx.item()), self.id2label.get(idx.item(), f"CLASS_{idx.item()}"))
                class_probs[label_str] = round(float(val.item()), 4)
                
        return {
            "text_available": True,
            "is_threat": True,
            "threat_filter_decision": "THREAT_RELEVANT",
            "predicted_class": pred_class,
            "confidence": round(confidence, 4),
            "class_probabilities": class_probs,
            "model_artifact": os.path.join(self.text_model_dir, "model.safetensors"),
            "matched_keywords": filter_eval.get("matched_keywords", [])
        }

    def _predict_tabular(self, record: Dict[str, Any], is_historical_record: bool) -> Dict[str, Any]:
        """Perform Tabular Autoencoder inference for historical records."""
        if not is_historical_record:
            return {
                "behavior_available": False,
                "anomaly_score": None,
                "is_anomaly_95": None,
                "is_anomaly_99": None,
                "model_artifact": None
            }
            
        # Build 39-feature raw vector in exact feature order
        raw_vec = []
        for feat in self.tab_features:
            val = record.get(feat, 0.0)
            try:
                raw_vec.append(float(val))
            except (ValueError, TypeError):
                raw_vec.append(0.0)
                
        raw_arr = np.array(raw_vec, dtype=np.float32).reshape(1, -1)
        scaled_arr = self.tab_scaler.transform(raw_arr)
        tensor_x = torch.tensor(scaled_arr, dtype=torch.float32).to(self.device)
        
        with torch.no_grad():
            recon = self.tab_model(tensor_x)
            mse = float(torch.mean((tensor_x - recon) ** 2).item())
            
        mse = max(0.0, mse)
        # Research thresholds: 95th=0.0365, 99th=0.1339
        return {
            "behavior_available": True,
            "anomaly_score": round(mse, 4),
            "is_anomaly_95": mse > 0.0365,
            "is_anomaly_99": mse > 0.1339,
            "model_artifact": "models/dwdata_tabular_model/model.pt"
        }

    def _predict_temporal(self, record: Dict[str, Any], is_historical_record: bool) -> Dict[str, Any]:
        """Perform Temporal Autoencoder inference for historical/temporal records."""
        if not is_historical_record:
            return {
                "temporal_available": False,
                "anomaly_score": None,
                "is_anomaly_95": None,
                "is_anomaly_99": None,
                "model_artifact": None
            }
            
        # Build 14-feature raw vector in exact feature order
        raw_vec = []
        for feat in self.temp_features:
            val = record.get(feat, 0.0)
            try:
                raw_vec.append(float(val))
            except (ValueError, TypeError):
                raw_vec.append(0.0)
                
        raw_arr = np.array(raw_vec, dtype=np.float32).reshape(1, -1)
        if self.temp_scaler is not None:
            scaled_arr = self.temp_scaler.transform(raw_arr)
        else:
            scaled_arr = (raw_arr - self.temp_mean) / (self.temp_scale + 1e-8)
            
        tensor_x = torch.tensor(scaled_arr, dtype=torch.float32).to(self.device)
        
        with torch.no_grad():
            recon = self.temp_model(tensor_x)
            mse = float(torch.mean((tensor_x - recon) ** 2).item())
            
        mse = max(0.0, mse)
        # Research thresholds: 95th=0.0058, 99th=0.0270
        return {
            "temporal_available": True,
            "anomaly_score": round(mse, 4),
            "is_anomaly_95": mse > 0.0058,
            "is_anomaly_99": mse > 0.0270,
            "model_artifact": os.path.join(self.temp_model_dir, "temporal_autoencoder_v2.pt")
        }

    def _predict_xgboost(self, record: Dict[str, Any], is_network_record: bool) -> Dict[str, Any]:
        """Perform XGBoost Multiclass Classifier inference for network flow records."""
        if not is_network_record or self.xgb_model is None or not self.xgb_features:
            return {
                "network_available": False,
                "predicted_class": None,
                "confidence": None,
                "class_probabilities": None,
                "model_artifact": os.path.basename(self.xgb_model_path) if self.xgb_model else None
            }
            
        raw_vec = []
        for feat in self.xgb_features:
            val = record.get(feat, 0.0)
            try:
                raw_vec.append(float(val))
            except (ValueError, TypeError):
                raw_vec.append(0.0)
                
        import pandas as pd
        raw_df = pd.DataFrame([raw_vec], columns=self.xgb_features)
        
        try:
            probs = self.xgb_model.predict_proba(raw_df)[0]
            pred_idx = int(np.argmax(probs))
            classes = getattr(self.xgb_model, "classes_", list(range(len(probs))))
            pred_class = str(classes[pred_idx]) if pred_idx < len(classes) else f"CLASS_{pred_idx}"
            confidence = float(probs[pred_idx])
            
            class_probs = {}
            for i, p in enumerate(probs):
                c_name = str(classes[i]) if i < len(classes) else f"CLASS_{i}"
                class_probs[c_name] = round(float(p), 4)
                
            return {
                "network_available": True,
                "predicted_class": pred_class,
                "confidence": round(confidence, 4),
                "class_probabilities": class_probs,
                "model_artifact": "models/xgboost_multiclass_model.joblib"
            }
        except Exception as e:
            return {
                "network_available": False,
                "error": str(e),
                "model_artifact": "models/xgboost_multiclass_model.joblib"
            }
