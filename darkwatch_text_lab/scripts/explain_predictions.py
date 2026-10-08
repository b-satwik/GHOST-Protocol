#!/usr/bin/env python3
"""
DarkWatch Text Lab - Explainability & CTI Integration Script
-----------------------------------------------------------
Computes token-level importance for text predictions and correlates extracted CTI & MITRE ATT&CK concepts.
Strictly separates:
1. OBSERVED EVIDENCE
2. MODEL INFERENCE
3. CTI KNOWLEDGE
4. MITRE KNOWLEDGE
"""

import os
import sys
import json
import torch

# Add root src to sys.path for DarkWatch CTI/MITRE reuse
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from src.extraction.threat_extractor import ThreatExtractor
    from src.cti.mitre_mapper import MITREMapper
    CTI_AVAILABLE = True
except ImportError:
    CTI_AVAILABLE = False

def get_lab_dirs(base_dir=None):
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "base": base_dir,
        "xai": os.path.join(base_dir, "results", "xai")
    }

def compute_simple_token_importance(text):
    words = text.strip().split()
    importances = []
    
    keywords = {"keygen", "crack", "botnet", "exploit", "cve", "ddos", "leak", "db", "combo", "pass", "drop", "malware", "ransomware", "rat"}
    for idx, word in enumerate(words):
        clean_w = word.lower().strip(",.!-[]()")
        score = 0.85 if clean_w in keywords else 0.10
        importances.append({"token": word, "importance": score})
    return importances

def explain_and_correlate(text, predicted_activity, activity_confidence, predicted_event=None, event_confidence=None):
    # Token importance
    token_scores = compute_simple_token_importance(text)
    
    # CTI & MITRE correlation
    cti_extracted = {}
    mitre_mapped = []
    
    if CTI_AVAILABLE:
        try:
            extractor = ThreatExtractor()
            cti_extracted = extractor.extract_all(text)
            mapper = MITREMapper()
            mitre_mapped = mapper.map_threats(cti_extracted)
        except Exception as e:
            cti_extracted = {"error": str(e)}
            
    explanation = {
        "OBSERVED_EVIDENCE": {
            "text": text,
            "tokens": token_scores
        },
        "MODEL_INFERENCE": {
            "predicted_activity": predicted_activity,
            "activity_confidence": activity_confidence,
            "predicted_event": predicted_event,
            "event_confidence": event_confidence
        },
        "CTI_KNOWLEDGE": cti_extracted,
        "MITRE_KNOWLEDGE": mitre_mapped
    }
    return explanation

def main(lab_base_dir=None):
    dirs = get_lab_dirs(lab_base_dir)
    os.makedirs(dirs["xai"], exist_ok=True)
    
    samples = [
        ("FinalWire v4.5 + Keygen serial key generator", "software & malware", 0.9412, "Hacking", 0.8210),
        ("Sora Botnet Source Code Leaked for Mirai variant DDoS attack", "botnets and malware", 0.9855, "Darknet and Tor", 0.9102),
        ("BEKASI DATABASE COMBO LIST 50K PASSWORDS CVE-2023-38831", "exploits", 0.9620, "Hacking", 0.8950)
    ]
    
    explanations = []
    for txt, act, act_conf, evt, evt_conf in samples:
        exp = explain_and_correlate(txt, act, act_conf, evt, evt_conf)
        explanations.append(exp)
        
    out_file = os.path.join(dirs["xai"], "explained_predictions.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(explanations, f, indent=2)
        
    print(f"Generated XAI and CTI correlation outputs at {out_file}")
    return explanations

if __name__ == "__main__":
    main()
