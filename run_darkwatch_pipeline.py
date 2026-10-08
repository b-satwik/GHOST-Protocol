#!/usr/bin/env python3
"""
DarkWatch End-to-End Prototype Orchestrator CLI.
Connects:
1. Phase 1 Tor/Whonix Collector & SQLite Evidence Store
2. CTI Indicator Extraction & STIX 2.1 Serialization
3. Official Local MITRE ATT&CK STIX 2.1 Knowledge Base & Enrichment
4. DistilBERT Text Model + PyTorch Tabular/Temporal Autoencoders + XGBoost Classifier
5. Dynamic Tri-Modal Risk Fusion Engine
6. Performance-Aware XAI & Security Alert Generator

Usage:
  python3 run_darkwatch_pipeline.py --demo
  python3 run_darkwatch_pipeline.py --record-id 1 --deep
  python3 run_darkwatch_pipeline.py --url "http://examplelab.lab.onion" --deep
"""

import sys
import os
import json
import argparse

# Add repository root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.collector.evidence_store import EvidenceStore
from src.pipeline.inference_engine import InferenceEngine

def run_demo_pipeline(deep_explain: bool = False, output_file: str = None):
    print("=" * 75)
    print("DarkWatch End-to-End Security Intelligence Pipeline Prototype")
    print("=" * 75)
    
    # 1. Initialize DB and Seed Demo Collector Attempt if DB is empty
    db_path = "data/collector_evidence.db"
    store = EvidenceStore(db_path=db_path)
    
    demo_onion = "http://loki2botnet.lab.onion"
    demo_text = (
        "SELLING LOKI 2.0 BOTNET & KEYLOGGER SOURCE CODE. "
        "Includes Windows RCE Zero-Day exploit CVE-2024-38077 and 500x stolen RDP access credentials. "
        "Command and control server IP: 192.168.1.100. Contact via Telegram or jabber."
    )
    
    saved_attempt = store.save_attempt({
        "source_id": "SRC_DEMO_001",
        "onion_address": demo_onion,
        "timestamp": "2026-09-26T21:00:00Z",
        "http_status": 200,
        "response_time_ms": 420,
        "state": "CONTENT_ACCESSIBLE",
        "text_length": len(demo_text),
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sanitized_text": demo_text
    })
    
    record_id = saved_attempt["id"]
    print(f"\n[+] Step 1: Ingested Collector Record #{record_id} ({demo_onion}) into SQLite Store ({db_path})")
    print(f"    State: {saved_attempt['state']} | Length: {saved_attempt['text_length']} bytes")
    
    # 2. Run Inference Engine with CTI + STIX 2.1 + MITRE + ML Fusion + XAI
    engine = InferenceEngine(models_dir="models")
    print("\n[+] Step 2: Processing through CTI Extraction, STIX 2.1, MITRE STIX 2.1, ML Models & XAI...")
    result = engine.predict_collector_record(record_id, db_path=db_path, deep_explain=deep_explain)
    
    # 3. Display Pipeline Execution Summary
    print("\n" + "=" * 75)
    print("PIPELINE EXECUTION SUMMARY")
    print("=" * 75)
    print(f"• Record ID:                 {record_id}")
    print(f"• Onion Address:             {result['alert'].get('source')}")
    print(f"• STIX 2.1 Bundle ID:        {result['alert'].get('stix_bundle_id')}")
    print(f"• DistilBERT Text Model:     {result['text_model'].get('predicted_class')} (Confidence: {result['text_model'].get('confidence')*100:.1f}%)")
    print(f"• XGBoost Network Model:     Network Available = {result['network_model'].get('network_available')}")
    print(f"• Behavioral Autoencoder:    Behavior Available = {result['behavior_model'].get('behavior_available')}")
    print(f"• Temporal Autoencoder:      Temporal Available = {result['temporal_model'].get('temporal_available')}")
    print(f"• Dynamic Risk Fusion Score: {result['fusion'].get('fusion_score')} ({result['fusion'].get('fusion_formula_description')})")
    print(f"• Extracted CTI Indicators:  {result['cti_bridge'].get('extracted_indicators_count')} items")
    print(f"• Enriched MITRE STIX 2.1:   {result['cti_bridge'].get('enriched_mitre_count')} techniques")
    print(f"• Final Risk Severity:       {result['risk'].get('severity')} (Score: {result['risk'].get('risk_score')})")
    print(f"• XAI Status:                {result['xai'].get('xai_status')} ({result['xai'].get('explanation_mode')})")
    
    output_json = json.dumps(result, indent=2)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_json)
        print(f"\n[+] Complete Security Alert JSON written to: {output_file}")
    else:
        print("\n" + "=" * 75)
        print("GENERATED SECURITY ANALYST ALERT OBJECT")
        print("=" * 75)
        print(output_json)
        
    return result

def main():
    parser = argparse.ArgumentParser(description="DarkWatch End-to-End Prototype Orchestrator")
    parser.add_argument("--demo", action="store_true", help="Run end-to-end prototype pipeline on sample collector record")
    parser.add_argument("--record-id", type=int, help="Process specific verification_attempts record ID from SQLite")
    parser.add_argument("--url", type=str, help="Process latest collector evidence record for an onion URL")
    parser.add_argument("--db-path", type=str, default="data/collector_evidence.db", help="SQLite evidence database path")
    parser.add_argument("--deep", action="store_true", help="Trigger deep LIME/SHAP XAI explanation")
    parser.add_argument("--output", type=str, help="Path to save output JSON alert")
    
    args = parser.parse_args()
    
    if args.record_id:
        engine = InferenceEngine(models_dir="models")
        result = engine.predict_collector_record(args.record_id, db_path=args.db_path, deep_explain=args.deep)
        output_json = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_json)
            print(f"Alert saved to: {args.output}")
        else:
            print(output_json)
    elif args.url:
        store = EvidenceStore(db_path=args.db_path)
        latest = store.get_latest_attempt(args.url)
        if not latest:
            print(f"No collector record found for URL '{args.url}' in {args.db_path}")
            sys.exit(1)
        engine = InferenceEngine(models_dir="models")
        result = engine.predict_collector_record(latest["id"], db_path=args.db_path, deep_explain=args.deep)
        output_json = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_json)
            print(f"Alert saved to: {args.output}")
        else:
            print(output_json)
    else:
        # Default fallback to demo execution
        run_demo_pipeline(deep_explain=args.deep, output_file=args.output)

if __name__ == "__main__":
    main()
