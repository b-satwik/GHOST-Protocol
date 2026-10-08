#!/usr/bin/env python3
"""
DarkWatch XAI End-to-End Prediction CLI Tool.

Usage:
  python3 predict.py --text "Selling Loki 2.0 Botnet keylogger source code with RDP access"
  python3 predict.py --text "CVE-2024-1234 zero-day exploit for Windows RCE" --deep
"""

import sys
import os
import json
import argparse

# Add repository root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline.inference_engine import InferenceEngine

def run_prediction(input_data, deep_explain: bool = False, output_file: str = None):
    engine = InferenceEngine()
    result = engine.predict(input_data, deep_explain=deep_explain)
    
    output_json = json.dumps(result, indent=2)
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output_json)
        print(f"Prediction alert saved to: {output_file}")
    else:
        print(output_json)
        
    return result

def main():
    parser = argparse.ArgumentParser(description="DarkWatch XAI Threat Analysis & Prediction Tool")
    parser.add_argument("--text", type=str, help="Raw dark web text or listing title")
    parser.add_argument("--json", type=str, help="Path to input JSON record file or JSON string")
    parser.add_argument("--deep", action="store_true", help="Trigger deep LIME / SHAP XAI explanation")
    parser.add_argument("--output", type=str, help="Optional output filepath to save JSON alert")
    
    args = parser.parse_args()
    
    if args.json:
        if os.path.exists(args.json):
            with open(args.json, 'r') as f:
                input_data = json.load(f)
        else:
            input_data = json.loads(args.json)
    elif args.text:
        input_data = args.text
    else:
        # Default fallback demo sample if no argument provided
        input_data = "Selling Loki 2.0 Botnet keylogger source code with 100x stolen RDP access accounts"
        print(f"No input provided. Running demonstration prediction on sample: '{input_data}'\n")
        
    run_prediction(input_data, deep_explain=args.deep, output_file=args.output)

if __name__ == "__main__":
    main()
