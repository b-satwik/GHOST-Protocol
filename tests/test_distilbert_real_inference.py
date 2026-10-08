#!/usr/bin/env python3
"""
🛡️ GHOST PROTOCOL — REAL DISTILBERT INFERENCE DIAGNOSTIC & TEST SUITE
Executes genuine inference using frozen HackerSignal DistilBERT model over controlled synthetic security text.
Prints: INPUT -> PREDICTED CLASS -> CONFIDENCE -> TOP-3 PREDICTIONS.
"""

import os
import sys
import json
import unittest
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)


class TestDistilBertRealInference(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model_dir = os.path.join(repo_root, "models", "distilbert_hackersignal", "final_model")
        cls.tok_dir = os.path.join(repo_root, "models", "distilbert_hackersignal", "tokenizer")
        cls.label_map_file = os.path.join(repo_root, "models", "distilbert_hackersignal", "metrics", "label_mapping.json")

        with open(cls.label_map_file, "r", encoding="utf-8") as f:
            mapping = json.load(f)
            cls.id2label = mapping.get("id2label", {})

        cls.tokenizer = AutoTokenizer.from_pretrained(cls.tok_dir)
        cls.model = AutoModelForSequenceClassification.from_pretrained(cls.model_dir)
        cls.model.eval()

    def run_inference(self, text: str):
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)[0]
            top_val, top_idx = torch.topk(probs, 3)

        top_3 = []
        for val, idx in zip(top_val, top_idx):
            lbl = self.id2label.get(str(idx.item()), f"CLASS_{idx.item()}")
            top_3.append((lbl, round(float(val.item()), 4)))

        pred_class = top_3[0][0]
        confidence = top_3[0][1]
        return pred_class, confidence, top_3

    def test_real_inference_benchmark(self):
        sample_texts = [
            ("rce", "Remote code execution zero-day exploit payload targeting unpatched web application server allowing system command execution."),
            ("xss", "Reflected cross-site scripting flaw in query parameter allows arbitrary JavaScript execution in user browser context."),
            ("injection", "SQL injection vulnerability in search parameter allows dumping database contents using UNION SELECT queries."),
            ("auth_access", "Default credentials and broken access control on administrative management interface allow unauthorized session takeover."),
            ("file_inclusion", "Local file inclusion vulnerability via directory traversal parameter allows reading arbitrary system configuration files."),
            ("info_disclosure", "Exposed backup directory containing unencrypted database dump files and administrative credential files."),
            ("dos", "Recursive parsing loop and high memory usage cause server hang and denial of service crash."),
            ("memory_corruption", "Heap memory buffer overflow vulnerability in binary parser allows register overwrite and memory corruption.")
        ]

        print("\n" + "=" * 80)
        print(" 🛡️ FROZEN DISTILBERT REAL INFERENCE DIAGNOSTIC RESULTS")
        print("=" * 80)

        results = []
        for category, text in sample_texts:
            pred_class, confidence, top_3 = self.run_inference(text)
            print(f"\n[Category: {category.upper()}]")
            print(f"INPUT:           {text}")
            print(f"PREDICTED CLASS: {pred_class}")
            print(f"CONFIDENCE:      {confidence:.4f}")
            print(f"TOP-3:           {top_3}")
            results.append({
                "expected": category,
                "input": text,
                "predicted": pred_class,
                "confidence": confidence,
                "top_3": top_3
            })

            # Verify that model returns a valid prediction from the 8 classes
            self.assertIn(pred_class, list(self.id2label.values()))
            self.assertGreater(confidence, 0.0)

        print("\n" + "=" * 80 + "\n")
        return results


if __name__ == "__main__":
    unittest.main()
