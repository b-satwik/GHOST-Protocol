# DARKWATCH XAI — INFERENCE GUIDE

This guide explains how to run predictions, inspect alerts, and launch the analyst dashboard for **DarkWatch XAI**.

---

## 1. CLI INFERENCE USAGE (`predict.py`)

### Text-Only Mode (Mode 2)
To analyze an arbitrary dark web string or threat post:
```bash
python3 predict.py --text "Selling Loki 2.0 Botnet keylogger source code with RDP access"
```

To enable Deep XAI mode (triggers LIME token perturbation & SHAP feature attributions):
```bash
python3 predict.py --text "CVE-2024-38077 Windows Remote Desktop RCE zero-day exploit" --deep
```

Save output directly to a JSON alert file:
```bash
python3 predict.py --text "Fresh credit card CVV combo list for sale" --output alert.json
```

---

## 2. PYTHON API USAGE

You can import `InferenceEngine` directly in Python scripts:
```python
from src.pipeline.inference_engine import InferenceEngine

engine = InferenceEngine()

# Input can be text string or dataset record dictionary
result = engine.predict("Selling RedLine stealer and Loki 2.0 RAT", deep_explain=True)

print("Predicted Class:", result["prediction"]["text_predicted_class"])
print("Risk Score:", result["prediction"]["risk_score"])
print("Severity:", result["prediction"]["severity"])
print("MITRE Techniques:", [m["technique_id"] for m in result["mitre_attack_mappings"]])
```

---

## 3. LAUNCHING THE ANALYST DASHBOARD

Run the Streamlit application:
```bash
streamlit run dashboard/app.py
```

Features included in the dashboard:
1. **Live Threat Inspection Sandbox:** Real-time input testing with instant risk gauges.
2. **Historical Alert Feed:** Filterable feed of dataset records.
3. **MITRE ATT&CK Mapping Cards:** Visual technique cards with evidence snippets.
4. **XAI Token & Feature Attributions:** Interactive plots for LIME weights and SHAP attributions.
