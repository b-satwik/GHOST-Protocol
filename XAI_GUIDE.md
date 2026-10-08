# DARKWATCH XAI — EXPLAINABLE AI (XAI) GUIDE

This guide explains the multi-modal Explainable AI architecture in **DarkWatch XAI**.

---

## 1. MULTI-MODAL XAI COMPONENT ARCHITECTURE

| Modality | Target Model | Research File | XAI Method | Output Representation |
| :--- | :--- | :--- | :--- | :--- |
| **Text** | DistilBERT | `learning/training/explain_text_lime.py` | LIME (Local Interpretable Model-agnostic Explanations) | Per-token importance weights & direction (+/-) |
| **Behavioral** | PyTorch Tabular AE | `learning/training/explain_behavioral_shap.py` | SHAP (SHapley Additive exPlanations) | Feature importance rankings for reconstruction MSE |
| **Temporal** | PyTorch Temporal AE | `learning/training/explain_temporal.py` | Reconstruction Attribution | Per-feature reconstruction error metrics |
| **Unified** | Tri-Modal Fusion | `learning/training/explain_fusion.py` | Multi-Modal Narrative Generator | Natural language threat narrative report |

---

## 2. CONDITIONAL PERFORMANCE-AWARE CONDITIONING

To keep the pipeline efficient for real-time streaming, `src/xai/conditional_xai.py` applies conditional execution:

- **`LOW` / `MODERATE` Risk (`explanation_mode = "LIGHTWEIGHT"`):**
  Generates instant, lightweight explanations (score breakdown, key keyword highlights, top feature metrics) in under 5ms.
  
- **`ELEVATED` / `HIGH` Risk (`explanation_mode = "DEEP_EXPLANATION"`):**
  Triggers deep LIME token perturbation and SHAP kernel attributions to provide in-depth analyst reports.
