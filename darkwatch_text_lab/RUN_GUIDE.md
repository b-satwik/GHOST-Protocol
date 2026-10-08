# DarkWatch Text Training Lab — Execution Guide 📖

Follow these instructions to execute the laboratory offline in VS Code or in Google Colab.

---

## 💻 Local Execution (VS Code / Jupyter)

1. **Open Workspace in VS Code**:
   - Open `/home/balasatwik/Downloads/darkwatch (2)/darkwatch` in VS Code.
   - Select Python Kernel: `.venv/bin/python3`.

2. **Run Scripts directly via Terminal**:
   ```bash
   cd darkwatch_text_lab

   # Step 1: Build unified corpus & dataset_v1
   python3 scripts/build_unified_dataset.py

   # Step 2: Train baseline models (LR, SVM, XGBoost)
   python3 scripts/train_baselines.py

   # Step 3: Train Multi-Task Transformer
   python3 scripts/train_transformer.py

   # Step 4: Evaluate untouched test set & error analysis
   python3 scripts/evaluate_models.py

   # Step 5: Run XAI & CTI correlation
   python3 scripts/explain_predictions.py
   ```

3. **Or Open Master Interactive Notebook**:
   - Open `darkwatch_text_lab/notebooks/DarkWatch_Text_Training.ipynb` in VS Code.
   - Run All Cells.

---

## ☁️ Google Colab Execution

1. Upload the `darkwatch_text_lab/` folder to Google Drive.
2. Open `DarkWatch_Text_Training.ipynb` in Google Colab.
3. Select **GPU runtime** (Runtime -> Change runtime type -> T4 GPU).
4. Run the first cell to mount Google Drive:
   ```python
   from google.colab import drive
   drive.mount('/content/drive')
   PROJECT_DIR = Path('/content/drive/MyDrive/darkwatch_text_lab')
   ```
5. Run the notebook top-to-bottom!

---

## 🔄 Continual Learning Workflow (v1 -> v2)

1. **Ingest New Text Observation**:
   ```bash
   python3 scripts/ingest_future_observations.py
   ```
2. **Review & Verify Observations**:
   - Open `data/future_observations/future_observations.jsonl`.
   - Update `annotation_status` to `"HUMAN_VERIFIED"` or `"HUMAN_CORRECTED"`.
   - Add `"human_label": "software & malware"`.
3. **Promote & Create dataset_v2**:
   ```bash
   python3 scripts/create_dataset_version.py
   ```
4. **Retrain Models on dataset_v2**:
   - Run retraining section in `DarkWatch_Text_Training.ipynb`.
   - Compare performance against dataset_v1 baseline!
