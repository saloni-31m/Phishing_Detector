# Phishing URL Detector — ML Model + Browser Extension

Final year project scaffold. This gives you a working end-to-end skeleton:
feature extraction → model training → inference API → browser extension.
You'll extend/tune each piece, but nothing here is a stub that doesn't run.

## Project structure

```
phishing-detector/
├── backend/
│   ├── feature_extraction.py   # URL feature extractor (17 features)
│   ├── train_model.py          # Trains + compares 4 models, saves best one
│   ├── api.py                  # FastAPI inference server
│   └── requirements.txt
├── extension/
│   ├── manifest.json           # Chrome Manifest V3
│   ├── background.js           # Calls API on tab navigation
│   ├── content.js              # Shows warning banner on page
│   ├── popup.html / popup.js   # Extension popup UI
├── data/
│   └── DATASETS.md             # Where to get phishing + legitimate URL data
└── README.md
```

## Quick start

### 1. Backend setup
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Get data
See `data/DATASETS.md`. Put your combined CSV (columns: `url`, `label`
where label is 1=phishing, 0=legitimate) at `data/urls.csv`.

### 3. Train
```bash
cd backend
python train_model.py
```
This extracts features from every URL, trains Logistic Regression, Random
Forest, XGBoost-style Gradient Boosting, and SVM, prints a comparison table,
and saves the best model to `backend/model.pkl`.

### 4. Run the API
```bash
uvicorn api:app --reload --port 8000
```
Test it:
```bash
curl -X POST http://localhost:8000/predict -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.tk/verify"}'
```

### 5. Load the extension
1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" → select the `extension/` folder
4. Make sure the API (step 4) is running — the extension calls
   `http://localhost:8000/predict`

## What to build on top of this scaffold

- Add the content-based features noted as TODOs in `feature_extraction.py`
  (requires fetching page HTML — do this carefully/sandboxed)
- Add WHOIS domain-age lookups (`python-whois` library)
- Try hyperparameter tuning (`GridSearchCV`) once you've picked a winner
- Log every prediction the extension makes to a local SQLite DB for later
  analysis (false positive/negative review — great viva material)
- Consider exporting the model to ONNX/TF.js to run fully client-side,
  removing the API dependency (mention this trade-off in your report either way)
