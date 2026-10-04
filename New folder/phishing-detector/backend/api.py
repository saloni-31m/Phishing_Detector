"""
Inference API for the phishing detector.
 
Run with:
    uvicorn api:app --reload --port 8000
 
The browser extension POSTs a URL here and gets back a phishing
probability + label. CORS is left open for local extension testing —
tighten this before any real deployment.
"""
 
import os
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
 
from feature_extraction import extract_features, get_full_domain
 
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "model_features.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")
 
app = FastAPI(title="Phishing URL Detector API")
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)
 
_model = None
_feature_cols = None
_scaler = None
 
 
def _load_artifacts():
    global _model, _feature_cols, _scaler
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise RuntimeError(
                "model.pkl not found — run train_model.py first"
            )
        _model = joblib.load(MODEL_PATH)
        _feature_cols = joblib.load(FEATURES_PATH)
        _scaler = joblib.load(SCALER_PATH)
 
 
class PredictRequest(BaseModel):
    url: str
 
 
class PredictResponse(BaseModel):
    url: str
    is_phishing: bool
    phishing_probability: float
    risk_level: str
    trust_override_applied: bool = False
 
 
# Trust override now covers subdomains of trusted domains too (e.g.
# students.masaischool.com is trusted because masaischool.com is), since
# for an institution's own site, subdomains are under the same owner's
# control — the false-positive cost of NOT trusting them outweighs the
# risk for most real-world sites.
#
# The one place this reasoning breaks down is free-hosting / user-generated
# subdomain platforms, where literally anyone can register
# "anything.platform.com" — trusting those blanket would defeat the whole
# point of a reputation check. Those apex domains are excluded from the
# override entirely, subdomain or not, so they're always scored purely
# on their URL features.
UGC_SUBDOMAIN_PLATFORMS = {
    "github.io", "blogspot.com", "wordpress.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "herokuapp.com", "netlify.app",
    "vercel.app", "pages.dev", "firebaseapp.com", "web.app",
    "googleusercontent.com", "sites.google.com", "notion.site",
    "glitch.me", "repl.co", "surge.sh", "azurewebsites.net",
}
 
TRUST_OVERRIDE_CAP = 0.05
 
 
def _apply_trust_override(proba: float, features: dict, full_domain: str) -> tuple[float, bool]:
    if full_domain in UGC_SUBDOMAIN_PLATFORMS:
        return proba, False  # never override — subdomains here are unowned
 
    is_reputable = features.get("is_trusted_domain") == 1
    is_restricted = features.get("is_restricted_tld") == 1
 
    if (is_reputable or is_restricted) and features.get("has_ip_address") == 0:
        return min(proba, TRUST_OVERRIDE_CAP), True
    return proba, False
 
 
@app.on_event("startup")
def startup():
    try:
        _load_artifacts()
    except RuntimeError as e:
        # Don't crash the server — just report on first request
        print(f"[warn] {e}")
 
 
@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _model is not None}
 
 
@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    _load_artifacts()
    if _model is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Run train_model.py first.",
        )
 
    features = extract_features(req.url)
    row = pd.DataFrame([features])[_feature_cols]
    row_scaled = _scaler.transform(row)
 
    proba = float(_model.predict_proba(row_scaled)[0, 1])
    full_domain = get_full_domain(req.url)
    proba, override_applied = _apply_trust_override(proba, features, full_domain)
    is_phishing = proba >= 0.5
 
    if proba >= 0.75:
        risk = "high"
    elif proba >= 0.5:
        risk = "medium"
    elif proba >= 0.25:
        risk = "low"
    else:
        risk = "safe"
 
    return PredictResponse(
        url=req.url,
        is_phishing=is_phishing,
        phishing_probability=round(proba, 4),
        risk_level=risk,
        trust_override_applied=override_applied,
    )