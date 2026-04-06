"""
Phishing Detection API
======================
FastAPI backend serving ML predictions with SHAP explanations.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import joblib
import pandas as pd
import numpy as np

from feature_extractor import FeatureExtractor

# --- App Setup ---
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="PhishGuard ML API",
    description="ML-powered phishing URL detection with SHAP explanations"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Load Model Artifacts ---
try:
    model = joblib.load('model.pkl')
    explainer = joblib.load('explainer.pkl')
    feature_names = joblib.load('feature_names.pkl')
    print(f"✅ Model loaded with {len(feature_names)} features")
except FileNotFoundError:
    raise Exception(
        "Model artifacts not found! Run:\n"
        "  1. python 2_build_dataset.py\n"
        "  2. python train.py"
    )


class URLRequest(BaseModel):
    url: str


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": True,
        "num_features": len(feature_names)
    }


@app.post("/predict")
@limiter.limit("30/minute")
def predict_phishing(request: Request, payload: URLRequest):
    url = payload.url.strip()
    
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL too long (max 2048 chars)")

    try:
        # 1. Extract Features
        extractor = FeatureExtractor(url)
        features_dict = extractor.extract_all()

        # 2. Format for Model — ensure column order matches training
        input_df = pd.DataFrame([features_dict])
        
        # Reorder columns to match training feature order
        # Add any missing columns with 0, drop any extra columns
        for col in feature_names:
            if col not in input_df.columns:
                input_df[col] = 0
        input_df = input_df[feature_names]
        input_df = input_df.fillna(0)

        # 3. Predict
        prediction = int(model.predict(input_df)[0])
        probabilities = model.predict_proba(input_df)[0]
        confidence = float(np.max(probabilities))
        phishing_probability = float(probabilities[1]) if len(probabilities) > 1 else confidence

        # 4. SHAP Values for Explanation
        shap_values = explainer.shap_values(input_df)

        # Handle different SHAP output formats
        if isinstance(shap_values, list):
            # Binary classification: [class_0_shap, class_1_shap]
            class_1_shap = shap_values[1][0]
        elif isinstance(shap_values, np.ndarray):
            if shap_values.ndim == 3:
                # Shape: (samples, features, classes)
                class_1_shap = shap_values[0, :, 1]
            else:
                # Shape: (samples, features)
                class_1_shap = shap_values[0]
        else:
            class_1_shap = np.zeros(len(feature_names))

        # Build SHAP breakdown
        shap_breakdown = []
        for feature, val in zip(feature_names, class_1_shap):
            shap_breakdown.append({
                "feature": feature,
                "contribution": round(float(val), 4),
                "actual_value": features_dict.get(feature, 0)
            })

        # Sort by absolute impact
        shap_breakdown.sort(key=lambda x: abs(x['contribution']), reverse=True)

        # 5. Compute risk indicators (readable summary for frontend)
        risk_indicators = []
        if features_dict.get('has_ip_address'):
            risk_indicators.append("Uses IP address instead of domain name")
        if features_dict.get('uses_shortening_service'):
            risk_indicators.append("Uses URL shortening service")
        if features_dict.get('has_punycode'):
            risk_indicators.append("Contains punycode (possible homoglyph attack)")
        if features_dict.get('tld_is_suspicious'):
            risk_indicators.append("Has suspicious top-level domain")
        if features_dict.get('brand_in_subdomain'):
            risk_indicators.append("Brand name used in subdomain (impersonation)")
        if features_dict.get('path_has_suspicious_keyword'):
            risk_indicators.append("Path contains suspicious keywords (login/verify/etc)")
        if features_dict.get('has_at_symbol'):
            risk_indicators.append("Contains @ symbol (URL redirect trick)")
        if features_dict.get('has_hex_encoding'):
            risk_indicators.append("Contains hex encoding (URL obfuscation)")
        if not features_dict.get('is_https'):
            risk_indicators.append("Does not use HTTPS")
        if features_dict.get('domain_entropy', 0) > 3.5:
            risk_indicators.append("Domain name has high entropy (random-looking)")
        if features_dict.get('domain_hyphen_count', 0) >= 3:
            risk_indicators.append("Domain has excessive hyphens")
        if features_dict.get('subdomain_depth', 0) >= 3:
            risk_indicators.append("Excessive subdomain depth")

        # Safety indicators
        safety_indicators = []
        if features_dict.get('is_https'):
            safety_indicators.append("Uses HTTPS encryption")
        if features_dict.get('domain_entropy', 0) < 2.5:
            safety_indicators.append("Domain name is clean and simple")
        if features_dict.get('subdomain_depth', 0) <= 1:
            safety_indicators.append("Simple domain structure")
        if not features_dict.get('has_ip_address') and not features_dict.get('uses_shortening_service'):
            safety_indicators.append("Uses standard domain name")

        return {
            "url": url,
            "verdict": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(confidence, 4),
            "phishing_probability": round(phishing_probability, 4),
            "top_drivers": shap_breakdown[:6],
            "risk_indicators": risk_indicators,
            "safety_indicators": safety_indicators,
            "features": features_dict
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")