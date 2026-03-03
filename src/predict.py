import joblib
import numpy as np
import pandas as pd
from catboost import CatBoostClassifier

from src.feature_extractor import extract_features, get_feature_names

LGBM_PATH = 'models/lgbm_model.pkl'
CAT_PATH = 'models/catboost_model.cbm'

_lgbm_model = None
_cat_model = None


def load_models():
    global _lgbm_model, _cat_model
    _lgbm_model = joblib.load(LGBM_PATH)
    _cat_model = CatBoostClassifier()
    _cat_model.load_model(CAT_PATH)
    print("Models loaded successfully.")


def compute_anti_phishing_score(url: str) -> float:
    """
    Returns anti-phishing score between 0 and 1.
    0 = definitely phishing, 1 = definitely legitimate.
    """
    features = extract_features(url)
    feature_cols = get_feature_names()
    X = pd.DataFrame([features])[feature_cols].fillna(0)

    lgbm_prob = _lgbm_model.predict_proba(X)[0][1]   # prob of phishing
    cat_prob = _cat_model.predict_proba(X)[0][1]      # prob of phishing

    phishing_prob = (lgbm_prob + cat_prob) / 2

    # Anti-phishing score: higher = safer
    anti_phishing_score = 1 - phishing_prob
    return round(float(anti_phishing_score), 4)


def predict_url(url: str) -> dict:
    """Full prediction pipeline for a single URL."""
    url = url.strip()

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    score = compute_anti_phishing_score(url)

    # Risk levels
    if score >= 0.75:
        label = "Legitimate"
        risk = "Low Risk"
        color = "green"
    elif score >= 0.50:
        label = "Likely Legitimate"
        risk = "Medium Risk"
        color = "orange"
    elif score >= 0.25:
        label = "Likely Phishing"
        risk = "High Risk"
        color = "red"
    else:
        label = "Phishing"
        risk = "Very High Risk"
        color = "darkred"

    # Extract key features for explanation
    features = extract_features(url)
    red_flags = []
    if features.get('has_ip'):
        red_flags.append("Uses IP address instead of domain")
    if features.get('has_at_symbol'):
        red_flags.append("Contains @ symbol")
    if features.get('is_shortener'):
        red_flags.append("Uses URL shortener")
    if features.get('suspicious_tld'):
        red_flags.append(f"Suspicious TLD")
    if features.get('has_suspicious_keywords'):
        red_flags.append("Contains phishing keywords")
    if features.get('has_dash_in_domain'):
        red_flags.append("Has dash in domain name")
    if features.get('subdomain_count', 0) > 2:
        red_flags.append("Too many subdomains")
    if not features.get('has_https'):
        red_flags.append("Not using HTTPS")
    if features.get('url_length', 0) > 100:
        red_flags.append("Unusually long URL")

    return {
        'url': url,
        'anti_phishing_score': score,
        'prediction': label,
        'risk_level': risk,
        'color': color,
        'confidence': round(max(score, 1 - score) * 100, 1),
        'red_flags': red_flags
    }