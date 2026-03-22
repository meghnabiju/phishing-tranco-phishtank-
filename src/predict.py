import joblib
import numpy as np
import pandas as pd
from catboost import CatBoostClassifier

from src.feature_extractor import extract_features, get_feature_names

LGBM_PATH = 'models/lgbm_model.pkl'
CAT_PATH  = 'models/catboost_model.cbm'

_lgbm_model = None
_cat_model  = None


def load_models():
    global _lgbm_model, _cat_model
    _lgbm_model = joblib.load(LGBM_PATH)
    _cat_model  = CatBoostClassifier()
    _cat_model.load_model(CAT_PATH)
    print("Models loaded successfully.")


def compute_anti_phishing_score(url: str) -> float:
    features      = extract_features(url)
    feature_cols  = get_feature_names()
    X             = pd.DataFrame([features])[feature_cols].fillna(0)
    lgbm_prob     = _lgbm_model.predict_proba(X)[0][1]
    cat_prob      = _cat_model.predict_proba(X)[0][1]
    phishing_prob = (lgbm_prob + cat_prob) / 2
    return round(float(1 - phishing_prob), 4)


def predict_url(url: str) -> dict:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    score = compute_anti_phishing_score(url)

    if score >= 0.75:
        label, risk, color = "Legitimate",        "Low Risk",       "green"
    elif score >= 0.50:
        label, risk, color = "Likely Legitimate",  "Medium Risk",   "orange"
    elif score >= 0.25:
        label, risk, color = "Likely Phishing",   "High Risk",      "red"
    else:
        label, risk, color = "Phishing",           "Very High Risk", "darkred"

    features  = extract_features(url)
    red_flags = []

    if features.get('has_ip'):
        red_flags.append("Uses IP address instead of domain")
    if features.get('has_at_symbol'):
        red_flags.append("Contains @ symbol")
    if features.get('is_shortener'):
        red_flags.append("Uses URL shortener service")
    if features.get('suspicious_tld'):
        red_flags.append("Suspicious free/disposable TLD (.tk .ml .xyz etc)")
    if features.get('brand_spoofing'):
        red_flags.append("Brand name spoofing detected")
    if features.get('phishing_keyword'):
        red_flags.append("Contains phishing-specific keywords")
    if features.get('brand_hyphen_pattern'):
        red_flags.append("Brand name with hyphen pattern in domain")
    if features.get('long_hyphenated_sld'):
        red_flags.append("Suspiciously long hyphenated domain name")
    if features.get('subdomain_depth', 0) >= 2:
        red_flags.append("Excessive subdomain depth")
    if not features.get('has_https'):
        red_flags.append("Not using HTTPS")
    if features.get('https_in_domain'):
        red_flags.append("'https' keyword deceptively inside domain name")
    if features.get('suspicious_path'):
        red_flags.append("Multiple suspicious keywords in URL path")
    if features.get('suspicious_query_params'):
        red_flags.append("Suspicious redirect parameters in URL")
    if features.get('has_double_slash'):
        red_flags.append("Double slash redirect detected")
    if features.get('numeric_domain'):
        red_flags.append("Domain is a numeric IP address")

    return {
        'url':                 url,
        'anti_phishing_score': score,
        'prediction':          label,
        'risk_level':          risk,
        'color':               color,
        'confidence':          round(max(score, 1 - score) * 100, 1),
        'red_flags':           red_flags
    }