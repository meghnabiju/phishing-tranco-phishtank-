import joblib
import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split

from src.feature_extractor import get_feature_names

LGBM_PATH  = 'models/lgbm_model.pkl'
CAT_PATH   = 'models/catboost_model.cbm'
FEAT_PATH  = 'data/features.csv'


def evaluate():
    # ── Load cached features ─────────────────────────────────────────
    print("\nLoading features...")
    df = pd.read_csv(FEAT_PATH)

    feature_cols = get_feature_names()
    X = df[feature_cols].fillna(0)
    y = df['label']

    # Same split as training — random_state=42 ensures same test set
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Test set size: {len(X_test)} samples")
    print(f"  Legitimate : {(y_test == 0).sum()}")
    print(f"  Phishing   : {(y_test == 1).sum()}")

    # ── Load models ──────────────────────────────────────────────────
    print("\nLoading models...")
    lgbm = joblib.load(LGBM_PATH)
    cat  = CatBoostClassifier()
    cat.load_model(CAT_PATH)

    # ── Predictions ──────────────────────────────────────────────────
    lgbm_proba = lgbm.predict_proba(X_test)[:, 1]
    cat_proba  = cat.predict_proba(X_test)[:, 1]
    ens_proba  = (lgbm_proba + cat_proba) / 2

    lgbm_preds = (lgbm_proba >= 0.5).astype(int)
    cat_preds  = (cat_proba  >= 0.5).astype(int)
    ens_preds  = (ens_proba  >= 0.5).astype(int)

    # ── Print Report ─────────────────────────────────────────────────
    sep = "=" * 55

    print(f"\n{sep}")
    print("        MODEL EVALUATION REPORT")
    print(sep)

    # Individual models
    for name, preds, proba in [
        ("LightGBM", lgbm_preds, lgbm_proba),
        ("CatBoost", cat_preds,  cat_proba),
        ("Ensemble", ens_preds,  ens_proba),
    ]:
        acc  = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds)
        rec  = recall_score(y_test, preds)
        f1   = f1_score(y_test, preds)
        auc  = roc_auc_score(y_test, proba)

        tag = " ◄ BEST" if name == "Ensemble" else ""
        print(f"\n  {'─'*20} {name}{tag} {'─'*20}")
        print(f"  Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
        print(f"  Precision : {prec:.4f}  "
              f"(of URLs flagged as phishing, {prec*100:.1f}% were actually phishing)")
        print(f"  Recall    : {rec:.4f}  "
              f"(caught {rec*100:.1f}% of all phishing URLs)")
        print(f"  F1 Score  : {f1:.4f}  (balance of precision & recall)")
        print(f"  ROC-AUC   : {auc:.4f}  (1.0 = perfect, 0.5 = random)")

    # Confusion matrix (ensemble)
    cm = confusion_matrix(y_test, ens_preds)
    tn, fp, fn, tp = cm.ravel()

    print(f"\n{sep}")
    print("        CONFUSION MATRIX  (Ensemble)")
    print(sep)
    print(f"\n                  Predicted")
    print(f"                  Legit    Phishing")
    print(f"  Actual Legit  [ {tn:>6}    {fp:>6} ]")
    print(f"  Actual Phish  [ {fn:>6}    {tp:>6} ]")
    print(f"\n  True  Negatives (Legit correctly identified) : {tn}")
    print(f"  True  Positives (Phish correctly identified) : {tp}")
    print(f"  False Positives (Legit wrongly flagged)      : {fp}  ← safe sites marked phishing")
    print(f"  False Negatives (Phish missed)               : {fn}  ← phishing sites missed")

    # Classification report
    print(f"\n{sep}")
    print("        FULL CLASSIFICATION REPORT (Ensemble)")
    print(sep)
    print(classification_report(
        y_test, ens_preds,
        target_names=['Legitimate', 'Phishing'],
        digits=4
    ))

    # Feature importance
    print(f"{sep}")
    print("        TOP 10 FEATURES  (LightGBM importance)")
    print(sep)
    feat_imp = pd.Series(
        lgbm.feature_importances_,
        index=feature_cols
    ).sort_values(ascending=False)

    for i, (feat, imp) in enumerate(feat_imp.head(10).items(), 1):
        bar = '█' * int(imp / feat_imp.max() * 30)
        print(f"  {i:>2}. {feat:<30} {bar}  ({imp})")

    print(f"\n{sep}\n")