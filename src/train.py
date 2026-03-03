import os
import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, accuracy_score,
    roc_auc_score, confusion_matrix
)

from src.feature_extractor import extract_features_batch, get_feature_names

DATA_PATH = 'data/dataset.csv'
MODEL_DIR = 'models'


def train():
    os.makedirs(MODEL_DIR, exist_ok=True)

    # ── Load Dataset ────────────────────────────────────────────────────
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    print(f"Total rows: {len(df)}")
    print(df['label'].value_counts())

    # ── Extract Features ────────────────────────────────────────────────
    features_path = 'data/features.csv'

    if os.path.exists(features_path):
        print("\nLoading cached features...")
        features_df = pd.read_csv(features_path)
    else:
        print("\nExtracting features from URLs (this takes a few minutes)...")
        features_df = extract_features_batch(df['url'].tolist())
        features_df['label'] = df['label'].values
        features_df.to_csv(features_path, index=False)
        print(f"Features cached to {features_path}")

    # ── Prepare X, y ────────────────────────────────────────────────────
    feature_cols = get_feature_names()
    X = features_df[feature_cols]
    y = features_df['label']

    # Check for any NaN in features
    nan_count = X.isnull().sum().sum()
    if nan_count > 0:
        print(f"Filling {nan_count} NaN values with 0")
        X = X.fillna(0)

    print(f"\nFeature matrix shape: {X.shape}")
    print(f"Class distribution: {y.value_counts().to_dict()}")

    # ── Train/Test Split ─────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)}, Test: {len(X_test)}")

    # ── LightGBM ─────────────────────────────────────────────────────────
    print("\n--- Training LightGBM ---")
    lgbm = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        max_depth=7,
        num_leaves=50,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight='balanced',
        random_state=42,
        verbose=-1
    )
    lgbm.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        callbacks=[lgbm_print_callback()]
    )

    # ── CatBoost ──────────────────────────────────────────────────────────
    print("\n--- Training CatBoost ---")
    cat = CatBoostClassifier(
        iterations=300,
        learning_rate=0.05,
        depth=7,
        eval_metric='AUC',
        random_seed=42,
        verbose=50,
        auto_class_weights='Balanced'
    )
    cat.fit(X_train, y_train, eval_set=(X_test, y_test))

    # ── Ensemble Evaluation ───────────────────────────────────────────────
    print("\n--- Ensemble Evaluation ---")
    lgbm_proba = lgbm.predict_proba(X_test)[:, 1]
    cat_proba = cat.predict_proba(X_test)[:, 1]

    # Average probabilities
    ensemble_proba = (lgbm_proba + cat_proba) / 2
    ensemble_preds = (ensemble_proba >= 0.5).astype(int)

    acc = accuracy_score(y_test, ensemble_preds)
    auc = roc_auc_score(y_test, ensemble_proba)
    cm = confusion_matrix(y_test, ensemble_preds)

    print(f"\nAccuracy:  {acc:.4f}")
    print(f"ROC-AUC:   {auc:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"              Predicted Legit  Predicted Phish")
    print(f"Actual Legit       {cm[0][0]:>6}           {cm[0][1]:>6}")
    print(f"Actual Phish       {cm[1][0]:>6}           {cm[1][1]:>6}")
    print(f"\n{classification_report(y_test, ensemble_preds, target_names=['Legitimate', 'Phishing'])}")

    # Individual model scores
    lgbm_preds = (lgbm_proba >= 0.5).astype(int)
    cat_preds = (cat_proba >= 0.5).astype(int)
    print(f"LightGBM alone: {accuracy_score(y_test, lgbm_preds):.4f}")
    print(f"CatBoost alone: {accuracy_score(y_test, cat_preds):.4f}")
    print(f"Ensemble:       {acc:.4f}")

    # Feature importance
    print("\n--- Top 10 Important Features (LightGBM) ---")
    importance = pd.Series(
        lgbm.feature_importances_, index=feature_cols
    ).sort_values(ascending=False)
    print(importance.head(10).to_string())

    # ── Save Models ───────────────────────────────────────────────────────
    joblib.dump(lgbm, os.path.join(MODEL_DIR, 'lgbm_model.pkl'))
    cat.save_model(os.path.join(MODEL_DIR, 'catboost_model.cbm'))
    print(f"\nModels saved to /{MODEL_DIR}/")


def lgbm_print_callback():
    """Simple callback to print LightGBM progress every 50 rounds."""
    from lightgbm import callback
    def _callback(env):
        if env.iteration % 50 == 0:
            print(f"  LightGBM round {env.iteration}")
    _callback.order = 10
    return _callback


if __name__ == '__main__':
    train()