"""
Train and compare multiple models for phishing URL detection.

Expects data/urls.csv (relative to project root) with columns: url,label
  label: 1 = phishing, 0 = legitimate

Usage:
    python train_model.py

Outputs:
    - Prints a comparison table (accuracy, precision, recall, F1, ROC-AUC)
      for Logistic Regression, Random Forest, Gradient Boosting, and SVM
    - Saves the best-performing model (by F1) to model.pkl
    - Saves the feature column order to model_features.pkl (the API needs
      this to build feature vectors in the same order at inference time)
"""

import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
)

from feature_extraction import extract_features

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "urls.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "model_features.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")


def load_and_featurize(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must have 'url' and 'label' columns")

    print(f"Loaded {len(df)} rows. Extracting features...")
    feature_rows = []
    for i, url in enumerate(df["url"]):
        try:
            feature_rows.append(extract_features(str(url)))
        except Exception as e:
            feature_rows.append(None)
            print(f"  [warn] failed to featurize row {i} ({url}): {e}")
        if (i + 1) % 1000 == 0:
            print(f"  ...{i + 1}/{len(df)}")

    feat_df = pd.DataFrame(feature_rows)
    feat_df["label"] = df["label"].values
    feat_df = feat_df.dropna()
    return feat_df


def main():
    if not os.path.exists(DATA_PATH):
        print(f"ERROR: {DATA_PATH} not found.")
        print("Create data/urls.csv with columns: url,label (see data/DATASETS.md)")
        return

    feat_df = load_and_featurize(DATA_PATH)
    feature_cols = [c for c in feat_df.columns if c != "label"]

    X = feat_df[feature_cols]
    y = feat_df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Random Forest": RandomForestClassifier(n_estimators=200, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
        "SVM (RBF)": SVC(probability=True, random_state=42),
    }

    results = []
    trained = {}

    for name, model in models.items():
        model.fit(X_train_scaled, y_train)
        preds = model.predict(X_test_scaled)
        probs = model.predict_proba(X_test_scaled)[:, 1]

        results.append({
            "model": name,
            "accuracy": accuracy_score(y_test, preds),
            "precision": precision_score(y_test, preds),
            "recall": recall_score(y_test, preds),
            "f1": f1_score(y_test, preds),
            "roc_auc": roc_auc_score(y_test, probs),
        })
        trained[name] = model

    results_df = pd.DataFrame(results).sort_values("f1", ascending=False)
    print("\n=== Model comparison ===")
    print(results_df.to_string(index=False))

    best_name = results_df.iloc[0]["model"]
    best_model = trained[best_name]
    print(f"\nBest model by F1: {best_name}")

    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(feature_cols, FEATURES_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved feature order to {FEATURES_PATH}")
    print(f"Saved scaler to {SCALER_PATH}")

    # Recall matters most for phishing detection — missing a real phishing
    # site is worse than a false alarm. Flag it explicitly:
    best_recall = results_df.iloc[0]["recall"]
    print(f"\nNote: {best_name} recall = {best_recall:.3f} "
          f"(fraction of actual phishing sites correctly caught)")


if __name__ == "__main__":
    main()
