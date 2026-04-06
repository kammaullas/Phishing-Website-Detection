"""
Train the phishing detection model using the new 34-feature dataset.
Uses Random Forest with tuned hyperparameters + SHAP explainability.
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score, confusion_matrix
import shap

from feature_extractor import FeatureExtractor

# 1. Load Dataset
print("📂 Loading dataset...")
try:
    df = pd.read_csv('../data/phishing_data.csv')
except FileNotFoundError:
    print("❌ Dataset not found. Run '2_build_dataset.py' first.")
    exit()

print(f"   Rows: {len(df)}")
print(f"   Label distribution:\n{df['label'].value_counts().to_string()}\n")

# 2. Prepare Features and Target
X = df.drop(['label', 'url'], axis=1, errors='ignore')
y = df['label']

# Sanity check
if len(y.unique()) < 2:
    print(f"⚠️ Error: Dataset only contains class '{y.unique()[0]}'. Need both 0 and 1.")
    exit()

feature_names = X.columns.tolist()
print(f"   Features ({len(feature_names)}): {feature_names}\n")

# Fill any NaN values
X = X.fillna(0)

# 3. Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# 4. Train Random Forest
print("🚀 Training Random Forest Classifier...")
model = RandomForestClassifier(
    n_estimators=200,       # More trees for better accuracy
    max_depth=15,           # Prevent overfitting
    min_samples_split=5,
    min_samples_leaf=2,
    max_features='sqrt',
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# 5. Evaluate
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"\n📊 Results:")
print(f"   Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
print(f"   ROC-AUC:   {roc_auc_score(y_test, y_prob):.4f}")
print(f"\n   Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")
print(f"\n   Classification Report:\n{classification_report(y_test, y_pred)}")

# Cross-validation for robust estimate
cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
print(f"   5-Fold CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

# 6. Feature Importance
importances = pd.Series(model.feature_importances_, index=feature_names)
importances = importances.sort_values(ascending=False)
print(f"\n🔑 Top 10 Feature Importances:")
for feat, imp in importances.head(10).items():
    print(f"   {feat:35s} {imp:.4f}")

# 7. SHAP Explainer
print("\n🧠 Building SHAP Explainer...")
explainer = shap.TreeExplainer(model)

# 8. Save Artifacts
print("💾 Saving model artifacts...")
joblib.dump(model, 'model.pkl')
joblib.dump(explainer, 'explainer.pkl')
joblib.dump(feature_names, 'feature_names.pkl')

print("\n✅ Training complete! Artifacts saved:")
print("   ├── model.pkl")
print("   ├── explainer.pkl")
print("   └── feature_names.pkl")