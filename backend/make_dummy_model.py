# backend/make_dummy_model.py
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
import shap

print("Generating dummy data...")

# These exactly match the keys in FeatureExtractor
feature_names = [
    'url_length', 'num_dots', 'num_hyphens', 'num_slashes', 
    'has_at_symbol', 'is_https', 'has_ip', 'subdomain_depth', 
    'domain_age_days', 'redirect_count', 'external_links', 'has_iframe'
]

# Create 100 rows of random synthetic data
X = pd.DataFrame(np.random.randint(0, 50, size=(100, len(feature_names))), columns=feature_names)
y = np.random.randint(0, 2, size=100) # Random 0s and 1s

print("Training dummy Random Forest...")
model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X, y)

print("Building SHAP Explainer...")
explainer = shap.TreeExplainer(model)

print("Saving artifacts...")
joblib.dump(model, 'model.pkl')
joblib.dump(explainer, 'explainer.pkl')
joblib.dump(feature_names, 'feature_names.pkl')

print("✅ Success! You can now run uvicorn main:app --reload")