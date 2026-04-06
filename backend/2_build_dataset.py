# backend/2_build_dataset.py
"""
Rebuild the dataset using the new 34-feature URL-string extractor.
Processes raw_urls.csv and outputs phishing_data.csv.
No network calls needed — runs in seconds.
"""

import pandas as pd
import os
import sys
from feature_extractor import FeatureExtractor

# --- CONFIGURATION ---
OUTPUT_FILE = '../data/phishing_data.csv'
RAW_FILE = '../data/raw_urls.csv'

# 1. Load raw URLs
try:
    raw_df = pd.read_csv(RAW_FILE)
    print(f"📂 Loaded {len(raw_df)} raw URLs from {RAW_FILE}")
except FileNotFoundError:
    print("❌ Error: Run 1_fetch_urls.py first to generate raw_urls.csv!")
    sys.exit(1)

# 2. Extract features for every URL
results = []
failed = 0
total = len(raw_df)

for idx, row in raw_df.iterrows():
    url = row['url']
    label = row['label']
    
    try:
        extractor = FeatureExtractor(url)
        features = extractor.extract_all()
        features['url'] = url
        features['label'] = label
        results.append(features)
    except Exception as e:
        failed += 1

    # Progress indicator every 200 URLs
    if (idx + 1) % 200 == 0 or idx == total - 1:
        print(f"  [{idx + 1}/{total}] Processed... ({failed} failed)")

# 3. Save
df = pd.DataFrame(results)

# Reorder columns so 'url' and 'label' are last
feature_cols = [c for c in df.columns if c not in ('url', 'label')]
df = df[feature_cols + ['url', 'label']]

df.to_csv(OUTPUT_FILE, index=False)

label_counts = df['label'].value_counts()
print(f"\n🎉 Dataset saved to {OUTPUT_FILE}")
print(f"   Total rows: {len(df)} ({failed} URLs failed)")
print(f"   Legitimate (0): {label_counts.get(0, 0)}")
print(f"   Phishing  (1): {label_counts.get(1, 0)}")
print(f"   Features: {len(feature_cols)}")