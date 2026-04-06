import requests
import json
import pandas as pd

url = "google.com"
r = requests.post("http://localhost:8000/predict", json={"url": url})
data = r.json()

print(f"URL: {data['url']}")
print(f"Verdict: {data['verdict']}")
print(f"Confidence: {data['confidence']}")
print(f"Phishing Prob: {data['phishing_probability']}")

print("\n--- Top Drivers ---")
for driver in data['top_drivers']:
    direction = "PHISH" if driver['contribution'] > 0 else "LEGIT"
    print(f"{driver['feature']:25} | Value: {driver['actual_value']:6} | Contrib: {driver['contribution']:8.4f} | {direction}")

print("\n--- Features ---")
# Print all features to see if anything looks weird
for k, v in data['features'].items():
    print(f"{k:25}: {v}")
