import requests
import json

urls_to_test = [
    "google.com",
    "https://www.amazon.com",
    "http://192.168.1.1/secure-login/verify.php",
    "http://paypal-secure-login.suspicious-domain.tk/account/verify?user=123",
    "https://www.github.com",
    "http://bit.ly/3xYz",
]

for url in urls_to_test:
    try:
        r = requests.post("http://localhost:8000/predict", json={"url": url})
        d = r.json()
        verdict = d["verdict"].upper()
        conf = f'{d["confidence"]*100:.1f}%'
        risks = len(d.get("risk_indicators", []))
        print(f"  {'PHISH' if verdict=='PHISHING' else 'LEGIT'} ({conf}) | Risks: {risks} | {url}")
    except Exception as e:
        print(f"  ERROR: {e} | {url}")
