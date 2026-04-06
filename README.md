# 🛡️ PhishGuard ML: Phishing Website Detection

A professional, machine-learning-powered phishing detection system that analyzes URL strings in real-time to identify malicious intent. PhishGuard uses **XGBoost** for classification and **SHAP** for explainable AI predictions.

---

## 🏗️ Structural View Architecture

The system's structural integrity can be decomposed into three primary layers:
1.  **Backend (FastAPI)**: Handles request validation and orchestrates the ML pipeline.
2.  **ML Engine (Feature Extractor)**: Decomposes URL strings into 34+ numerical features (no network calls required).
3.  **Frontend (Vanilla JS/CSS)**: A premium, dark-themed dashboard for scanning and history visualization.

> [!TIP]
> You can find detailed **Class** and **Object** diagrams in the project root to understand the system's class relationships and runtime behavior.

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.9+**
- **Git**
- A modern web browser (Chrome/Edge/Firefox)

### 1. Installation

Clone the repository and set up a virtual environment:

```powershell
# Clone the repository
git clone https://github.com/kammaullas/Phishing-Website-Detection.git
cd Phishing-Website-Detection

# Create a virtual environment
python -m venv venv

# Activate it (Windows)
.\venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt
```

### 2. Running the Backend (API)

The backend must be running for URLs to be scanned:

```powershell
cd backend
uvicorn main:app --reload
```
-   **API Base URL**: `http://localhost:8000`
-   **Documentation**: Visit `http://localhost:8000/docs` for the interactive API docs.

### 3. Running the Frontend

The frontend is built with vanilla JS and CSS, so it doesn't require a build step.
Simply open `frontend/index.html` in your browser.

Alternatively, if you're using VS Code, use the **Live Server** extension to host it.

---

## 🔍 Features & Functionality

-   **Zero-Network Feature Extraction**: Analysis is done purely on the URL string, making it immune to "cloaking" or site downtime.
-   **Explainable AI (SHAP)**: Every prediction comes with a "Top Drivers" breakdown showing *why* a URL was flagged.
-   **Risk Indicators**: Immediate visual flags for suspicious patterns (e.g., suspicious TLDs, Punycode, excessive hyphens).
-   **Scan History**: Automatically persists your previous scans in local storage.

---

## 🛠️ Tech Stack
-   **Backend**: FastAPI, Scikit-learn, XGBoost, SHAP, Joblib.
-   **Frontend**: Vanilla HTML5, CSS3 (Glassmorphism), JavaScript (ES6+).
-   **Deployment**: Ready for Docker/Heroku deployment.

---

*Developed by [@kammaullas](https://github.com/kammaullas)*
