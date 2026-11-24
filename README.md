# ⚡ ConfigGuard — Enterprise AI Infrastructure & Uptime Engine

> **Inspect Any Web Application or Endpoint for Production Outage & Scaling Bottlenecks.**  
> *Real-time endpoint latency profiling, SSL handshake verification, HTTP security posture, and 1,000 to 5,000 concurrent user scaling stress-test analysis.*

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Google SRE](https://img.shields.io/badge/Compliance-Google%20SRE%20Protocol-green.svg)](https://sre.google)

---

## 📌 1. Overview
ConfigGuard is a high-performance site reliability and security audit gate designed for modern cloud applications. Users simply enter an application URL (e.g., `https://velsuniversity.com`, `https://gnani.ai`, or `https://github.com/kishorein25/MindBloom-ChatCampanion`), and ConfigGuard executes real-time diagnostics:

* **Live Endpoint Profiling:** Measures real DNS and TCP response latency.
* **HTTP Security Posture:** Audits HSTS, CSP (Content-Security-Policy), X-Frame-Options, and server banner leaks.
* **1,000 to 5,000 Concurrent User Concurrency Stress-Testing:** Simulates traffic spikes using the endpoint's live baseline response time and charts failure points.
* **Automated Hardening Patch:** Generates production-ready Kubernetes Horizontal Pod Autoscaler (HPA) and Nginx reverse proxy configurations with 1-click download.

---

## 🛠️ 2. Quickstart & Local Installation

### Prerequisites
* Python 3.9+
* Pip

### Setup
```bash
# Navigate to the project directory
cd D:\Projects\ConfigGuard

# Install dependencies
pip install -r requirements.txt

# Launch the Application
streamlit run app.py
```

Open your browser at: `http://localhost:8501`

---

## 👨‍💻 Author
* **Kishore S** ([@kishorein25](https://github.com/kishorein25))
