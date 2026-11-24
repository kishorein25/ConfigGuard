# 🛡️ ConfigGuard OS — Autonomous Pre-Flight Configuration Validator

> **Preventing Cloud Outages & Ensuring 1,000 to 5,000 User Concurrency Scaling Before Code Hits Production.**  
> *Built on Google Site Reliability Engineering (SRE) Outage Prevention Principles.*

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Google SRE](https://img.shields.io/badge/Compliance-Google%20SRE%20Protocol-green.svg)](https://sre.google)

---

## 📌 1. The Real-World Problem
According to the **Google Site Reliability Engineering (SRE) Book** and post-mortems from **Amazon AWS** and **Microsoft**:
> **"Over 70% of major production outages are caused by configuration changes, not code bugs."**

While developers spend weeks writing unit tests for Python, Java, or Node.js code, **nobody tests configuration files** (`deployment.yaml`, `config.json`, `.env`). A single wrong port, missing memory boundary, or low database connection limit causes catastrophic outages under user traffic.

### Recent Real-World Proof:
* **The Global Microsoft Outlook / 365 Outage:** Caused by a faulty network router configuration update.
* **The CrowdStrike Outage (July 2024):** Caused by a single faulty configuration channel file (Channel File 291).
* **The Exam Result Day Collapse:** A university portal crashes when 5,000 students log in simultaneously because the configuration capped traffic at 100 connections.

---

## 🚀 2. What ConfigGuard Does

`ConfigGuard` acts as an automated **Pre-Flight Safety Gate** for software deployments:

1. **Pre-Flight Static Analysis:** Scans Kubernetes YAML, Docker, and environment configs before deployment.
2. **Real-World Scenarios Included:**
   - **`MindBloom-ChatCampanion`:** Audits real deployment configs from GitHub, detecting port mismatches and OOM memory leak risks.
   - **`High-Traffic Scaling Crisis`:** Simulates traffic jumping from 1,000 to 5,000 concurrent users.
   - **`Vels University Results Portal`:** Catches low student connection ceilings and 2-second payment timeouts.
3. **Interactive Concurrency Stress-Testing (Plotly Engine):**
   - Visualizes latency and error rate curves as user load climbs from 500 to 5,000 concurrent users.
   - Proves how the un-rectified config crashes at 1,200 users, while the auto-rectified config scales smoothly.
4. **✨ One-Click Auto-Rectification Engine:**
   - Automatically synchronizes mismatched ports.
   - Injects memory and CPU limits (`resources.limits`).
   - Configures Horizontal Pod Autoscalers (HPA) to handle up to 5,000 users.
   - Exports production-ready files with one click.

---

## 🛠️ 3. Quickstart & Local Installation

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

## 📊 4. Architecture Workflow

```
[ Developer Writes Config / YAML / JSON ]
                   ⬇
    [ 🛡️ ConfigGuard Pre-Flight Safety Gate ]
                   ⬇
  ├── Static Rule Validator (Memory, CPU, Ports, Timeouts)
  ├── Concurrency Stress Model (1,000 -> 5,000 Users)
  └── Outage Risk Score Generator (0 - 100)
                   ⬇
  [ ❌ BLOCKED if Risk >= 80% (Outage Prevented!) ]
                   ⬇
  [ ✨ Auto-Rectify Engine Generates Safe Config ]
                   ⬇
  [ 📥 1-Click Export to Kubernetes / Cloud Production ]
```

---

## 👨‍💻 Author
* **Kishore S** ([@kishorein25](https://github.com/kishorein25))
