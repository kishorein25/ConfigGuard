# 🛡️ ConfigGuard OS — Autonomous Infrastructure & Configuration Audit Engine

> **Live URL Security Auditing, DNS/TLS Profiling, GitHub Config Drift Detection & 1,000–5,000 Concurrent User Scaling Simulation.**  
> *Built with Python FastAPI + Tailwind CSS (Gnani.ai / Stitch Enterprise Dark UI).*

---

## 📌 What ConfigGuard OS Does
ConfigGuard OS inspects any live web application URL or public GitHub repository in real time—with **zero dummy data**:

1. **Real-Time Network & TLS Profiling:** Measures actual DNS lookup latency, TCP connect time, TLS handshake speed, active cipher suite, certificate issuer, and exact SSL days remaining.
2. **HTTP Security Posture Audit:** Checks live response headers for `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Server` banner disclosure.
3. **GitHub Configuration Drift Inspection:** When given a GitHub repository URL (e.g., `https://github.com/kishorein25/MindBloom-ChatCampanion`), inspects actual `k8s/*.yaml` and `.env*` files for port mismatches, missing CPU/memory boundaries (`resources.limits`), unpinned `:latest` tags, and missing readiness probes.
4. **Concurrency Stress Projection (1,000 → 5,000 Users):** Models saturation vs. Horizontal Pod Autoscaler (HPA) scaling using the endpoint's real measured TTFB baseline.
5. **One-Click Hardening Patch & Certificate Export:** Generates tailored Nginx + Kubernetes HPA patches and downloadable Markdown audit certificates.

---

## 🛠️ Quickstart (Local)

```bash
cd D:\Projects\ConfigGuard
pip install -r requirements.txt
uvicorn server:app --reload --port 8000
```

Open in browser: **`http://localhost:8000`**

---

## 👨‍💻 Author
* **Kishore S** ([@kishorein25](https://github.com/kishorein25))
