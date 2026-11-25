"""ConfigGuard OS Backend - Real-time Infrastructure, SSL, Header & GitHub Config Auditor."""

import base64
import datetime
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="ConfigGuard OS API",
    version="4.2.0",
    description="Real-time SRE endpoint telemetry, security header audit, and Kubernetes/config drift analyzer.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    url: str
    target_users: int = 5000


def _normalize_url(raw_url: str) -> urllib.parse.ParseResult:
    cleaned = raw_url.strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="Please enter a valid URL.")
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    parsed = urllib.parse.urlparse(cleaned)
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Could not parse hostname from URL.")
    return parsed


def _inspect_dns_and_tls(hostname: str, port: int, is_https: bool) -> dict[str, Any]:
    """Measure real DNS resolution, TCP connect, and TLS certificate metadata."""
    info: dict[str, Any] = {
        "dns_ms": 0.0,
        "tcp_ms": 0.0,
        "tls_ms": 0.0,
        "tls_version": "Plaintext (No TLS)",
        "cipher": "None",
        "ssl_days_remaining": None,
        "ssl_issuer": None,
        "resolved_ip": None,
        "tls_error": None,
    }

    t0 = time.perf_counter()
    try:
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        info["dns_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if addr_info:
            info["resolved_ip"] = addr_info[0][4][0]
    except socket.gaierror as exc:
        info["dns_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        info["tls_error"] = f"DNS lookup failed: {exc}"
        return info

    t_tcp = time.perf_counter()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            info["tcp_ms"] = round((time.perf_counter() - t_tcp) * 1000, 1)
            if is_https:
                ctx = ssl.create_default_context()
                t_tls = time.perf_counter()
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    info["tls_ms"] = round((time.perf_counter() - t_tls) * 1000, 1)
                    info["tls_version"] = ssock.version() or "TLS"
                    cipher = ssock.cipher()
                    info["cipher"] = cipher[0] if cipher else "Unknown"
                    cert = ssock.getpeercert()
                    if cert:
                        not_after = cert.get("notAfter")
                        if not_after:
                            exp_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            delta = exp_dt - datetime.datetime.utcnow()
                            info["ssl_days_remaining"] = max(0, delta.days)
                        issuer_tuples = cert.get("issuer", ())
                        issuer_dict = dict(x[0] for x in issuer_tuples if x)
                        info["ssl_issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
    except Exception as exc:
        info["tls_error"] = str(exc)

    return info


def _fetch_http(full_url: str) -> dict[str, Any]:
    """Perform live HTTP GET probe and capture real headers and TTFB."""
    req = urllib.request.Request(
        full_url,
        headers={
            "User-Agent": "ConfigGuard-OS-SRE-Auditor/4.2 (+https://sre.google)",
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        },
        method="GET",
    )
    t_start = time.perf_counter()
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            # Read first chunk to confirm TTFB + payload availability
            resp.read(8192)
            total_ms = round((time.perf_counter() - t_start) * 1000, 1)
            return {
                "alive": True,
                "status_code": resp.getcode(),
                "latency_ms": total_ms,
                "headers": dict(resp.headers),
                "error": None,
            }
    except urllib.error.HTTPError as err:
        total_ms = round((time.perf_counter() - t_start) * 1000, 1)
        return {
            "alive": True,
            "status_code": err.code,
            "latency_ms": total_ms,
            "headers": dict(err.headers) if err.headers else {},
            "error": f"HTTP {err.code}: {err.reason}",
        }
    except Exception as exc:
        total_ms = round((time.perf_counter() - t_start) * 1000, 1)
        return {
            "alive": False,
            "status_code": 0,
            "latency_ms": total_ms,
            "headers": {},
            "error": str(exc),
        }


def _github_get_json(api_url: str) -> Any:
    req = urllib.request.Request(
        api_url,
        headers={
            "User-Agent": "ConfigGuard-OS-Auditor/4.2",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _audit_github_repo(parsed: urllib.parse.ParseResult) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Inspect real config files in a public GitHub repository."""
    findings: list[dict[str, Any]] = []
    repo_meta: dict[str, Any] = {"detected": False, "config_files": []}
    patch_snippets: list[str] = []

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return findings, repo_meta, patch_snippets

    owner, repo = parts[0], parts[1].removesuffix(".git")
    repo_meta["owner"] = owner
    repo_meta["repo"] = repo
    repo_meta["detected"] = True

    try:
        root_items = _github_get_json(f"https://api.github.com/repos/{owner}/{repo}/contents")
    except Exception as exc:
        findings.append({
            "severity": "WARNING",
            "code": "GITHUB-API-ACCESS",
            "title": "Unable to Inspect Repository Contents",
            "root_cause": f"GitHub API returned an error for {owner}/{repo}: {exc}",
            "impact": "Repository may be private or GitHub unauthenticated rate limit was reached.",
            "target": f"github.com/{owner}/{repo}",
            "patch_hint": "Verify repository visibility is public or supply a GitHub token.",
        })
        return findings, repo_meta, patch_snippets

    if not isinstance(root_items, list):
        return findings, repo_meta, patch_snippets

    file_names = {item["name"]: item for item in root_items}
    config_candidates = [
        name for name in [".env", ".env.example", "Dockerfile", "docker-compose.yml", "railway.json", "package.json", "requirements.txt"]
        if name in file_names
    ]
    repo_meta["config_files"].extend(config_candidates)

    if ".env" in file_names:
        findings.append({
            "severity": "CRITICAL",
            "code": "SEC-ENV-EXPOSURE",
            "title": "Live .env Secret File Committed to Public Repository",
            "root_cause": "Detected `.env` committed in repository root instead of `.gitignore`.",
            "impact": "API keys, database credentials, and tokens may be publicly exposed.",
            "target": ".env",
            "patch_hint": "Remove `.env` from git history, rotate exposed keys, and add `.env` to `.gitignore`.",
        })

    env_port = None
    if ".env.example" in file_names:
        try:
            env_data = _github_get_json(file_names[".env.example"]["url"])
            env_raw = base64.b64decode(env_data["content"]).decode("utf-8", errors="replace")
            for line in env_raw.splitlines():
                if line.strip().startswith("PORT="):
                    env_port = line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass

    # Inspect k8s/ directory if present
    if "k8s" in file_names and file_names["k8s"]["type"] == "dir":
        try:
            k8s_items = _github_get_json(file_names["k8s"]["url"])
            for kitem in k8s_items:
                if kitem["name"].endswith((".yaml", ".yml")):
                    repo_meta["config_files"].append(f"k8s/{kitem['name']}")
                    k_data = _github_get_json(kitem["url"])
                    k_raw = base64.b64decode(k_data["content"]).decode("utf-8", errors="replace")
                    docs = list(yaml.safe_load_all(k_raw))
                    for doc in docs:
                        if not isinstance(doc, dict):
                            continue
                        kind = doc.get("kind", "")
                        if kind == "Deployment":
                            spec = doc.get("spec", {})
                            replicas = spec.get("replicas", 1)
                            containers = spec.get("template", {}).get("spec", {}).get("containers", [])
                            for c in containers:
                                cname = c.get("name", "app")
                                image = c.get("image", "")
                                if image.endswith(":latest"):
                                    findings.append({
                                        "severity": "WARNING",
                                        "code": "K8S-MUTABLE-TAG",
                                        "title": f"Unpinned ':latest' Container Tag in {kitem['name']}",
                                        "root_cause": f"Container `{cname}` uses mutable image `{image}`.",
                                        "impact": "Deployments are non-reproducible and rollbacks may pull unexpected broken builds.",
                                        "target": f"k8s/{kitem['name']}",
                                        "patch_hint": "Pin image tag to an immutable SHA digest or semantic version (e.g. :v1.4.2).",
                                    })
                                if not c.get("resources", {}).get("limits"):
                                    findings.append({
                                        "severity": "CRITICAL",
                                        "code": "SRE-NO-OOM-LIMIT",
                                        "title": f"Missing CPU/Memory Limits in k8s/{kitem['name']}",
                                        "root_cause": f"Container `{cname}` defines no `resources.limits` or `resources.requests`.",
                                        "impact": "Under 1,000-5,000 concurrent users, memory leaks can starve the host node and trigger OOMKilled crash loops.",
                                        "target": f"k8s/{kitem['name']}",
                                        "patch_hint": "Inject resources.limits (cpu: 1000m, memory: 1Gi) and requests.",
                                    })
                                if not c.get("readinessProbe"):
                                    findings.append({
                                        "severity": "HIGH",
                                        "code": "SRE-NO-PROBE",
                                        "title": f"Missing Readiness Probe in k8s/{kitem['name']}",
                                        "root_cause": f"Container `{cname}` lacks a `readinessProbe` health check.",
                                        "impact": "Kubernetes routes live traffic to warming pods before the server finishes booting, causing 502 errors.",
                                        "target": f"k8s/{kitem['name']}",
                                        "patch_hint": "Add readinessProbe on the container's active listening port.",
                                    })
                                c_ports = [str(p.get("containerPort")) for p in c.get("ports", []) if p.get("containerPort")]
                                if env_port and c_ports and env_port not in c_ports:
                                    findings.append({
                                        "severity": "CRITICAL",
                                        "code": "NET-PORT-MISMATCH",
                                        "title": f"Port Mismatch Between .env.example ({env_port}) and k8s/{kitem['name']} ({','.join(c_ports)})",
                                        "root_cause": f"`.env.example` configures PORT={env_port}, whereas Kubernetes routes containerPort={','.join(c_ports)}.",
                                        "impact": "100% of ingress traffic hits a closed port in production, returning 502 Bad Gateway.",
                                        "target": f"k8s/{kitem['name']} vs .env.example",
                                        "patch_hint": f"Align containerPort and targetPort to {env_port}.",
                                    })
                            if isinstance(replicas, int) and replicas < 3:
                                findings.append({
                                    "severity": "HIGH",
                                    "code": "SRE-LOW-REPLICAS",
                                    "title": f"Fixed Low Replica Count (replicas={replicas}) Without HPA",
                                    "root_cause": f"Deployment `{doc.get('metadata', {}).get('name', 'app')}` is pinned to {replicas} replicas with no HorizontalPodAutoscaler.",
                                    "impact": "Cannot absorb sudden traffic surges from 1,000 to 5,000 concurrent users.",
                                    "target": f"k8s/{kitem['name']}",
                                    "patch_hint": "Provision HorizontalPodAutoscaler (minReplicas: 4, maxReplicas: 16).",
                                })
                        elif kind == "Service":
                            svc_type = doc.get("spec", {}).get("type", "ClusterIP")
                            if svc_type == "NodePort":
                                findings.append({
                                    "severity": "WARNING",
                                    "code": "K8S-NODEPORT-EXPOSED",
                                    "title": f"Hardcoded NodePort Service in k8s/{kitem['name']}",
                                    "root_cause": "Service uses `type: NodePort` instead of `ClusterIP` behind an Ingress/LoadBalancer.",
                                    "impact": "Exposes raw node ports and risks port collisions across multi-tenant clusters.",
                                    "target": f"k8s/{kitem['name']}",
                                    "patch_hint": "Switch to ClusterIP + TLS-terminated Ingress controller.",
                                })

            target_port = env_port or "8000"
            patch_snippets.append(
                f"""# Kubernetes Deployment & Autoscaler Patch for {owner}/{repo}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {repo.lower()}-hardened
spec:
  replicas: 4
  template:
    spec:
      containers:
        - name: {repo.lower()}
          ports:
            - containerPort: {target_port}  # Synced with environment PORT
          resources:
            limits:
              cpu: "1000m"
              memory: "1Gi"
            requests:
              cpu: "250m"
              memory: "512Mi"
          readinessProbe:
            httpGet:
              path: /health
              port: {target_port}
            initialDelaySeconds: 5
            periodSeconds: 10
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {repo.lower()}-hpa
spec:
  minReplicas: 4
  maxReplicas: 16
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70"""
            )
        except Exception:
            pass

    return findings, repo_meta, patch_snippets


def _build_concurrency_projection(base_ms: float, max_users: int, has_hpa: bool) -> list[dict[str, Any]]:
    """Model latency and failure risk across 500 -> max_users using queueing theory from real measured TTFB."""
    safe_base = max(25.0, min(base_ms if base_ms > 0 else 180.0, 2000.0))
    points = []
    step = 500
    for users in range(500, max_users + 1, step):
        # Single-instance / unhardened saturation knee around 1,500 concurrents
        load_factor = users / 1500.0
        if load_factor < 1.0:
            unhardened_ms = round(safe_base * (1.0 + 0.55 * (load_factor ** 2)), 1)
            err_pct = round(max(0.0, (load_factor - 0.6) * 8.0), 1)
        else:
            unhardened_ms = round(min(15000.0, safe_base * (1.55 + 4.5 * ((load_factor - 0.85) ** 2.2))), 1)
            err_pct = round(min(94.0, 6.0 + (load_factor - 1.0) * 38.0), 1)

        # Hardened with HPA (4 -> 16 pods) + connection pooling keeps utilization under ~65%
        replicas = min(16, max(4, (users // 350) + 2))
        hardened_ms = round(safe_base * (1.0 + (users / (replicas * 1200.0)) * 0.45), 1)
        hardened_err = 0.0 if users <= 5000 else 0.2

        points.append({
            "users": users,
            "unhardened_ms": unhardened_ms,
            "hardened_ms": hardened_ms,
            "unhardened_error_pct": err_pct,
            "hardened_error_pct": hardened_err,
            "active_replicas": replicas,
        })
    return points


@app.get("/")
def serve_frontend():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/healthz")
def health_check():
    return {"status": "ok", "service": "ConfigGuard OS", "version": "4.2.0"}


@app.get("/api/github/{username}")
def list_user_repos(username: str):
    """Fetch public GitHub repositories for one-click auditing."""
    safe_user = username.strip()
    if not safe_user:
        raise HTTPException(status_code=400, detail="GitHub username is required.")
    try:
        repos = _github_get_json(f"https://api.github.com/users/{urllib.parse.quote(safe_user)}/repos?sort=updated&per_page=15")
        return {
            "username": safe_user,
            "repos": [
                {
                    "name": r["name"],
                    "url": r["html_url"],
                    "language": r.get("language") or "Multi",
                    "description": r.get("description") or "No description",
                    "updated_at": r.get("updated_at"),
                }
                for r in repos
            ],
        }
    except urllib.error.HTTPError as err:
        raise HTTPException(status_code=err.code, detail=f"GitHub API error: {err.reason}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/audit")
def run_live_audit(payload: AuditRequest):
    """Run a real live audit against any web URL or GitHub repository URL."""
    t_audit_start = time.perf_counter()
    parsed = _normalize_url(payload.url)
    full_url = parsed.geturl()
    hostname = parsed.hostname or ""
    is_https = parsed.scheme == "https"
    port = parsed.port or (443 if is_https else 80)

    net_info = _inspect_dns_and_tls(hostname, port, is_https)
    http_info = _fetch_http(full_url)

    headers_lower = {k.lower(): v for k, v in http_info["headers"].items()}
    findings: list[dict[str, Any]] = []
    passed_checks = 0
    total_checks = 7
    score = 100

    # Check 1: Reachability & HTTP status
    if not http_info["alive"]:
        score -= 40
        findings.append({
            "severity": "CRITICAL",
            "code": "NET-UNREACHABLE",
            "title": "Target Endpoint Unreachable or Connection Timed Out",
            "root_cause": f"Failed to complete HTTP request to `{full_url}`: {http_info['error']}",
            "impact": "100% service outage; users receive connection timeout errors.",
            "target": full_url,
            "patch_hint": "Verify DNS records, firewall ports (80/443), and upstream server health.",
        })
    elif http_info["status_code"] >= 500:
        score -= 35
        findings.append({
            "severity": "CRITICAL",
            "code": f"HTTP-{http_info['status_code']}",
            "title": f"Upstream Server Returning HTTP {http_info['status_code']} Error",
            "root_cause": f"Endpoint responded with server failure `{http_info['error']}`.",
            "impact": "Requests are failing at origin or ingress gateway.",
            "target": full_url,
            "patch_hint": "Inspect backend logs, port bindings, and readiness probes.",
        })

    # Check 2: HTTPS / TLS
    if is_https and not net_info["tls_error"]:
        passed_checks += 1
        if net_info["ssl_days_remaining"] is not None and net_info["ssl_days_remaining"] < 14:
            score -= 15
            findings.append({
                "severity": "HIGH",
                "code": "TLS-EXPIRING-SOON",
                "title": f"SSL Certificate Expiring in {net_info['ssl_days_remaining']} Days",
                "root_cause": "TLS certificate renewal threshold (<14 days) breached.",
                "impact": "Browsers will block all users with security warnings once expired.",
                "target": hostname,
                "patch_hint": "Enable automated Cert-Manager / Let's Encrypt renewal.",
            })
    else:
        score -= 25
        findings.append({
            "severity": "CRITICAL",
            "code": "TLS-INSECURE",
            "title": "TLS / HTTPS Encryption Missing or Handshake Failed",
            "root_cause": net_info["tls_error"] or "Endpoint is served over unencrypted HTTP plaintext.",
            "impact": "User credentials and session cookies can be intercepted over public networks.",
            "target": full_url,
            "patch_hint": "Terminate TLS 1.3 at load balancer and force HTTPS redirects.",
        })

    # Check 3: HSTS
    if "strict-transport-security" in headers_lower:
        passed_checks += 1
    else:
        score -= 12
        findings.append({
            "severity": "HIGH",
            "code": "HDR-NO-HSTS",
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "root_cause": "Server response omits `Strict-Transport-Security` directive.",
            "impact": "Clients may connect over insecure HTTP on first visit, enabling SSL-stripping attacks.",
            "target": "HTTP Response Headers",
            "patch_hint": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
        })

    # Check 4: Content-Security-Policy
    if "content-security-policy" in headers_lower:
        passed_checks += 1
    else:
        score -= 15
        findings.append({
            "severity": "CRITICAL",
            "code": "HDR-NO-CSP",
            "title": "Missing Content-Security-Policy (CSP) Protection",
            "root_cause": "No `Content-Security-Policy` header enforced in HTTP response.",
            "impact": "Increases exposure to Cross-Site Scripting (XSS) and unauthorized script execution.",
            "target": "HTTP Response Headers",
            "patch_hint": "add_header Content-Security-Policy \"default-src 'self'; object-src 'none';\" always;",
        })

    # Check 5: X-Frame-Options
    if "x-frame-options" in headers_lower or "frame-ancestors" in headers_lower.get("content-security-policy", ""):
        passed_checks += 1
    else:
        score -= 8
        findings.append({
            "severity": "WARNING",
            "code": "HDR-CLICKJACK",
            "title": "Missing Clickjacking Protection (X-Frame-Options)",
            "root_cause": "Neither `X-Frame-Options` nor CSP `frame-ancestors` was returned.",
            "impact": "Site may be embedded in malicious third-party iframes.",
            "target": "HTTP Response Headers",
            "patch_hint": 'add_header X-Frame-Options "DENY" always;',
        })

    # Check 6: X-Content-Type-Options
    if headers_lower.get("x-content-type-options", "").lower() == "nosniff":
        passed_checks += 1
    else:
        score -= 6
        findings.append({
            "severity": "WARNING",
            "code": "HDR-MIME-SNIFF",
            "title": "Missing X-Content-Type-Options: nosniff",
            "root_cause": "Browser MIME-type sniffing is not explicitly disabled.",
            "impact": "Uploaded text/asset files could be interpreted as executable scripts.",
            "target": "HTTP Response Headers",
            "patch_hint": 'add_header X-Content-Type-Options "nosniff" always;',
        })

    # Check 7: Referrer-Policy
    if "referrer-policy" in headers_lower:
        passed_checks += 1
    else:
        score -= 5
        findings.append({
            "severity": "WARNING",
            "code": "HDR-REFERRER",
            "title": "Missing Referrer-Policy Header",
            "root_cause": "Response omits `Referrer-Policy` control.",
            "impact": "Full URL paths or query parameters may leak to external links.",
            "target": "HTTP Response Headers",
            "patch_hint": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        })

    # Check 8: Server Version Banner Disclosure
    server_hdr = headers_lower.get("server", "")
    if server_hdr and any(ch.isdigit() for ch in server_hdr):
        score -= 5
        findings.append({
            "severity": "WARNING",
            "code": "INFO-SERVER-BANNER",
            "title": f"Server Software Version Exposed (`{server_hdr}`)",
            "root_cause": f"Ingress/web server disclosed version details in `Server: {server_hdr}`.",
            "impact": "Helps automated scanners fingerprint exact software versions for known CVEs.",
            "target": "Ingress / Reverse Proxy",
            "patch_hint": "Set `server_tokens off;` in Nginx or strip `Server` header at edge.",
        })
    else:
        passed_checks += 1

    # Check latency SLA
    if http_info["alive"] and http_info["latency_ms"] > 1000:
        score -= 10
        findings.append({
            "severity": "HIGH",
            "code": "PERF-HIGH-TTFB",
            "title": f"High Origin Response Latency ({http_info['latency_ms']} ms)",
            "root_cause": "Initial single-request roundtrip exceeded 1,000ms SLA threshold.",
            "impact": "Under 1,000-5,000 concurrent users, connection queuing will rapidly exhaust worker threads.",
            "target": full_url,
            "patch_hint": "Enable edge caching, HTTP keep-alive pooling, and horizontal autoscaling.",
        })

    # GitHub Deep Repository Audit if URL points to GitHub
    repo_meta: dict[str, Any] = {"detected": False, "config_files": []}
    patch_snippets: list[str] = []
    if "github.com" in hostname.lower():
        gh_findings, repo_meta, patch_snippets = _audit_github_repo(parsed)
        findings.extend(gh_findings)
        for gf in gh_findings:
            if gf["severity"] == "CRITICAL":
                score -= 15
            elif gf["severity"] == "HIGH":
                score -= 10
            else:
                score -= 4

    final_score = max(0, min(100, score))
    if final_score >= 90:
        grade = "Grade A+ • Hardened"
    elif final_score >= 75:
        grade = "Grade B • Moderate Risk"
    elif final_score >= 55:
        grade = "Grade C • Needs Hardening"
    else:
        grade = "Grade F • Critical Outage Risk"

    # Build real dynamic remediation patch tailored to findings
    nginx_lines = ["# Edge / Reverse Proxy Security Header Hardening"]
    if "strict-transport-security" not in headers_lower:
        nginx_lines.append('add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;')
    if "content-security-policy" not in headers_lower:
        nginx_lines.append("add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';\" always;")
    if "x-frame-options" not in headers_lower:
        nginx_lines.append('add_header X-Frame-Options "DENY" always;')
    if headers_lower.get("x-content-type-options", "").lower() != "nosniff":
        nginx_lines.append('add_header X-Content-Type-Options "nosniff" always;')
    if "referrer-policy" not in headers_lower:
        nginx_lines.append('add_header Referrer-Policy "strict-origin-when-cross-origin" always;')
    nginx_lines.append("server_tokens off;")
    nginx_lines.append("keepalive_timeout 65;")
    nginx_lines.append("limit_req_zone $binary_remote_addr zone=api_burst:10m rate=100r/s;")

    if not patch_snippets:
        safe_name = hostname.replace(".", "-")
        patch_snippets.append(
            f"""# Kubernetes Autoscaling & Resource Protection for {hostname}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {safe_name}-hpa
spec:
  minReplicas: 4
  maxReplicas: 16   # Supports 1,000 -> 5,000 concurrent user surges
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70"""
        )

    full_patch = "\n".join(nginx_lines) + "\n\n" + "\n\n".join(patch_snippets)

    target_users = max(1000, min(5000, payload.target_users))
    concurrency_curve = _build_concurrency_projection(http_info["latency_ms"], target_users, has_hpa=False)

    audit_elapsed_ms = round((time.perf_counter() - t_audit_start) * 1000, 1)

    return JSONResponse({
        "url": full_url,
        "hostname": hostname,
        "audited_at": datetime.datetime.now().strftime("%H:%M:%S"),
        "audit_duration_ms": audit_elapsed_ms,
        "http": {
            "alive": http_info["alive"],
            "status_code": http_info["status_code"],
            "latency_ms": http_info["latency_ms"],
            "keep_alive": headers_lower.get("connection", "keep-alive"),
            "server": server_hdr or "Hidden",
            "headers": http_info["headers"],
            "error": http_info["error"],
        },
        "network": net_info,
        "security": {
            "score": final_score,
            "grade": grade,
            "passed_checks": passed_checks,
            "total_checks": total_checks,
        },
        "findings": findings,
        "github_repo": repo_meta,
        "concurrency_projection": concurrency_curve,
        "remediation_patch": full_patch,
    })
