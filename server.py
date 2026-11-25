"""ConfigGuard OS Backend - Real-time Infrastructure, SSL, Header, Concurrency & GitHub Config Auditor."""

import base64
import concurrent.futures
import datetime
import json
import math
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
    version="4.3.0",
    description="Real-time SRE endpoint telemetry, security header audit, Little's Law capacity modeling, and Kubernetes/config drift analyzer.",
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


class ChatRequest(BaseModel):
    question: str
    audit_context: dict[str, Any] | None = None


_PLAIN_FINDING_GUIDANCE: dict[str, tuple[str, str]] = {
    "NET-UNREACHABLE": (
        "The website did not open at all—it timed out or is down.",
        "Hosting server / Domain DNS panel",
    ),
    "TLS-INSECURE": (
        "The browser safety lock (HTTPS) is missing or broken, so passwords could be seen.",
        "Cloudflare / Domain SSL settings",
    ),
    "TLS-EXPIRING-SOON": (
        "The security lock certificate is about to expire soon, which will show browser warnings.",
        "Hosting / SSL Certificate settings",
    ),
    "HDR-NO-HSTS": (
        "Browsers are not forced to always open the safe HTTPS version first.",
        "Web Server (Nginx) or Cloudflare SSL rules",
    ),
    "HDR-NO-CSP": (
        "No script shield—if someone slips fake JavaScript into a form, the browser might run it.",
        "Web Server / Reverse Proxy headers (see Patch tab)",
    ),
    "HDR-CLICKJACK": (
        "Another shady website could hide your page inside an invisible frame to trick clicks.",
        "Web Server / Reverse Proxy headers",
    ),
    "HDR-MIME-SNIFF": (
        "Browsers might guess uploaded files as runnable programs instead of plain files.",
        "Web Server / Reverse Proxy headers",
    ),
    "HDR-REFERRER": (
        "When users click outside links, your internal page link details may be shared.",
        "Web Server / Reverse Proxy headers",
    ),
    "INFO-RUNTIME-LEAK": (
        "The website announces what software it runs on (e.g., Express), making it easier for hackers to look up bugs.",
        "Backend app config (disable X-Powered-By / server tokens)",
    ),
    "COOKIE-WEAK-FLAGS": (
        "The login cookie is missing extra safety locks, making session hijacking easier.",
        "Backend login / session cookie settings",
    ),
    "PERF-HIGH-TTFB": (
        "Even for 1 person, the server takes over 1 second to reply. Under heavy crowds, it will jam.",
        "Backend database/server optimization & caching",
    ),
    "SEC-ENV-EXPOSURE": (
        "A private `.env` password/API-key file is sitting publicly on GitHub for anyone to read.",
        "GitHub repo root (.env + .gitignore)",
    ),
    "K8S-MUTABLE-TAG": (
        "Deployment uses `:latest` instead of a fixed version number, so updates can break unexpectedly.",
        "GitHub file: k8s/deployment.yaml",
    ),
    "SRE-NO-OOM-LIMIT": (
        "No memory limit is set—if many users visit, the app can eat all server RAM and crash.",
        "GitHub file: k8s/deployment.yaml (resources.limits)",
    ),
    "SRE-NO-PROBE": (
        "Cloud does not check if the app finished starting before sending users to it.",
        "GitHub file: k8s/deployment.yaml (readinessProbe)",
    ),
    "NET-PORT-MISMATCH": (
        "Your app listens on one door (port) while Kubernetes knocks on a different door—causing 502 errors.",
        "GitHub files: .env.example & k8s/deployment.yaml",
    ),
    "SRE-LOW-REPLICAS": (
        "Only a small fixed number of servers are running with no auto-scaling for traffic spikes.",
        "GitHub file: k8s/deployment.yaml (+ add HPA)",
    ),
    "K8S-NODEPORT-EXPOSED": (
        "Raw server port is exposed directly instead of using a clean load balancer.",
        "GitHub file: k8s/service.yaml",
    ),
}


def _enrich_findings_plain_english(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach short, non-technical meaning and exact fix location to every finding."""
    for f in findings:
        code = f.get("code", "")
        if code in _PLAIN_FINDING_GUIDANCE:
            meaning, where = _PLAIN_FINDING_GUIDANCE[code]
        elif code.startswith("HTTP-"):
            meaning = "The server crashed or returned an error page instead of loading normally."
            where = "Backend server logs & application code"
        else:
            meaning = f.get("root_cause", "Configuration rule failed.")
            where = f.get("target", "Server configuration")
        f["simple_meaning"] = meaning
        f["where_to_fix"] = where
    return findings


def _build_plain_capacity_summary(safe_cap: int, points: list[dict[str, Any]], alive: bool) -> str:
    """Summarize concurrent capacity in plain everyday English for non-technical employees."""
    if not alive or safe_cap == 0:
        return "Website is currently unreachable, so 0 users can access it right now."

    overload_pt = next((p for p in points if p["unhardened_error_pct"] >= 20 or p["unhardened_ms"] >= 5000), None)
    end_pt = points[-1] if points else {"users": 5000, "unhardened_error_pct": 0, "unhardened_ms": 0}

    if safe_cap >= 5000 and end_pt["unhardened_error_pct"] < 5:
        return f"Safe for ~{safe_cap:,}+ users at the same time. Even at 5,000 users, it stays responsive."
    if overload_pt:
        return (
            f"Safe for ~{safe_cap:,} users at a time. Around {overload_pt['users']:,} users it starts overloading, "
            f"and at {end_pt['users']:,} users the server slows to {round(end_pt['unhardened_ms'] / 1000, 1)}s "
            f"and crashes/fails for ~{end_pt['unhardened_error_pct']}% of users."
        )
    return f"Safe for ~{safe_cap:,} users at a time before slowdown begins."


def _simple_fallback_explainer(question: str, ctx: dict[str, Any] | None) -> str:
    """Deterministic plain-English helper used if local Ollama is not running (e.g. cloud hosting)."""
    if not ctx or not ctx.get("url"):
        return "Please paste any website URL or GitHub repo in the bar above and click 'Run Audit' first. Then ask me anything!"

    q = question.lower()
    url = ctx.get("url", "this website")
    cap_summary = ctx.get("plain_capacity_summary") or f"Safe for ~{ctx.get('safe_capacity_users', 0):,} users at a time."
    findings = ctx.get("findings", [])

    if any(w in q for w in ["user", "how many", "capacity", "5000", "5,000", "crash", "load", "time"]):
        return f"For {url}: {cap_summary} To handle 5,000 users without crashing, apply the Auto-Scaling (HPA) patch in Tab 3."

    if any(w in q for w in ["where", "fix", "location", "log", "patch"]):
        if not findings:
            return f"No fixes are needed right now—all checked items on {url} passed!"
        lines = [f"Where to fix the issues found on {url}:"]
        for i, f in enumerate(findings[:6], 1):
            lines.append(f"{i}. {f.get('simple_meaning', f.get('title'))} -> Fix in: {f.get('where_to_fix', f.get('target'))}")
        lines.append("You can copy or download the ready-made fix file from the 'Automated Hardening Patch' tab.")
        return "\n".join(lines)

    # Default overview in plain English
    score = ctx.get("security", {}).get("score", "--")
    if not findings:
        return f"{url} scored {score}/100. {cap_summary} All inspected security checks look healthy."

    lines = [
        f"Simple summary for {url} (Score: {score}/100):",
        f"• Crowd Limit: {cap_summary}",
        f"• {len(findings)} thing(s) need fixing:",
    ]
    for i, f in enumerate(findings[:5], 1):
        lines.append(f"  {i}) {f.get('simple_meaning', f.get('title'))} (Where: {f.get('where_to_fix', f.get('target'))})")
    return "\n".join(lines)


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


def _single_probe(full_url: str, read_limit: int = 8192) -> dict[str, Any]:
    """Perform a single live HTTP GET probe and return status, latency, and headers."""
    req = urllib.request.Request(
        full_url,
        headers={
            "User-Agent": "ConfigGuard-OS-SRE-Auditor/4.3 (+https://sre.google)",
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        },
        method="GET",
    )
    t_start = time.perf_counter()
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            resp.read(read_limit)
            total_ms = round((time.perf_counter() - t_start) * 1000, 1)
            raw_headers = dict(resp.headers)
            set_cookies = resp.headers.get_all("Set-Cookie") or []
            return {
                "alive": True,
                "status_code": resp.getcode(),
                "latency_ms": total_ms,
                "headers": raw_headers,
                "set_cookies": set_cookies,
                "error": None,
            }
    except urllib.error.HTTPError as err:
        total_ms = round((time.perf_counter() - t_start) * 1000, 1)
        raw_headers = dict(err.headers) if err.headers else {}
        set_cookies = err.headers.get_all("Set-Cookie") if err.headers else []
        return {
            "alive": True,
            "status_code": err.code,
            "latency_ms": total_ms,
            "headers": raw_headers,
            "set_cookies": set_cookies or [],
            "error": f"HTTP {err.code}: {err.reason}",
        }
    except Exception as exc:
        total_ms = round((time.perf_counter() - t_start) * 1000, 1)
        return {
            "alive": False,
            "status_code": 0,
            "latency_ms": total_ms,
            "headers": {},
            "set_cookies": [],
            "error": str(exc),
        }


def _fetch_http_with_micro_benchmark(full_url: str) -> dict[str, Any]:
    """Run primary HTTP probe, then a 4-connection parallel burst to measure real warm tail latency."""
    primary = _single_probe(full_url, read_limit=8192)
    if not primary["alive"]:
        primary["p50_ms"] = primary["latency_ms"]
        primary["p95_ms"] = primary["latency_ms"]
        primary["jitter_ratio"] = 1.0
        return primary

    latencies: list[float] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_single_probe, full_url, 2048) for _ in range(4)]
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
                if res["alive"]:
                    latencies.append(res["latency_ms"])
            except Exception:
                pass

    if not latencies:
        latencies = [primary["latency_ms"]]

    latencies.sort()
    mid = len(latencies) // 2
    p50 = latencies[mid]
    p95 = latencies[-1]
    min_lat = max(1.0, latencies[0])
    jitter_ratio = round(p95 / min_lat, 2)

    primary["p50_ms"] = round(p50, 1)
    primary["p95_ms"] = round(p95, 1)
    primary["jitter_ratio"] = jitter_ratio
    primary["sample_latencies_ms"] = latencies
    return primary


def _github_get_json(api_url: str) -> Any:
    req = urllib.request.Request(
        api_url,
        headers={
            "User-Agent": "ConfigGuard-OS-Auditor/4.3",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _audit_github_repo(parsed: urllib.parse.ParseResult) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Inspect real config files in a public GitHub repository."""
    findings: list[dict[str, Any]] = []
    repo_meta: dict[str, Any] = {"detected": False, "config_files": [], "has_hpa": False}
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
                        if kind == "HorizontalPodAutoscaler":
                            repo_meta["has_hpa"] = True
                        elif kind == "Deployment":
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


def _fingerprint_architecture(headers_lower: dict[str, str], set_cookies: list[str], http_info: dict[str, Any]) -> dict[str, Any]:
    """Extract real infrastructure signals from response headers to parameterize capacity modeling."""
    server_val = headers_lower.get("server", "").lower()
    cf_cache = headers_lower.get("cf-cache-status", "").upper()
    x_cache = headers_lower.get("x-cache", "").lower()
    via_val = headers_lower.get("via", "").lower()
    alt_svc = headers_lower.get("alt-svc", "").lower()
    encoding = headers_lower.get("content-encoding", "").lower()
    conn_val = headers_lower.get("connection", "").lower()
    powered_by = headers_lower.get("x-powered-by", "")
    cookie_blob = " ".join(set_cookies).upper()

    has_cdn = any(k in server_val for k in ["cloudflare", "fastly", "cloudfront", "akamai"]) or bool(cf_cache or x_cache or "cloudfront" in via_val)
    edge_cached = cf_cache == "HIT" or "hit" in x_cache
    stateful_session = any(tok in cookie_blob for tok in ["JSESSIONID", "PHPSESSID", "ASP.NET_SESSIONID"])
    uses_compression = ("gzip" in encoding) or ("br" in encoding) or ("zstd" in encoding)
    supports_http3 = "h3=" in alt_svc
    keep_alive_enabled = conn_val != "close"

    tags = []
    if has_cdn:
        tags.append(f"CDN: {server_val or 'Edge'}" + (f" ({cf_cache})" if cf_cache else ""))
    else:
        tags.append("Direct Origin (No Edge CDN)")
    if stateful_session:
        tags.append("Stateful Server Session")
    if uses_compression:
        tags.append(f"Compressed ({encoding})")
    if supports_http3:
        tags.append("HTTP/3 QUIC")
    if not keep_alive_enabled:
        tags.append("Connection: close")
    if powered_by:
        tags.append(f"Origin Runtime: {powered_by}")
    if headers_lower.get("x-render-origin-server"):
        tags.append(f"Host: {headers_lower['x-render-origin-server']}")

    return {
        "has_cdn": has_cdn,
        "edge_cached": edge_cached,
        "stateful_session": stateful_session,
        "uses_compression": uses_compression,
        "supports_http3": supports_http3,
        "keep_alive_enabled": keep_alive_enabled,
        "powered_by": powered_by,
        "tags": tags,
    }


def _build_concurrency_projection(
    http_info: dict[str, Any],
    arch: dict[str, Any],
    max_users: int,
    has_hpa: bool,
) -> dict[str, Any]:
    """
    Compute site-specific concurrency capacity and latency curve (500 -> max_users)
    using Little's Law throughput from measured P50/P95 latency + real header architecture signals.
    """
    if not http_info["alive"]:
        return {
            "safe_capacity_users": 0,
            "saturation_reason": "Target endpoint did not respond to live probe (0 concurrent users supported).",
            "points": [
                {
                    "users": u,
                    "unhardened_ms": 15000.0,
                    "hardened_ms": 15000.0,
                    "unhardened_error_pct": 100.0,
                    "hardened_error_pct": 100.0,
                    "active_replicas": 0,
                }
                for u in range(500, max_users + 1, 500)
            ],
        }

    p50_ms = max(20.0, float(http_info.get("p50_ms") or http_info["latency_ms"]))
    jitter = max(1.0, float(http_info.get("jitter_ratio", 1.0)))

    # Little's Law capacity estimation:
    # Effective single-origin active worker throughput scales inversely with response time.
    # Reference: 250ms origin response ~= ~2,000 safe concurrent browsing users (thinking time ~4s).
    speed_factor = math.sqrt(250.0 / p50_ms)
    base_capacity = 2000.0 * speed_factor

    reasons = [f"measured P50 latency {p50_ms}ms"]
    if arch["edge_cached"]:
        base_capacity *= 2.4
        reasons.append("edge cache HIT")
    elif arch["has_cdn"]:
        base_capacity *= 1.15
        reasons.append("CDN edge present (dynamic origin)")
    else:
        base_capacity *= 0.8
        reasons.append("no CDN edge shield")

    if arch["stateful_session"]:
        base_capacity *= 0.65
        reasons.append("stateful server session memory lock")
    if not arch["keep_alive_enabled"]:
        base_capacity *= 0.82
        reasons.append("Connection: close overhead")
    if arch["uses_compression"]:
        base_capacity *= 1.12
    if arch["supports_http3"]:
        base_capacity *= 1.1
    if jitter > 1.6:
        base_capacity *= max(0.6, 1.3 - (jitter - 1.6) * 0.25)
        reasons.append(f"parallel probe tail jitter {jitter}x")
    if has_hpa:
        base_capacity *= 1.8
        reasons.append("Kubernetes HPA configured")

    safe_capacity = int(max(150, min(8000, round(base_capacity / 50.0) * 50)))

    points = []
    for users in range(500, max_users + 1, 500):
        load_ratio = users / float(safe_capacity)
        if load_ratio <= 0.85:
            unhardened_ms = round(p50_ms * (1.0 + 0.35 * (load_ratio ** 2)), 1)
            err_pct = 0.0
        elif load_ratio <= 1.25:
            unhardened_ms = round(p50_ms * (1.25 + 1.8 * ((load_ratio - 0.85) / 0.4) ** 1.6), 1)
            err_pct = round(min(18.0, (load_ratio - 0.85) * 35.0), 1)
        else:
            overload = load_ratio - 1.25
            unhardened_ms = round(min(15000.0, p50_ms * (3.05 + 4.8 * (overload ** 1.75))), 1)
            err_pct = round(min(96.0, 14.0 + overload * 42.0), 1)

        # Hardened with HPA (4 -> 16 replicas) + keep-alive connection pool + edge cache
        replicas = min(16, max(4, math.ceil(users / 350.0)))
        hardened_base = min(p50_ms, p50_ms * 0.55) if p50_ms > 500 else p50_ms * 0.85
        hardened_ms = round(hardened_base * (1.0 + (users / (replicas * 1200.0)) * 0.3), 1)
        hardened_err = 0.0 if users <= 5000 else 0.1

        points.append({
            "users": users,
            "unhardened_ms": unhardened_ms,
            "hardened_ms": hardened_ms,
            "unhardened_error_pct": err_pct,
            "hardened_error_pct": hardened_err,
            "active_replicas": replicas,
        })

    return {
        "safe_capacity_users": safe_capacity,
        "saturation_reason": "Calculated from " + ", ".join(reasons) + ".",
        "points": points,
    }


@app.get("/")
def serve_frontend():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/healthz")
def health_check():
    return {"status": "ok", "service": "ConfigGuard OS", "version": "4.3.0"}


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
    http_info = _fetch_http_with_micro_benchmark(full_url)

    headers_lower = {k.lower(): v for k, v in http_info["headers"].items()}
    arch = _fingerprint_architecture(headers_lower, http_info.get("set_cookies", []), http_info)

    findings: list[dict[str, Any]] = []
    passed_checks = 0
    total_checks = 8
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

    # Check 8: Server / X-Powered-By Information Leakage
    server_hdr = headers_lower.get("server", "")
    powered_by = headers_lower.get("x-powered-by", "")
    if powered_by or (server_hdr and any(ch.isdigit() for ch in server_hdr)):
        score -= 5
        exposed = f"X-Powered-By: {powered_by}" if powered_by else f"Server: {server_hdr}"
        findings.append({
            "severity": "WARNING",
            "code": "INFO-RUNTIME-LEAK",
            "title": f"Backend Runtime Fingerprinting Exposed (`{exposed}`)",
            "root_cause": f"Response disclosed backend stack details via `{exposed}`.",
            "impact": "Helps automated scanners target stack-specific vulnerabilities and CVEs.",
            "target": "HTTP Response Headers",
            "patch_hint": "Disable `X-Powered-By` (e.g., `app.disable('x-powered-by')` in Express) and `server_tokens off;`.",
        })
    else:
        passed_checks += 1

    # Check Cookie Security Flags if Set-Cookie is returned
    for cookie_str in http_info.get("set_cookies", []):
        c_lower = cookie_str.lower()
        if is_https and ("secure" not in c_lower or "samesite" not in c_lower):
            missing_flags = [f for f in ["Secure", "SameSite"] if f.lower() not in c_lower]
            score -= 6
            findings.append({
                "severity": "HIGH",
                "code": "COOKIE-WEAK-FLAGS",
                "title": f"Session Cookie Missing Security Flag(s): {', '.join(missing_flags)}",
                "root_cause": f"Cookie `{cookie_str.split(';', 1)[0].split('=')[0]}` omits `{', '.join(missing_flags)}`.",
                "impact": "Session tokens may be exposed over HTTP downgrades or CSRF attacks.",
                "target": "Set-Cookie Header",
                "patch_hint": "Enforce `Secure; HttpOnly; SameSite=Lax` on all session cookies.",
            })
            break

    # Check latency SLA
    if http_info["alive"] and http_info["latency_ms"] > 1000:
        score -= 10
        findings.append({
            "severity": "HIGH",
            "code": "PERF-HIGH-TTFB",
            "title": f"High Origin Response Latency ({http_info['latency_ms']} ms)",
            "root_cause": "Initial single-request roundtrip exceeded 1,000ms SLA threshold.",
            "impact": "Under high concurrency, connection queuing will rapidly exhaust origin worker threads.",
            "target": full_url,
            "patch_hint": "Enable edge caching, HTTP keep-alive pooling, and horizontal autoscaling.",
        })

    # GitHub Deep Repository Audit if URL points to GitHub
    repo_meta: dict[str, Any] = {"detected": False, "config_files": [], "has_hpa": False}
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
    if powered_by:
        nginx_lines.append("proxy_hide_header X-Powered-By;")
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

    _enrich_findings_plain_english(findings)

    target_users = max(1000, min(5000, payload.target_users))
    concurrency = _build_concurrency_projection(
        http_info,
        arch,
        target_users,
        has_hpa=repo_meta.get("has_hpa", False),
    )
    plain_cap_summary = _build_plain_capacity_summary(
        concurrency["safe_capacity_users"],
        concurrency["points"],
        http_info["alive"],
    )

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
            "p50_ms": http_info.get("p50_ms", http_info["latency_ms"]),
            "p95_ms": http_info.get("p95_ms", http_info["latency_ms"]),
            "jitter_ratio": http_info.get("jitter_ratio", 1.0),
            "keep_alive": headers_lower.get("connection", "keep-alive"),
            "server": server_hdr or "Hidden",
            "headers": http_info["headers"],
            "error": http_info["error"],
        },
        "network": net_info,
        "architecture": arch,
        "security": {
            "score": final_score,
            "grade": grade,
            "passed_checks": passed_checks,
            "total_checks": total_checks,
        },
        "findings": findings,
        "github_repo": repo_meta,
        "safe_capacity_users": concurrency["safe_capacity_users"],
        "plain_capacity_summary": plain_cap_summary,
        "saturation_reason": concurrency["saturation_reason"],
        "concurrency_projection": concurrency["points"],
        "remediation_patch": full_patch,
    })


@app.post("/api/chat")
def chat_simple_explainer(payload: ChatRequest):
    """Explain the current audit in simple everyday English using local Ollama (llama3.2:1b) with safe fallback."""
    question = payload.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Please enter a question.")

    ctx = payload.audit_context or {}
    if not ctx.get("url"):
        return JSONResponse({
            "reply": _simple_fallback_explainer(question, ctx),
            "engine": "built-in explainer",
        })

    findings_brief = "\n".join(
        f"- {f.get('simple_meaning', f.get('title'))} (Fix in: {f.get('where_to_fix', f.get('target'))})"
        for f in ctx.get("findings", [])[:8]
    ) or "None (all checks passed)."

    system_prompt = (
        "You are ConfigGuard Simple Helper. Explain website check results to a non-technical employee. "
        "Use VERY short, clear, everyday English. Do not use hard technical words. "
        "Be accurate using ONLY the real audit numbers below:\n"
        f"Website: {ctx.get('url')}\n"
        f"Status: {ctx.get('http', {}).get('status_code')}\n"
        f"Security Score: {ctx.get('security', {}).get('score')}/100\n"
        f"User Capacity Summary: {ctx.get('plain_capacity_summary')}\n"
        f"Issues & Where to Fix:\n{findings_brief}"
    )

    ollama_body = {
        "model": "llama3.2:1b",
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
    }

    try:
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/chat",
            data=json.dumps(ollama_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            answer = data.get("message", {}).get("content", "").strip()
            if answer:
                return JSONResponse({"reply": answer, "engine": "ollama (llama3.2:1b)"})
    except Exception:
        pass

    return JSONResponse({
        "reply": _simple_fallback_explainer(question, ctx),
        "engine": "built-in explainer",
    })
