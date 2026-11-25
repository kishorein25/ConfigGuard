"""Unit tests for ConfigGuard OS backend logic and FastAPI endpoints."""

from fastapi.testclient import TestClient

import server

client = TestClient(server.app)


def test_healthz_and_home():
    home_res = client.get("/")
    assert home_res.status_code == 200
    assert "ConfigGuard OS" in home_res.text

    health_res = client.get("/healthz")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "ok"


def test_audit_rejects_empty_url():
    res = client.post("/api/audit", json={"url": "   "})
    assert res.status_code == 400


def test_architecture_fingerprint_detects_stateful_cdn_and_compression():
    headers = {
        "server": "cloudflare",
        "cf-cache-status": "DYNAMIC",
        "content-encoding": "gzip",
        "connection": "close",
        "alt-svc": 'h3=":443"; ma=86400',
        "x-powered-by": "Express",
    }
    arch = server._fingerprint_architecture(
        headers,
        ["JSESSIONID=ABC123; Path=/; HttpOnly"],
        {"latency_ms": 500.0},
    )
    assert arch["has_cdn"] is True
    assert arch["edge_cached"] is False
    assert arch["stateful_session"] is True
    assert arch["uses_compression"] is True
    assert arch["supports_http3"] is True
    assert arch["keep_alive_enabled"] is False
    assert arch["powered_by"] == "Express"


def test_concurrency_projection_differs_between_fast_cached_and_slow_stateful_sites():
    fast_cached = server._build_concurrency_projection(
        {"alive": True, "latency_ms": 120.0, "p50_ms": 120.0, "jitter_ratio": 1.1},
        {
            "has_cdn": True,
            "edge_cached": True,
            "stateful_session": False,
            "uses_compression": True,
            "supports_http3": True,
            "keep_alive_enabled": True,
        },
        max_users=5000,
        has_hpa=False,
    )
    slow_stateful = server._build_concurrency_projection(
        {"alive": True, "latency_ms": 1650.0, "p50_ms": 1650.0, "jitter_ratio": 1.8},
        {
            "has_cdn": True,
            "edge_cached": False,
            "stateful_session": True,
            "uses_compression": True,
            "supports_http3": True,
            "keep_alive_enabled": False,
        },
        max_users=5000,
        has_hpa=False,
    )

    assert fast_cached["safe_capacity_users"] > slow_stateful["safe_capacity_users"]
    # At 2,000 users, slow stateful site should show higher projected error rate & latency
    pt_fast_2k = next(p for p in fast_cached["points"] if p["users"] == 2000)
    pt_slow_2k = next(p for p in slow_stateful["points"] if p["users"] == 2000)
    assert pt_slow_2k["unhardened_ms"] > pt_fast_2k["unhardened_ms"]
    assert pt_slow_2k["unhardened_error_pct"] > pt_fast_2k["unhardened_error_pct"]


def test_plain_english_enrichment_and_chat_endpoint():
    findings = [{"code": "HDR-NO-CSP", "title": "Missing CSP", "root_cause": "None", "target": "Headers"}]
    enriched = server._enrich_findings_plain_english(findings)
    assert "simple_meaning" in enriched[0]
    assert "where_to_fix" in enriched[0]

    chat_res = client.post(
        "/api/chat",
        json={
            "question": "How many users can use this at a time?",
            "audit_context": {
                "url": "https://example.com",
                "http": {"status_code": 200},
                "security": {"score": 60},
                "safe_capacity_users": 500,
                "plain_capacity_summary": "Safe for ~500 users at a time. At 5,000 users it crashes.",
                "findings": enriched,
            },
        },
    )
    assert chat_res.status_code == 200
    body = chat_res.json()
    assert "reply" in body and len(body["reply"]) > 10
    assert "engine" in body
