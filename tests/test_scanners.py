import pytest
from backend.app.scanners.headers_scanner import scan_security_headers
from backend.app.scanners.cookie_scanner import scan_cookies
from backend.app.scanners.tls_scanner import scan_tls
from backend.app.engine.scoring import calculate_wspi_score

def test_headers_scanner_vulnerable():
    # An empty header dict simulates an unhardened web server
    findings = scan_security_headers({})
    # Should flag missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.
    titles = [f["title"] for f in findings]
    assert any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)

def test_headers_scanner_hardened():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self';",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Cross-Origin-Opener-Policy": "same-origin"
    }
    findings = scan_security_headers(headers)
    failed = [f for f in findings if f["status"] == "FAILED"]
    assert len(failed) == 0

def test_cookie_scanner_flags_insecure_cookie():
    raw_cookies = ["session_token=secret_val_1234; Path=/"]
    findings = scan_cookies(raw_cookies)
    titles = [f["title"] for f in findings]
    assert any("Missing 'Secure' Flag" in t for t in titles)
    assert any("Missing 'HttpOnly' Attribute" in t for t in titles)
    assert any("Missing 'SameSite' Attribute" in t for t in titles)

def test_cookie_scanner_passes_hardened_cookie():
    raw_cookies = ["__Host-Auth=valid_secret; Secure; HttpOnly; SameSite=Strict; Path=/"]
    findings = scan_cookies(raw_cookies)
    failed = [f for f in findings if f["status"] == "FAILED"]
    assert len(failed) == 0

def test_wspi_scoring_algorithm():
    # Hardened set of findings
    passed_findings = [
        {"status": "PASSED", "severity": "LOW", "title": "TLS Valid"},
        {"status": "PASSED", "severity": "LOW", "title": "HSTS Active"},
        {"status": "PASSED", "severity": "LOW", "title": "CSP Active"},
        {"status": "PASSED", "severity": "LOW", "title": "Cookies Secure"},
    ]
    score, grade, counts = calculate_wspi_score(passed_findings)
    assert score == 100
    assert grade == "A+"
    assert counts["passed"] == 4
    assert counts["critical"] == 0

    # Vulnerable set of findings
    vulnerable_findings = [
        {"status": "FAILED", "severity": "CRITICAL", "title": "Plaintext HTTP"},
        {"status": "FAILED", "severity": "HIGH", "title": "Missing HSTS"},
        {"status": "FAILED", "severity": "HIGH", "title": "Missing CSP"},
        {"status": "FAILED", "severity": "MEDIUM", "title": "Missing X-Frame-Options"},
        {"status": "FAILED", "severity": "MEDIUM", "title": "Missing SameSite Cookie"},
        {"status": "FAILED", "severity": "LOW", "title": "Server Banner Disclosed"},
    ]
    # Deductions: -20 -12 -12 -6 -6 -2 = -58 => score = 42 (Grade D or F)
    score_vuln, grade_vuln, counts_vuln = calculate_wspi_score(vulnerable_findings)
    assert score_vuln == 42
    assert grade_vuln == "D"
    assert counts_vuln["critical"] == 1
    assert counts_vuln["high"] == 2
