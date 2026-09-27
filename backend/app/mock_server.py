from fastapi import APIRouter, Response
from fastapi.responses import HTMLResponse

mock_router = APIRouter(prefix="/mock", tags=["Mock Test Bench"])

@mock_router.get("/hardened", response_class=HTMLResponse)
async def mock_hardened_endpoint(response: Response):
    # Perfect security hardening headers (Grade A+)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Access-Control-Allow-Origin"] = "https://authorized-partner.com"
    
    # Secure Cookie
    response.headers.append("Set-Cookie", "__Host-AuthToken=cyber_sec_token_99812; Secure; HttpOnly; SameSite=Strict; Path=/")
    
    return """<!DOCTYPE html>
<html>
<head><title>CyberSentinel Hardened Benchmark</title></head>
<body style="font-family:sans-serif;background:#0d1117;color:#38bdf8;padding:2rem;">
    <h1>[SAFE MOCK] Hardened Web Benchmark</h1>
    <p>This endpoint delivers a fully compliant defensive security posture (HSTS, CSP, XFO, XCTO, Cookie Flags).</p>
</body>
</html>"""

@mock_router.get("/vulnerable", response_class=HTMLResponse)
async def mock_vulnerable_endpoint(response: Response):
    # Insecure configuration (Grade F)
    # Banner disclosure
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    response.headers["X-AspNet-Version"] = "4.0.30319"
    # Permissive wildcard CORS
    response.headers["Access-Control-Allow-Origin"] = "*"
    # Insecure Cookie without Secure, HttpOnly, or SameSite
    response.headers.append("Set-Cookie", "session_id=insecure_plaintext_token_8877; Path=/")
    
    # Intentionally omit HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
    return """<!DOCTYPE html>
<html>
<head><title>CyberSentinel Vulnerable Demo</title></head>
<body style="font-family:sans-serif;background:#18181b;color:#f87171;padding:2rem;">
    <h1>[SAFE MOCK] Vulnerable Configuration Benchmark</h1>
    <p>This simulated endpoint lacks modern browser security headers, leaks server banners, uses unhardened cookies, and has wildcard CORS.</p>
</body>
</html>"""

@mock_router.get("/balanced", response_class=HTMLResponse)
async def mock_balanced_endpoint(response: Response):
    # Grade B benchmark
    response.headers["Strict-Transport-Security"] = "max-age=15552000; includeSubDomains"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Server"] = "Nginx"
    response.headers.append("Set-Cookie", "auth=sample_auth_token; Secure; SameSite=Lax; Path=/")
    
    return """<!DOCTYPE html>
<html>
<head><title>CyberSentinel Balanced Benchmark</title></head>
<body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;">
    <h1>[SAFE MOCK] Balanced Configuration Benchmark</h1>
    <p>Adequate baseline configuration with minor hardening gaps (no CSP, partial cookie hygiene).</p>
</body>
</html>"""
