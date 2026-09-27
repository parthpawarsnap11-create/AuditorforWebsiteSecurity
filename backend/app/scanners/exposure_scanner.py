from typing import Dict, Any, List
from urllib.parse import urljoin
import httpx

async def scan_exposure(target_url: str, headers: Dict[str, str], client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    findings = []
    h = {k.lower(): v for k, v in headers.items()}

    # 1. Server Banner Exposure
    server = h.get("server")
    if server:
        # If running on local test runner
        if ("127.0.0.1" in target_url or "localhost" in target_url) and server.lower() == "uvicorn":
            findings.append({
                "category": "Attack Surface Recon",
                "title": "Local Test Server Environment (Uvicorn)",
                "severity": "LOW",
                "status": "PASSED",
                "description": "Target is hosted on local ASGI Uvicorn server for academic simulation.",
                "impact": "Test environment runtime.",
                "technical_evidence": f"Server: {server}",
                "remediation": "When deployed in production behind Nginx/Cloudflare, enable 'server_tokens off;'.",
                "cwe_owasp": "NIST Guidelines"
            })
        else:
            has_version = any(char.isdigit() for char in server)
            if has_version:
                findings.append({
                    "category": "Attack Surface Recon",
                    "title": f"Granular Server Version Disclosure ({server})",
                    "severity": "MEDIUM",
                    "status": "FAILED",
                    "description": f"The web server exposes its detailed brand and build version in the HTTP 'Server' header: '{server}'.",
                    "impact": "Attackers can search CVE vulnerability databases for known exploit vectors targeting this specific software release.",
                    "technical_evidence": f"Server: {server}",
                    "remediation": "Suppress version tokens in web server configuration (e.g. Nginx: 'server_tokens off;', Apache: 'ServerTokens Prod').",
                    "cwe_owasp": "CWE-200: Exposure of Sensitive Information | OWASP A05:2021-Security Misconfiguration"
                })
            else:
                findings.append({
                    "category": "Attack Surface Recon",
                    "title": f"Generic Server Header Detected ({server})",
                    "severity": "LOW",
                    "status": "WARNING",
                    "description": f"The 'Server' header is present ({server}), but detailed version numbers are concealed.",
                    "impact": "Minimal risk, but reveals underlying server technology family.",
                    "technical_evidence": f"Server: {server}",
                    "remediation": "Consider masking or completely removing the Server header if proxy layer supports it.",
                    "cwe_owasp": "CWE-200: Exposure of Sensitive Information"
                })
    else:
        findings.append({
            "category": "Attack Surface Recon",
            "title": "Server Banner Suppressed / Obfuscated",
            "severity": "LOW",
            "status": "PASSED",
            "description": "No 'Server' header is disclosed in HTTP responses.",
            "impact": "Hinders automated reconnaissance and technology stack fingerprinting.",
            "technical_evidence": "Server header omitted.",
            "remediation": "Maintain banner masking across reverse proxies and origin servers.",
            "cwe_owasp": "Defense-In-Depth Posture"
        })

    # 2. X-Powered-By & Framework Disclosures
    powered_by = h.get("x-powered-by")
    aspnet_ver = h.get("x-aspnet-version")
    if powered_by:
        findings.append({
            "category": "Attack Surface Recon",
            "title": f"Application Framework Disclosure (X-Powered-By: {powered_by})",
            "severity": "MEDIUM",
            "status": "FAILED",
            "description": f"The response reveals the underlying application engine via 'X-Powered-By: {powered_by}'.",
            "impact": "Aids threat actors in selecting targeted exploits for the backend runtime (e.g. Express, PHP, Next.js).",
            "technical_evidence": f"X-Powered-By: {powered_by}",
            "remediation": "Disable the header. In Express: 'app.disable(\"x-powered-by\")'; in PHP: 'expose_php = Off'.",
            "cwe_owasp": "CWE-200: Information Exposure | OWASP A05:2021"
        })

    if aspnet_ver:
        findings.append({
            "category": "Attack Surface Recon",
            "title": f"ASP.NET Version Disclosure (X-AspNet-Version: {aspnet_ver})",
            "severity": "MEDIUM",
            "status": "FAILED",
            "description": f"ASP.NET version '{aspnet_ver}' is revealed in response headers.",
            "impact": "Facilitates version-specific .NET framework vulnerability scanning.",
            "technical_evidence": f"X-AspNet-Version: {aspnet_ver}",
            "remediation": "Disable 'enableVersionHeader' in web.config under <httpRuntime>.",
            "cwe_owasp": "CWE-200: Information Exposure"
        })

    # 3. Passive Security Policy Discovery: security.txt
    try:
        sec_url = urljoin(target_url, "/.well-known/security.txt")
        sec_resp = await client.get(sec_url, timeout=4.0)
        if sec_resp.status_code == 200 and "contact" in sec_resp.text.lower():
            findings.append({
                "category": "Attack Surface Recon",
                "title": "Security Vulnerability Disclosure Policy Present (security.txt)",
                "severity": "LOW",
                "status": "PASSED",
                "description": "Target publishes an RFC 9116 compliant security.txt file for responsible vulnerability disclosure.",
                "impact": "Empowers ethical security researchers to report discovered flaws to the security team safely.",
                "technical_evidence": f"Located at: {sec_url}",
                "remediation": "Keep contact information and PGP keys updated.",
                "cwe_owasp": "RFC 9116 Standard"
            })
    except Exception:
        pass

    return findings
