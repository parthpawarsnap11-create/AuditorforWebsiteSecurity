from typing import Dict, Any, List
from http.cookies import SimpleCookie

def scan_cookies(raw_cookie_headers: List[str]) -> List[Dict[str, Any]]:
    findings = []
    if not raw_cookie_headers:
        findings.append({
            "category": "Cookie Hygiene",
            "title": "No Set-Cookie Headers Emitted on Baseline Request",
            "severity": "LOW",
            "status": "INFO",
            "description": "The target did not return any cookies during the initial response handshake.",
            "impact": "No immediate session or tracking cookie vulnerabilities detected on this baseline endpoint.",
            "technical_evidence": "No 'Set-Cookie' header present.",
            "remediation": "When configuring authentication cookies in future routes, always specify Secure, HttpOnly, and SameSite.",
            "cwe_owasp": "RFC 6265bis Cookie Specification"
        })
        return findings

    for raw in raw_cookie_headers:
        cookie_obj = SimpleCookie()
        try:
            cookie_obj.load(raw)
        except Exception:
            pass

        raw_lower = raw.lower()
        parts = [p.strip() for p in raw.split(";")]
        cookie_name = parts[0].split("=")[0] if parts else "Unknown"

        is_secure = "secure" in raw_lower
        is_httponly = "httponly" in raw_lower
        has_samesite = "samesite" in raw_lower
        samesite_mode = "None"

        for p in parts[1:]:
            if "samesite=" in p.lower():
                samesite_mode = p.split("=")[1].strip()

        # 1. Missing Secure Flag
        if not is_secure:
            findings.append({
                "category": "Cookie Hygiene",
                "title": f"Insecure Cookie: Missing 'Secure' Flag ({cookie_name})",
                "severity": "HIGH",
                "status": "FAILED",
                "description": f"Cookie '{cookie_name}' does not include the 'Secure' directive. Browsers will transmit this cookie over unencrypted HTTP channels.",
                "impact": "Attackers can intercept sensitive session identifiers or authentication tokens via plaintext HTTP sniffing on unencrypted networks.",
                "technical_evidence": f"Raw Set-Cookie: {raw}",
                "remediation": f"Append '; Secure' to the Set-Cookie directive for '{cookie_name}'.",
                "cwe_owasp": "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | OWASP A05:2021"
            })
        else:
            findings.append({
                "category": "Cookie Hygiene",
                "title": f"Cookie 'Secure' Attribute Enforced ({cookie_name})",
                "severity": "LOW",
                "status": "PASSED",
                "description": f"Cookie '{cookie_name}' is restricted to encrypted HTTPS transport.",
                "impact": "Protects authentication cookies from cleartext transmission.",
                "technical_evidence": f"Cookie: {cookie_name} | Secure: Yes",
                "remediation": "Maintain Secure flag on all application cookies.",
                "cwe_owasp": "RFC 6265bis Section 5.5.1"
            })

        # 2. Missing HttpOnly Flag
        if not is_httponly:
            findings.append({
                "category": "Cookie Hygiene",
                "title": f"Missing 'HttpOnly' Attribute ({cookie_name})",
                "severity": "MEDIUM",
                "status": "FAILED",
                "description": f"Cookie '{cookie_name}' is accessible to JavaScript running within the browser (via document.cookie).",
                "impact": "If an XSS vulnerability exists anywhere on the site, malicious JavaScript can read and exfiltrate this cookie to hijack user sessions.",
                "technical_evidence": f"Raw Set-Cookie: {raw}",
                "remediation": f"Append '; HttpOnly' to the Set-Cookie header for '{cookie_name}'.",
                "cwe_owasp": "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag | OWASP A07:2021-Identification and Authentication Failures"
            })
        else:
            findings.append({
                "category": "Cookie Hygiene",
                "title": f"Cookie 'HttpOnly' Protection Active ({cookie_name})",
                "severity": "LOW",
                "status": "PASSED",
                "description": f"Cookie '{cookie_name}' cannot be accessed via client-side JavaScript.",
                "impact": "Mitigates credential theft during XSS injection attacks.",
                "technical_evidence": f"Cookie: {cookie_name} | HttpOnly: Yes",
                "remediation": "Continue enforcing HttpOnly on sensitive session identifiers.",
                "cwe_owasp": "OWASP Session Management Cheat Sheet"
            })

        # 3. SameSite Attribute
        if not has_samesite:
            findings.append({
                "category": "Cookie Hygiene",
                "title": f"Missing 'SameSite' Attribute ({cookie_name})",
                "severity": "MEDIUM",
                "status": "FAILED",
                "description": f"Cookie '{cookie_name}' lacks an explicit SameSite attribute, defaulting to browser-specific behavior.",
                "impact": "Cross-Site Request Forgery (CSRF) vulnerabilities may allow external sites to perform unauthorized authenticated requests on behalf of the user.",
                "technical_evidence": f"Raw Set-Cookie: {raw}",
                "remediation": f"Set '; SameSite=Lax' (recommended for navigation) or '; SameSite=Strict' on '{cookie_name}'.",
                "cwe_owasp": "CWE-1275: Sensitive Cookie with Improper SameSite Attribute | OWASP A01:2021-Broken Access Control"
            })
        else:
            findings.append({
                "category": "Cookie Hygiene",
                "title": f"Cookie SameSite Configured ({cookie_name} -> {samesite_mode})",
                "severity": "LOW",
                "status": "PASSED",
                "description": f"Cookie '{cookie_name}' controls cross-site transmission with SameSite={samesite_mode}.",
                "impact": "Significantly decreases susceptibility to CSRF attacks.",
                "technical_evidence": f"SameSite Mode: {samesite_mode}",
                "remediation": "Maintain appropriate SameSite isolation according to API integration requirements.",
                "cwe_owasp": "RFC 6265bis Section 5.3.7"
            })

        # 4. Cookie Prefix hygiene (__Host- and __Secure-)
        if is_secure and is_httponly:
            if cookie_name.startswith("__Host-"):
                findings.append({
                    "category": "Cookie Hygiene",
                    "title": f"Hardened Cookie Prefix Deployed ({cookie_name})",
                    "severity": "LOW",
                    "status": "PASSED",
                    "description": "Cookie uses the '__Host-' prefix, enforcing path='/', domain isolation, and HTTPS transport.",
                    "impact": "Blocks cookie-tossing attacks from untrusted subdomains.",
                    "technical_evidence": f"Prefix: __Host- confirmed on {cookie_name}",
                    "remediation": "Gold standard for sensitive session cookies.",
                    "cwe_owasp": "W3C Cookie Prefixes"
                })

    return findings
