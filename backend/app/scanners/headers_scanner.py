from typing import Dict, Any, List

def scan_security_headers(headers: Dict[str, str], is_https: bool = True) -> List[Dict[str, Any]]:
    findings = []
    # Normalize headers to lowercase for reliable matching
    h = {k.lower(): v for k, v in headers.items()}

    # 1. Strict-Transport-Security (HSTS)
    hsts = h.get("strict-transport-security")
    if not hsts:
        findings.append({
            "category": "HTTP Security Headers",
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "severity": "HIGH",
            "status": "FAILED",
            "description": "The HTTP Strict-Transport-Security response header informs browsers that the site should only ever be accessed using HTTPS.",
            "impact": "Vulnerable to SSL-stripping attacks and man-in-the-middle protocol downgrade when users enter 'domain.com' without the 'https://' prefix.",
            "technical_evidence": "Header 'Strict-Transport-Security' not present in HTTP response.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
            "cwe_owasp": "CWE-523: Unprotected Transport | OWASP A05:2021-Security Misconfiguration"
        })
    else:
        # Check max-age value
        max_age = 0
        for part in hsts.split(";"):
            if "max-age=" in part.lower():
                try:
                    max_age = int(part.lower().split("max-age=")[1].strip())
                except Exception:
                    pass
        if max_age < 15552000:  # < 180 days
            findings.append({
                "category": "HTTP Security Headers",
                "title": "HSTS max-age Duration Insufficient",
                "severity": "MEDIUM",
                "status": "WARNING",
                "description": f"HSTS max-age is set to {max_age} seconds, which is less than the recommended minimum of 6 months (15552000s).",
                "impact": "Browser HTTPS enforcement expires too quickly, increasing the window for opportunistic SSL stripping attacks.",
                "technical_evidence": f"Strict-Transport-Security: {hsts}",
                "remediation": "Increase HSTS max-age to at least 31536000 seconds (1 year) and append 'includeSubDomains'.",
                "cwe_owasp": "CWE-523: Unprotected Transport"
            })
        else:
            findings.append({
                "category": "HTTP Security Headers",
                "title": "Strict-Transport-Security (HSTS) Properly Configured",
                "severity": "LOW",
                "status": "PASSED",
                "description": f"Robust HSTS directive deployed ({hsts}).",
                "impact": "Browsers strictly refuse plaintext HTTP connections and mitigate protocol downgrade.",
                "technical_evidence": f"Strict-Transport-Security: {hsts}",
                "remediation": "Maintain HSTS and verify HSTS preload list eligibility at hstspreload.org.",
                "cwe_owasp": "RFC 6797 HSTS Standard"
            })

    # 2. Content-Security-Policy (CSP)
    csp = h.get("content-security-policy")
    if not csp:
        findings.append({
            "category": "HTTP Security Headers",
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "HIGH",
            "status": "FAILED",
            "description": "Content Security Policy (CSP) is a foundational defense-in-depth standard that restricts which scripts, styles, frames, and images can execute.",
            "impact": "Greatly increases susceptibility to Cross-Site Scripting (XSS), data exfiltration, clickjacking, and unauthorized third-party script injection.",
            "technical_evidence": "Header 'Content-Security-Policy' not present in response headers.",
            "remediation": "Implement a strict CSP. Example: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
            "cwe_owasp": "CWE-79: Improper Neutralization of Input During Web Page Generation | OWASP A03:2021-Injection"
        })
    else:
        # Deep inspection of CSP keywords
        csp_lower = csp.lower()
        has_unsafe_inline = "'unsafe-inline'" in csp_lower
        has_unsafe_eval = "'unsafe-eval'" in csp_lower
        if has_unsafe_inline or has_unsafe_eval:
            findings.append({
                "category": "HTTP Security Headers",
                "title": "Weak Content-Security-Policy Directives ('unsafe' keywords)",
                "severity": "MEDIUM",
                "status": "WARNING",
                "description": f"CSP contains {'unsafe-inline ' if has_unsafe_inline else ''}{'unsafe-eval' if has_unsafe_eval else ''}, weakening XSS protection.",
                "impact": "Attackers can bypass script restrictions if user-controlled input can be injected into HTML contexts.",
                "technical_evidence": f"Content-Security-Policy: {csp}",
                "remediation": "Replace 'unsafe-inline' with cryptographic nonces (nonce-...) or SHA-256 hashes.",
                "cwe_owasp": "CWE-1021: Improper Restriction of Rendered UI Layers"
            })
        else:
            findings.append({
                "category": "HTTP Security Headers",
                "title": "Content-Security-Policy (CSP) Active",
                "severity": "LOW",
                "status": "PASSED",
                "description": "CSP header is present without obvious unsafe directives.",
                "impact": "Reduces attack surface against reflected and stored XSS vulnerabilities.",
                "technical_evidence": f"Content-Security-Policy: {csp[:80]}...",
                "remediation": "Periodically audit CSP policies using Google CSP Evaluator.",
                "cwe_owasp": "W3C CSP Level 3"
            })

    # 3. X-Frame-Options (Clickjacking)
    xfo = h.get("x-frame-options")
    if not xfo:
        findings.append({
            "category": "HTTP Security Headers",
            "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
            "severity": "MEDIUM",
            "status": "FAILED",
            "description": "The X-Frame-Options header indicates whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>.",
            "impact": "Attackers can embed this website within an invisible iframe on a malicious domain, tricking authenticated users into clicking buttons (UI Redressing/Clickjacking).",
            "technical_evidence": "Header 'X-Frame-Options' missing from response.",
            "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors'.",
            "cwe_owasp": "CWE-1021: Restriction of Rendered UI Layers | OWASP A05:2021"
        })
    else:
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            findings.append({
                "category": "HTTP Security Headers",
                "title": "X-Frame-Options Clickjacking Defense Active",
                "severity": "LOW",
                "status": "PASSED",
                "description": f"Page enforces clickjacking mitigation via X-Frame-Options: {xfo}.",
                "impact": "Third-party domains are forbidden from embedding this application in iframes.",
                "technical_evidence": f"X-Frame-Options: {xfo}",
                "remediation": "Ensure frame-ancestors directive in CSP is also aligned for modern browser parity.",
                "cwe_owasp": "RFC 7034 Standard"
            })
        else:
            findings.append({
                "category": "HTTP Security Headers",
                "title": "Non-Standard X-Frame-Options Value",
                "severity": "LOW",
                "status": "WARNING",
                "description": f"Unexpected value for X-Frame-Options: '{xfo}'.",
                "impact": "Some browsers may disregard invalid directives, leaving pages susceptible to framing.",
                "technical_evidence": f"X-Frame-Options: {xfo}",
                "remediation": "Use standard values: 'DENY' or 'SAMEORIGIN'.",
                "cwe_owasp": "CWE-1021: Restriction of Rendered UI Layers"
            })

    # 4. X-Content-Type-Options (MIME Sniffing)
    xcto = h.get("x-content-type-options")
    if not xcto or xcto.lower() != "nosniff":
        findings.append({
            "category": "HTTP Security Headers",
            "title": "Missing X-Content-Type-Options Header",
            "severity": "LOW",
            "status": "FAILED",
            "description": "The X-Content-Type-Options: nosniff header prevents browsers from MIME-type sniffing a response away from the declared content-type.",
            "impact": "Browsers may treat non-executable MIME types (e.g. image/png or text/plain) as executable JavaScript, facilitating cross-site script execution.",
            "technical_evidence": f"Current value: {xcto if xcto else 'Not Set'}",
            "remediation": "Configure web server to return 'X-Content-Type-Options: nosniff'.",
            "cwe_owasp": "CWE-79: Cross-Site Scripting | OWASP A05:2021"
        })
    else:
        findings.append({
            "category": "HTTP Security Headers",
            "title": "X-Content-Type-Options 'nosniff' Configured",
            "severity": "LOW",
            "status": "PASSED",
            "description": "MIME-sniffing protection is strictly enabled.",
            "impact": "Browser respects authoritative Content-Type headers, blocking MIME-confusion attacks.",
            "technical_evidence": "X-Content-Type-Options: nosniff",
            "remediation": "Ensure all static assets deliver appropriate Content-Type definitions.",
            "cwe_owasp": "Fetch Living Standard"
        })

    # 5. Referrer-Policy
    ref = h.get("referrer-policy")
    if not ref:
        findings.append({
            "category": "HTTP Security Headers",
            "title": "Missing Referrer-Policy Header",
            "severity": "LOW",
            "status": "FAILED",
            "description": "The Referrer-Policy HTTP header controls how much referrer information (URL path and query parameters) is included with requests.",
            "impact": "Sensitive user IDs, tokens, or private URL query parameters may leak to external third-party sites in HTTP Referer headers.",
            "technical_evidence": "Header 'Referrer-Policy' missing from response.",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            "cwe_owasp": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        })
    else:
        findings.append({
            "category": "HTTP Security Headers",
            "title": f"Referrer-Policy Configured ({ref})",
            "severity": "LOW",
            "status": "PASSED",
            "description": f"Target controls referrer leakage using '{ref}'.",
            "impact": "Limits exposure of internal routing paths and query parameters to external origins.",
            "technical_evidence": f"Referrer-Policy: {ref}",
            "remediation": "Ensure policies remain strict across all subdomains.",
            "cwe_owasp": "W3C Referrer Policy Specification"
        })

    # 6. Permissions-Policy (Feature-Policy)
    perm = h.get("permissions-policy") or h.get("feature-policy")
    if not perm:
        findings.append({
            "category": "HTTP Security Headers",
            "title": "Missing Permissions-Policy Header",
            "severity": "LOW",
            "status": "FAILED",
            "description": "Permissions-Policy allows developers to selectively enable, disable, and modify browser features and APIs (geolocation, microphone, camera, payment).",
            "impact": "Embedded iframes or third-party scripts may attempt unauthorized hardware or sensor API invocations.",
            "technical_evidence": "Header 'Permissions-Policy' not found in response.",
            "remediation": "Define Permissions-Policy, e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "cwe_owasp": "W3C Permissions Policy Standard"
        })
    else:
        findings.append({
            "category": "HTTP Security Headers",
            "title": "Permissions-Policy Active",
            "severity": "LOW",
            "status": "PASSED",
            "description": "Browser feature access restrictions are declared.",
            "impact": "Controls sensitive client hardware APIs (camera, microphone, geolocation).",
            "technical_evidence": f"Permissions-Policy: {perm[:60]}...",
            "remediation": "Audit policy regularly to ensure newly introduced browser features are locked down.",
            "cwe_owasp": "W3C Permissions Policy"
        })

    # 7. Cross-Origin-Opener-Policy (COOP) & Cross-Origin-Embedder-Policy (COEP)
    coop = h.get("cross-origin-opener-policy")
    if coop and coop.lower() in ("same-origin", "same-origin-allow-popups"):
        findings.append({
            "category": "HTTP Security Headers",
            "title": f"Cross-Origin-Opener-Policy (COOP) Enabled ({coop})",
            "severity": "LOW",
            "status": "PASSED",
            "description": "Process-level origin isolation prevents cross-origin window attacks and Spectre timing side-channels.",
            "impact": "Mitigates cross-window attacks (XS-Leaks) and isolates browse context.",
            "technical_evidence": f"Cross-Origin-Opener-Policy: {coop}",
            "remediation": "Retain COOP for high-security web applications.",
            "cwe_owasp": "HTML Living Standard - Cross-Origin Opener Policy"
        })

    return findings
