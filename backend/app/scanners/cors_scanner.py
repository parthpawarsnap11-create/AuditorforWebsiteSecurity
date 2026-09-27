from typing import Dict, Any, List
import httpx

async def scan_cors(target_url: str, base_headers: Dict[str, str], client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    findings = []
    h = {k.lower(): v for k, v in base_headers.items()}
    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials")

    # If baseline headers have CORS
    if acao:
        if acao.strip() == "*":
            findings.append({
                "category": "CORS Policy Audit",
                "title": "Permissive Wildcard Access-Control-Allow-Origin (*)",
                "severity": "MEDIUM",
                "status": "WARNING",
                "description": "The target allows any arbitrary domain on the internet to read response resources via the wildcard '*' origin.",
                "impact": "If this endpoint contains authenticated or user-specific data, malicious third-party websites can read sensitive responses via cross-origin requests.",
                "technical_evidence": f"Access-Control-Allow-Origin: {acao}",
                "remediation": "Restrict Access-Control-Allow-Origin to explicitly trusted domain origins rather than a universal wildcard.",
                "cwe_owasp": "CWE-942: Permissive Cross-Domain Policy with Untrusted Domains | OWASP A01:2021-Broken Access Control"
            })
        elif acao.lower() == "null":
            findings.append({
                "category": "CORS Policy Audit",
                "title": "Insecure 'null' Origin Permitted in CORS",
                "severity": "HIGH",
                "status": "FAILED",
                "description": "The endpoint accepts 'null' as a legitimate origin. Sandboxed iframes and local file schemas can forge null origins.",
                "impact": "Attackers can deploy sandboxed iframe exploits to bypass origin validations and extract data.",
                "technical_evidence": "Access-Control-Allow-Origin: null",
                "remediation": "Never accept 'null' in Access-Control-Allow-Origin. Specify explicit domain whitelists.",
                "cwe_owasp": "CWE-942: Permissive Cross-Domain Policy"
            })
        else:
            findings.append({
                "category": "CORS Policy Audit",
                "title": f"Explicit CORS Origin Declared ({acao})",
                "severity": "LOW",
                "status": "PASSED",
                "description": f"The target specifies an explicit origin constraint ({acao}) rather than a wildcard.",
                "impact": "Restricts cross-origin resource extraction to designated callers.",
                "technical_evidence": f"Access-Control-Allow-Origin: {acao}",
                "remediation": "Maintain strict CORS origin whitelisting.",
                "cwe_owasp": "W3C CORS Specification"
            })

    # Test pre-flight probe with arbitrary untrusted origin
    test_origin = "https://evil-untrusted-exploit.com"
    try:
        probe_resp = await client.get(
            target_url,
            headers={"Origin": test_origin},
            timeout=5.0
        )
        probe_acao = probe_resp.headers.get("access-control-allow-origin", "")
        if probe_acao == test_origin:
            is_creds = probe_resp.headers.get("access-control-allow-credentials", "").lower() == "true"
            if is_creds:
                findings.append({
                    "category": "CORS Policy Audit",
                    "title": "Critical CORS Misconfiguration: Dynamic Origin Echo with Credentials",
                    "severity": "CRITICAL",
                    "status": "FAILED",
                    "description": f"The server echoes back any untrusted Origin ('{test_origin}') combined with 'Access-Control-Allow-Credentials: true'.",
                    "impact": "Allows attackers to make authenticated requests from malicious sites and completely steal private user data.",
                    "technical_evidence": f"Echoed Origin: {probe_acao} | Allow-Credentials: true",
                    "remediation": "Validate the incoming Origin against a strict server-side whitelist before reflecting it in Access-Control-Allow-Origin.",
                    "cwe_owasp": "CWE-942: Permissive Cross-Domain Policy with Untrusted Domains | OWASP A01:2021"
                })
            else:
                findings.append({
                    "category": "CORS Policy Audit",
                    "title": "Untrusted Origin Dynamically Reflected Without Validation",
                    "severity": "HIGH",
                    "status": "FAILED",
                    "description": "The server blindly reflects the incoming 'Origin' header in its Access-Control-Allow-Origin response without checking validity.",
                    "impact": "Enables cross-origin data extraction from any malicious website.",
                    "technical_evidence": f"Reflected Origin: {probe_acao}",
                    "remediation": "Validate Origin against an approved whitelist array.",
                    "cwe_owasp": "CWE-942: Permissive Cross-Domain Policy"
                })
    except Exception:
        pass

    if not findings:
        findings.append({
            "category": "CORS Policy Audit",
            "title": "Strict Default Same-Origin Policy (No Cross-Origin Headers)",
            "severity": "LOW",
            "status": "PASSED",
            "description": "Target does not emit CORS headers on baseline requests, maintaining standard browser Same-Origin Policy isolation.",
            "impact": "Browser default SOP actively blocks other origins from reading response data.",
            "technical_evidence": "No Access-Control-Allow-Origin header returned.",
            "remediation": "Retain SOP default unless public API consumption is required.",
            "cwe_owasp": "W3C Same-Origin Policy"
        })

    return findings
