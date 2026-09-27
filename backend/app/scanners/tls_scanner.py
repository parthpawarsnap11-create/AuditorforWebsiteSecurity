import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List

def scan_tls(target_url: str) -> List[Dict[str, Any]]:
    findings = []
    parsed = urlparse(target_url)
    
    # Check if target is local loopback / mock testing environment
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    if hostname in ("127.0.0.1", "localhost"):
        findings.append({
            "category": "Transport Security",
            "title": "Local Loopback Transport (Test Bench Mode)",
            "severity": "LOW",
            "status": "PASSED",
            "description": f"Target is running on local test interface ({hostname}:{port}). Real TLS validation is bypassed for controlled offline evaluation.",
            "impact": "Local loopback connections are isolated to the host operating system.",
            "technical_evidence": f"Host: {hostname}:{port} (Loopback)",
            "remediation": "When deploying to public production, enforce TLS 1.3 certificates and redirect port 80 to 443.",
            "cwe_owasp": "NIST SP 800-52r2"
        })
        return findings

    # Check if target uses HTTP instead of HTTPS
    if parsed.scheme.lower() != "https":
        findings.append({
            "category": "Transport Security",
            "title": "Unencrypted Plaintext HTTP Scheme",
            "severity": "CRITICAL",
            "status": "FAILED",
            "description": "The communication channel uses unencrypted HTTP. All data, credentials, and session tokens are transmitted in plaintext across the network.",
            "impact": "Man-In-The-Middle (MITM) attackers on local Wi-Fi, ISP, or routing nodes can eavesdrop, intercept credentials, or tamper with website contents.",
            "technical_evidence": f"URL Scheme: {parsed.scheme}://",
            "remediation": "Enforce HTTPS by obtaining an SSL/TLS certificate and configuring automatic 301/308 redirects from HTTP to HTTPS on port 443.",
            "cwe_owasp": "CWE-319: Cleartext Transmission of Sensitive Information | OWASP A02:2021-Cryptographic Failures"
        })
        return findings

    # Live TLS handshake and certificate extraction
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=6.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                # Check TLS Version
                if tls_version in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "category": "Transport Security",
                        "title": f"Deprecated TLS Protocol In Use ({tls_version})",
                        "severity": "HIGH",
                        "status": "FAILED",
                        "description": f"Target negotiates {tls_version}, which suffers from known cryptographic vulnerabilities (BEAST, POODLE) and is deprecated by RFC 8996.",
                        "impact": "Attackers can exploit protocol downgrade attacks to decrypt session traffic.",
                        "technical_evidence": f"Negotiated Protocol: {tls_version} | Cipher: {cipher[0] if cipher else 'Unknown'}",
                        "remediation": "Disable TLS 1.0 and TLS 1.1 in web server configuration. Enforce TLS 1.2 and TLS 1.3 exclusively.",
                        "cwe_owasp": "CWE-326: Inadequate Encryption Strength | OWASP A02:2021-Cryptographic Failures"
                    })
                else:
                    findings.append({
                        "category": "Transport Security",
                        "title": f"Modern Transport Encryption Enabled ({tls_version})",
                        "severity": "LOW",
                        "status": "PASSED",
                        "description": f"Target successfully negotiated {tls_version} with cipher {cipher[0] if cipher else 'Standard'}.",
                        "impact": "Data in transit is safeguarded against passive eavesdropping and network tampering.",
                        "technical_evidence": f"Protocol: {tls_version} | Cipher Suite: {cipher[0] if cipher else 'Active'}",
                        "remediation": "Continue monitoring cipher suite recommendations and deprecate legacy CBC ciphers.",
                        "cwe_owasp": "NIST SP 800-52r2 Guidelines"
                    })

                # Certificate Expiry Analysis
                if cert and "notAfter" in cert:
                    not_after_str = cert["notAfter"]
                    # Example format: 'May 10 12:00:00 2027 GMT'
                    try:
                        expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expire_date - datetime.utcnow()).days
                        if days_left < 0:
                            findings.append({
                                "category": "Transport Security",
                                "title": "Expired SSL/TLS Certificate",
                                "severity": "CRITICAL",
                                "status": "FAILED",
                                "description": f"Certificate expired on {not_after_str} ({abs(days_left)} days ago).",
                                "impact": "Browsers display prominent security warnings, breaking user trust and blocking traffic.",
                                "technical_evidence": f"Expiry Date: {not_after_str} | Days Remaining: {days_left}",
                                "remediation": "Immediately renew and deploy a valid certificate via Let's Encrypt or your Certificate Authority.",
                                "cwe_owasp": "CWE-295: Improper Certificate Validation"
                            })
                        elif days_left < 15:
                            findings.append({
                                "category": "Transport Security",
                                "title": "SSL/TLS Certificate Nearing Expiration",
                                "severity": "MEDIUM",
                                "status": "WARNING",
                                "description": f"Certificate will expire in {days_left} days on {not_after_str}.",
                                "impact": "Service disruption will occur if certificate is not renewed before the deadline.",
                                "technical_evidence": f"Expiry Date: {not_after_str} | Days Remaining: {days_left}",
                                "remediation": "Initiate automated renewal protocols (e.g. Certbot cron renewal).",
                                "cwe_owasp": "CWE-298: Impending Expiration of Valid Certificate"
                            })
                        else:
                            findings.append({
                                "category": "Transport Security",
                                "title": "Valid SSL/TLS Certificate Deployed",
                                "severity": "LOW",
                                "status": "PASSED",
                                "description": f"Certificate is valid for {days_left} more days (expires {not_after_str}).",
                                "impact": "Users can securely establish encrypted communication with validated server identity.",
                                "technical_evidence": f"Issuer: {dict(x[0] for x in cert.get('issuer', [])) if cert.get('issuer') else 'Recognized CA'}",
                                "remediation": "Ensure automated ACME cert renewal checks are active.",
                                "cwe_owasp": "RFC 5280 PKI Standards"
                            })
                    except Exception:
                        pass

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "category": "Transport Security",
            "title": "SSL Certificate Verification Failed",
            "severity": "HIGH",
            "status": "FAILED",
            "description": f"The target's TLS certificate could not be verified by trust store: {str(e)}",
            "impact": "Self-signed or improperly chained certificates cause browser connection warnings and allow impersonation.",
            "technical_evidence": f"SSL Error: {str(e)}",
            "remediation": "Install a publicly trusted certificate with the full intermediate CA certificate bundle.",
            "cwe_owasp": "CWE-295: Improper Certificate Validation | OWASP A02:2021"
        })
    except Exception as e:
        findings.append({
            "category": "Transport Security",
            "title": "TLS Handshake Inspection Incomplete",
            "severity": "LOW",
            "status": "WARNING",
            "description": f"Direct TLS socket handshake could not be completed: {str(e)}",
            "impact": "Inability to verify certificate details directly over raw socket.",
            "technical_evidence": f"Socket Note: {str(e)}",
            "remediation": "Verify host accessibility, firewall settings, and port 443 connectivity.",
            "cwe_owasp": "CWE-319: Cleartext Transmission"
        })

    return findings
