from typing import Dict, Any, List
from urllib.parse import urlparse
import dns.resolver

def scan_dns(target_url: str) -> List[Dict[str, Any]]:
    findings = []
    parsed = urlparse(target_url)
    domain = parsed.hostname or ""

    if not domain or domain in ("127.0.0.1", "localhost"):
        findings.append({
            "category": "DNS & Anti-Spoofing",
            "title": "Local/Loopback Hostname (DNS Checks Skipped)",
            "severity": "LOW",
            "status": "INFO",
            "description": f"Domain '{domain}' resolves locally. Public DNS SPF/DMARC inspection is bypassed.",
            "impact": "Local mock testing environment.",
            "technical_evidence": f"Target Domain: {domain}",
            "remediation": "Test public registered domains for complete DNS email hygiene evaluation.",
            "cwe_owasp": "N/A"
        })
        return findings

    # Root domain extraction (e.g. sub.example.com -> example.com)
    domain_parts = domain.split(".")
    root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 1. Check A / AAAA Records
    try:
        a_records = [r.to_text() for r in resolver.resolve(domain, "A")]
        findings.append({
            "category": "DNS & Anti-Spoofing",
            "title": "DNS A Records Resolved",
            "severity": "LOW",
            "status": "PASSED",
            "description": f"Domain successfully resolved to IPv4 addresses: {', '.join(a_records[:3])}.",
            "impact": "Valid name resolution confirms network routability.",
            "technical_evidence": f"A Records: {', '.join(a_records)}",
            "remediation": "Ensure TTL values are balanced for cache efficiency and rapid failover.",
            "cwe_owasp": "RFC 1035 Domain Implementation"
        })
    except Exception:
        pass

    # 2. Check SPF (Sender Policy Framework) Record
    has_spf = False
    spf_record_text = ""
    try:
        txt_records = resolver.resolve(root_domain, "TXT")
        for rdata in txt_records:
            txt_str = rdata.to_text().strip('"')
            if txt_str.lower().startswith("v=spf1"):
                has_spf = True
                spf_record_text = txt_str
                break
    except Exception:
        pass

    if not has_spf:
        findings.append({
            "category": "DNS & Anti-Spoofing",
            "title": f"Missing SPF (Sender Policy Framework) Record on {root_domain}",
            "severity": "MEDIUM",
            "status": "FAILED",
            "description": "The domain lacks an active SPF TXT record declaring which mail servers are authorized to send email on its behalf.",
            "impact": "Cybercriminals and phishing operators can easily spoof emails appearing to originate from this domain to deceive customers and employees.",
            "technical_evidence": f"No 'v=spf1' TXT record found for '{root_domain}'.",
            "remediation": f"Publish an SPF TXT record for {root_domain}. Example: 'v=spf1 include:_spf.google.com ~all'.",
            "cwe_owasp": "CWE-345: Insufficient Verification of Data Authenticity | RFC 7208"
        })
    else:
        findings.append({
            "category": "DNS & Anti-Spoofing",
            "title": f"SPF Anti-Spoofing Record Present ({root_domain})",
            "severity": "LOW",
            "status": "PASSED",
            "description": f"Domain enforces mail server authorization: {spf_record_text[:60]}...",
            "impact": "Helps mail transfer agents identify and reject forged sender identities.",
            "technical_evidence": f"SPF: {spf_record_text}",
            "remediation": "Regularly audit SPF mechanisms to avoid exceeding the 10 DNS lookup limit.",
            "cwe_owasp": "RFC 7208 Specification"
        })

    # 3. Check DMARC (Domain-based Message Authentication, Reporting & Conformance)
    has_dmarc = False
    dmarc_policy = ""
    try:
        dmarc_domain = f"_dmarc.{root_domain}"
        dmarc_records = resolver.resolve(dmarc_domain, "TXT")
        for rdata in dmarc_records:
            txt_str = rdata.to_text().strip('"')
            if "v=dmarc1" in txt_str.lower():
                has_dmarc = True
                dmarc_policy = txt_str
                break
    except Exception:
        pass

    if not has_dmarc:
        findings.append({
            "category": "DNS & Anti-Spoofing",
            "title": f"Missing DMARC Policy Record on _dmarc.{root_domain}",
            "severity": "MEDIUM",
            "status": "FAILED",
            "description": "No DMARC record is published. DMARC enables domain owners to specify how receivers should handle emails that fail SPF or DKIM checks.",
            "impact": "Unprotected against brand impersonation, spear phishing campaigns, and CEO fraud using the organization's domain name.",
            "technical_evidence": f"No DMARC record found at _dmarc.{root_domain}",
            "remediation": f"Deploy a DMARC TXT record at '_dmarc.{root_domain}'. Example: 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@{root_domain}'.",
            "cwe_owasp": "CWE-345: Insufficient Verification | RFC 7489"
        })
    else:
        findings.append({
            "category": "DNS & Anti-Spoofing",
            "title": f"DMARC Policy Enforced (_dmarc.{root_domain})",
            "severity": "LOW",
            "status": "PASSED",
            "description": f"DMARC validation directive deployed: {dmarc_policy[:60]}...",
            "impact": "Instructs recipient mail servers to quarantine or reject unauthenticated messages.",
            "technical_evidence": f"DMARC: {dmarc_policy}",
            "remediation": "Gradually advance policy from 'p=none' to 'p=quarantine' and 'p=reject'.",
            "cwe_owasp": "RFC 7489 DMARC Standard"
        })

    return findings
