from typing import List, Dict, Any, Tuple

SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2
}

def calculate_wspi_score(findings: List[Dict[str, Any]]) -> Tuple[int, str, Dict[str, int]]:
    score = 100
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "passed": 0,
        "total": len(findings)
    }

    for f in findings:
        status = f.get("status", "").upper()
        severity = f.get("severity", "").upper()

        if status == "PASSED":
            counts["passed"] += 1
            continue

        if status in ("FAILED", "WARNING"):
            if severity == "CRITICAL":
                counts["critical"] += 1
                score -= SEVERITY_WEIGHTS["CRITICAL"]
            elif severity == "HIGH":
                counts["high"] += 1
                score -= SEVERITY_WEIGHTS["HIGH"]
            elif severity == "MEDIUM":
                counts["medium"] += 1
                score -= SEVERITY_WEIGHTS["MEDIUM"]
            elif severity == "LOW":
                counts["low"] += 1
                score -= SEVERITY_WEIGHTS["LOW"]

    # Clamp score to 0 - 100 range
    score = max(0, min(100, score))

    # Determine Academic/Industry Grade
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return score, grade, counts

def get_posture_summary(score: int, grade: str) -> Dict[str, str]:
    if grade in ("A+", "A"):
        return {
            "status_label": "Hardened & Compliant",
            "badge_color": "emerald",
            "summary": "Target exhibits excellent defense-in-depth configurations with strict transport, modern policy headers, and minimal attack surface disclosure."
        }
    elif grade == "B":
        return {
            "status_label": "Acceptable Defense (Minor Gaps)",
            "badge_color": "blue",
            "summary": "Target has established foundational protections, but lacks advanced policies (such as granular CSP directives or email anti-spoofing)."
        }
    elif grade == "C":
        return {
            "status_label": "Action Recommended",
            "badge_color": "yellow",
            "summary": "Multiple missing browser security headers and cookie hygiene flags increase potential vulnerability to clickjacking, MIME-sniffing, and session theft."
        }
    elif grade == "D":
        return {
            "status_label": "Elevated Security Risk",
            "badge_color": "orange",
            "summary": "High-severity vulnerabilities detected, such as missing HSTS, unencrypted endpoints, or overly permissive CORS configurations."
        }
    else:
        return {
            "status_label": "Critical Exposure Detected",
            "badge_color": "red",
            "summary": "Target is severely compromised in terms of defensive configurations. Immediate remediation is mandatory before processing sensitive traffic."
        }
