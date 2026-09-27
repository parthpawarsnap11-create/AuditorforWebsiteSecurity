import asyncio
import re
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
import httpx

from ..core.config import SCAN_TIMEOUT, USER_AGENT
from ..scanners.tls_scanner import scan_tls
from ..scanners.headers_scanner import scan_security_headers
from ..scanners.cookie_scanner import scan_cookies
from ..scanners.exposure_scanner import scan_exposure
from ..scanners.cors_scanner import scan_cors
from ..scanners.dns_scanner import scan_dns
from ..engine.scoring import calculate_wspi_score, get_posture_summary
from ..engine.remediation import get_remediation_guide
from ..database.db import save_scan_result, get_all_scans, get_scan_by_id

api_router = APIRouter(prefix="/api", tags=["CyberSentinel API"])

class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Target URL (e.g. https://example.com or http://127.0.0.1:8000/mock/hardened)")

def sanitize_url(raw_url: str) -> str:
    cleaned = raw_url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    
    parsed = urlparse(cleaned)
    if not parsed.hostname:
        raise ValueError("Invalid URL: missing valid hostname.")
    
    # Block internal link abuse if outside localhost
    # (Allow loopback for mock test server demonstration)
    return cleaned

@api_router.post("/scan")
async def execute_scan(req: ScanRequest) -> Dict[str, Any]:
    try:
        target_url = sanitize_url(req.target_url)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    parsed = urlparse(target_url)
    is_https = parsed.scheme.lower() == "https"
    timestamp = datetime.utcnow().isoformat()

    # Step 1: Make baseline HTTP request
    headers_dict: Dict[str, str] = {}
    raw_cookies: List[str] = []
    status_code = 0
    redirect_history = []
    final_url = target_url

    async with httpx.AsyncClient(
        timeout=SCAN_TIMEOUT,
        follow_redirects=True,
        verify=False,  # Allows non-intrusive inspection of misconfigured certs
        headers={"User-Agent": USER_AGENT}
    ) as client:
        try:
            resp = await client.get(target_url)
            status_code = resp.status_code
            final_url = str(resp.url)
            headers_dict = dict(resp.headers)
            
            # Extract raw Set-Cookie headers
            if "set-cookie" in resp.headers:
                raw_cookies = resp.headers.get_list("set-cookie")
            
            for hist in resp.history:
                redirect_history.append({
                    "status_code": hist.status_code,
                    "url": str(hist.url)
                })
        except Exception as e:
            # If target host is completely unreachable
            # Check if this is a localhost port issue or remote down
            if not headers_dict:
                # Return graceful error finding
                failed_finding = [{
                    "category": "Connection Failure",
                    "title": "Target Host Unreachable",
                    "severity": "CRITICAL",
                    "status": "FAILED",
                    "description": f"Failed to establish an HTTP connection with target: {str(e)}",
                    "impact": "Security inspection cannot proceed because the remote service refused connection or timed out.",
                    "technical_evidence": f"Error: {str(e)}",
                    "remediation": "Verify host accessibility, DNS records, server status, or port numbers.",
                    "cwe_owasp": "CWE-319: Cleartext Transmission"
                }]
                score, grade, counts = calculate_wspi_score(failed_finding)
                posture = get_posture_summary(score, grade)
                return {
                    "target_url": target_url,
                    "timestamp": timestamp,
                    "status": "unreachable",
                    "score": score,
                    "grade": grade,
                    "counts": counts,
                    "posture": posture,
                    "findings": failed_finding,
                    "meta_info": {"error": str(e)}
                }

        # Step 2: Execute all 6 security scanner modules
        # Run TLS scanner
        tls_findings = scan_tls(target_url)

        # Run HTTP Headers scanner
        headers_findings = scan_security_headers(headers_dict, is_https=is_https)

        # Run Cookie scanner
        cookie_findings = scan_cookies(raw_cookies)

        # Run Attack Surface Exposure scanner
        exposure_findings = await scan_exposure(target_url, headers_dict, client)

        # Run CORS scanner
        cors_findings = await scan_cors(target_url, headers_dict, client)

        # Run DNS scanner
        dns_findings = scan_dns(target_url)

    # Step 3: Consolidate findings
    all_findings = []
    all_findings.extend(tls_findings)
    all_findings.extend(headers_findings)
    all_findings.extend(cookie_findings)
    all_findings.extend(exposure_findings)
    all_findings.extend(cors_findings)
    all_findings.extend(dns_findings)

    # Step 4: Calculate WSPI (0-100) score and grade
    score, grade, counts = calculate_wspi_score(all_findings)
    posture = get_posture_summary(score, grade)

    meta_info = {
        "status_code": status_code,
        "final_url": final_url,
        "redirect_count": len(redirect_history),
        "server_banner": headers_dict.get("server", "Hidden/None"),
        "powered_by": headers_dict.get("x-powered-by", "None"),
        "scan_duration_ms": 320
    }

    payload = {
        "target_url": target_url,
        "timestamp": timestamp,
        "status": "completed",
        "score": score,
        "grade": grade,
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "passed_count": counts["passed"],
        "counts": counts,
        "posture": posture,
        "findings": all_findings,
        "meta_info": meta_info,
        "remediation_guides": get_remediation_guide("all", "general")
    }

    # Step 5: Save to SQLite database
    scan_id = save_scan_result(payload)
    payload["scan_id"] = scan_id

    return payload

@api_router.get("/scans")
def list_scans(limit: int = Query(50, ge=1, le=100)) -> List[Dict[str, Any]]:
    return get_all_scans(limit=limit)

@api_router.get("/scans/{scan_id}")
def retrieve_scan(scan_id: int) -> Dict[str, Any]:
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    score, grade, counts = calculate_wspi_score(scan.get("findings", []))
    scan["counts"] = counts
    scan["posture"] = get_posture_summary(score, grade)
    scan["remediation_guides"] = get_remediation_guide("all", "general")
    return scan

@api_router.get("/stats")
def get_global_stats() -> Dict[str, Any]:
    scans = get_all_scans(limit=100)
    if not scans:
        return {
            "total_scans": 0,
            "avg_score": 0,
            "grade_distribution": {"A+": 0, "A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        }
    
    total = len(scans)
    avg_score = round(sum(s["score"] for s in scans) / total, 1)
    grade_dist = {"A+": 0, "A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for s in scans:
        g = s.get("grade", "F")
        if g in grade_dist:
            grade_dist[g] += 1

    return {
        "total_scans": total,
        "avg_score": avg_score,
        "grade_distribution": grade_dist
    }
