

## 1. Overview
**CyberSentinel** is an automated, non-intrusive web security posture evaluation engine. It assesses the defensive configuration of any authorized web target—including transport encryption, modern browser security headers, cookie hygiene, attack surface exposure, CORS policies, and domain email anti-spoofing safeguards—without deploying aggressive or offensive payloads.

## 2. Key Features
- **6 Core Security Scanners**:
  1. *Transport Security & TLS*: Protocol version (TLS 1.2/1.3), certificate validity, expiration, and HSTS preload readiness.
  2. *HTTP Security Headers*: CSP directive evaluation, HSTS, X-Frame-Options (Clickjacking), X-Content-Type-Options (MIME-sniffing), Referrer-Policy, Permissions-Policy, COOP.
  3. *Cookie Hygiene*: Strict verification of `Secure`, `HttpOnly`, `SameSite` flags, and `__Host-` / `__Secure-` prefixes.
  4. *Attack Surface & Recon*: Detection of `Server` version banners, `X-Powered-By`, ASP.NET/PHP disclosures, and `security.txt` discovery.
  5. *CORS Policy*: Wildcard `*` origins, null origin reflection, and credential exposure.
  6. *DNS & Email Spoofing Defense*: DNS resolution and verification of SPF and DMARC TXT records.
- **Weighted Security Posture Index (WSPI: 0–100)**: Algorithmic scoring with letter grades (A+, A, B, C, D, F) based on CVSS-aligned severity deductions.
- **Actionable Remediation**: Multi-platform configuration snippets (Nginx, Apache, Express.js, FastAPI).
- **Built-in Safe Test Bench**: Local mock servers (`/mock/hardened` [Grade A+], `/mock/vulnerable` [Grade F], `/mock/balanced` [Grade B]) for offline demonstration.
- **Persistent SQLite Audit History**: Relational logging of past assessments.
- **1-Click Academic Report Generator**: Formats complete reports matching Vijaybhoomi University STCS225 requirements.

## 3. Technology Stack
- **Backend**: Python 3.12, FastAPI, Uvicorn, HTTPX, Cryptography, dnspython, SQLite3
- **Frontend**: Modern Vanilla Web UI (HTML5, Custom Obsidian CSS Design Tokens, SVG Circular Radial Gauge, Glassmorphism)
- **Testing**: Pytest automated test suite

## 4. Quick Start (Windows)
Double-click `run.bat` or run the following command in PowerShell:
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser and navigate to: `http://127.0.0.1:8000`

## 5. Running Automated Verification Tests
```powershell
pytest tests/test_scanners.py -v
```

## 6. Ethical & Defensive Cybersecurity Standards
CyberSentinel operates entirely within defensive and ethical boundaries:
- Conforms to OWASP Top 10 (2021) and NIST SP 800-52r2 standards.
- Does **not** perform SQL injection, Cross-Site Scripting exploit injection, brute force, or denial-of-service.
- All testing targets local loopback addresses or authorized domains via standard passive HTTP headers.
