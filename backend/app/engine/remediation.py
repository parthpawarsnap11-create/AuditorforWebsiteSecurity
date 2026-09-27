from typing import Dict, Any, List

SNIPPET_TEMPLATES = {
    "nginx": """# Nginx Security Hardening Directives (/etc/nginx/nginx.conf)
server {
    listen 443 ssl http2;
    server_name example.com;

    # Transport Security & HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Content Security Policy (CSP)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;

    # Browser Security Controls
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;

    # Suppress Server Banner Exposure
    server_tokens off;
}
""",
    "apache": """# Apache Security Headers (.htaccess / httpd.conf)
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>
ServerTokens Prod
ServerSignature Off
""",
    "express": """// Node.js Express Helmet Hardening Middleware
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by');

app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
""",
    "fastapi": """# Python FastAPI / Starlette Security Middleware
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

app = FastAPI()

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self';"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)
"""
}

def get_remediation_guide(category: str, title: str) -> Dict[str, str]:
    return {
        "nginx": SNIPPET_TEMPLATES["nginx"],
        "apache": SNIPPET_TEMPLATES["apache"],
        "express": SNIPPET_TEMPLATES["express"],
        "fastapi": SNIPPET_TEMPLATES["fastapi"]
    }
