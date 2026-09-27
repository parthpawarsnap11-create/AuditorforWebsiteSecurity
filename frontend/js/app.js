// CyberSentinel Core Application Logic

let currentScanData = null;
let currentFilter = "all";

document.addEventListener("DOMContentLoaded", () => {
  initPresets();
  loadScanHistory();
  checkApiHealth();
});

// Check backend connectivity
async function checkApiHealth() {
  const statusPill = document.getElementById("api-status-pill");
  try {
    const res = await fetch("/health");
    if (res.ok) {
      if (statusPill) statusPill.innerHTML = '<span class="status-dot"></span> API Connected';
    } else {
      if (statusPill) statusPill.innerHTML = '<span class="status-dot" style="background:#f43f5e;"></span> API Warning';
    }
  } catch (e) {
    if (statusPill) statusPill.innerHTML = '<span class="status-dot" style="background:#f43f5e;"></span> Offline';
  }
}

// Quick Preset Handlers
function initPresets() {
  const input = document.getElementById("target-url-input");
  const protocolSelect = document.getElementById("protocol-select");

  window.selectPreset = function(type) {
    if (type === "hardened") {
      protocolSelect.value = "http://";
      input.value = "127.0.0.1:8000/mock/hardened";
    } else if (type === "vulnerable") {
      protocolSelect.value = "http://";
      input.value = "127.0.0.1:8000/mock/vulnerable";
    } else if (type === "balanced") {
      protocolSelect.value = "http://";
      input.value = "127.0.0.1:8000/mock/balanced";
    } else if (type === "custom") {
      protocolSelect.value = "https://";
      input.value = "";
      input.placeholder = "Enter custom domain e.g. example.com";
      input.focus();
    }
  };
}

// Initiate Audit
async function triggerAudit() {
  const protocol = document.getElementById("protocol-select").value;
  const rawInput = document.getElementById("target-url-input").value.trim();

  if (!rawInput) {
    alert("Please enter a valid target URL or select a preset benchmark.");
    return;
  }

  let fullUrl = rawInput;
  if (!rawInput.startsWith("http://") && !rawInput.startsWith("https://")) {
    fullUrl = protocol + rawInput;
  }

  // UI state: Scanning
  const scanBtn = document.getElementById("scan-btn");
  const progressBar = document.getElementById("scan-progress-bar");
  const resultsSection = document.getElementById("results-section");

  scanBtn.disabled = true;
  scanBtn.innerHTML = '<span>⏳</span> Auditing Target...';
  progressBar.classList.add("active");
  resultsSection.classList.remove("visible");

  animateProgressSteps();

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: fullUrl })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Scan request failed");
    }

    const data = await res.json();
    currentScanData = data;

    // Render results
    renderDashboard(data);
    loadScanHistory(); // Refresh history
  } catch (err) {
    alert("Audit Error: " + err.message);
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<span>🛡️</span> Run Defensive Audit';
    progressBar.classList.remove("active");
  }
}

// Step-by-step progress animation
function animateProgressSteps() {
  const steps = document.querySelectorAll(".step-item");
  steps.forEach((s, idx) => {
    s.classList.remove("active", "completed");
    setTimeout(() => {
      s.classList.add("active");
      if (idx > 0) steps[idx - 1].classList.remove("active");
      if (idx > 0) steps[idx - 1].classList.add("completed");
    }, idx * 250);
  });
}

// Render Results Dashboard
function renderDashboard(data) {
  const resultsSection = document.getElementById("results-section");
  resultsSection.classList.add("visible");
  resultsSection.scrollIntoView({ behavior: "smooth" });

  // Update SVG Gauge
  updateScoreGauge(data.score, data.grade);

  // Update Posture Summary Box
  document.getElementById("res-target-url").textContent = data.target_url;
  document.getElementById("res-status-label").textContent = data.posture?.status_label || "Evaluated";
  document.getElementById("res-summary-text").textContent = data.posture?.summary || "";

  // Update Metric Counters
  const counts = data.counts || { critical: 0, high: 0, medium: 0, low: 0, passed: 0 };
  document.getElementById("cnt-critical").textContent = counts.critical;
  document.getElementById("cnt-high").textContent = counts.high;
  document.getElementById("cnt-medium").textContent = counts.medium;
  document.getElementById("cnt-low").textContent = counts.low;
  document.getElementById("cnt-passed").textContent = counts.passed;

  // Metadata
  const meta = data.meta_info || {};
  document.getElementById("meta-server").textContent = meta.server_banner || "Not Disclosed";
  document.getElementById("meta-status-code").textContent = meta.status_code || "N/A";
  document.getElementById("meta-duration").textContent = (meta.scan_duration_ms || 350) + " ms";

  // Render Findings
  renderFindings(data.findings || []);
}

// Filter and Render Finding Cards
function renderFindings(findings) {
  const container = document.getElementById("findings-list");
  container.innerHTML = "";

  const filtered = findings.filter(f => {
    const sev = f.severity?.toLowerCase();
    const status = f.status?.toLowerCase();
    if (currentFilter === "all") return true;
    if (currentFilter === "critical-high") return sev === "critical" || sev === "high";
    if (currentFilter === "medium") return sev === "medium";
    if (currentFilter === "low") return sev === "low" && status !== "passed";
    if (currentFilter === "passed") return status === "passed";
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align:center; padding: 2rem; color: var(--text-muted); background: var(--bg-card); border-radius: var(--radius-md);">
        No findings match the selected filter criteria.
      </div>
    `;
    return;
  }

  filtered.forEach((f, idx) => {
    const card = document.createElement("div");
    const sevClass = f.status?.toLowerCase() === "passed" ? "passed" : f.severity?.toLowerCase();
    card.className = `finding-card severity-${sevClass}`;

    card.innerHTML = `
      <div class="finding-header" onclick="toggleCard(this)">
        <div class="finding-title-group">
          <span class="badge badge-${sevClass}">${escapeHtml(f.severity)}</span>
          <span class="badge badge-category">${escapeHtml(f.category)}</span>
          <span class="finding-title">${escapeHtml(f.title)}</span>
        </div>
        <div class="chevron-icon">▼</div>
      </div>
      <div class="finding-body">
        <div class="detail-block">
          <div class="detail-label">Issue Description</div>
          <div class="detail-text">${escapeHtml(f.description)}</div>
        </div>
        <div class="detail-block">
          <div class="detail-label">Security Impact</div>
          <div class="detail-text">${escapeHtml(f.impact)}</div>
        </div>
        <div class="detail-block">
          <div class="detail-label">Technical Evidence</div>
          <div class="code-snippet-box">${escapeHtml(f.technical_evidence)}</div>
        </div>
        <div class="detail-block">
          <div class="detail-label">Actionable Remediation</div>
          <div class="detail-text" style="color:#6ee7b7; margin-bottom: 6px;">${escapeHtml(f.remediation)}</div>
          <div class="detail-label" style="margin-top: 10px;">Configuration Snippet (Nginx / Express / Apache)</div>
          <div class="code-snippet-box">
            <button class="copy-btn" onclick="copySnippet(this, \`${escapeJs(getSnippetForCategory(f.category))}\`)">Copy Code</button>
            <pre style="margin:0;"><code>${escapeHtml(getSnippetForCategory(f.category))}</code></pre>
          </div>
        </div>
        ${f.cwe_owasp ? `
        <div class="detail-block" style="margin-top: 8px;">
          <span class="detail-label">Standards Reference: </span>
          <span style="font-size:0.8rem; color:#94a3b8;">${escapeHtml(f.cwe_owasp)}</span>
        </div>` : ""}
      </div>
    `;

    container.appendChild(card);
  });
}

function toggleCard(el) {
  const card = el.closest(".finding-card");
  card.classList.toggle("open");
}

function setFilter(filterType, element) {
  currentFilter = filterType;
  document.querySelectorAll(".metric-pill").forEach(p => p.classList.remove("active"));
  if (element) element.classList.add("active");
  if (currentScanData) {
    renderFindings(currentScanData.findings || []);
  }
}

// Load SQLite History
async function loadScanHistory() {
  const tbody = document.getElementById("history-table-body");
  if (!tbody) return;

  try {
    const res = await fetch("/api/scans?limit=10");
    if (!res.ok) return;
    const scans = await res.json();

    if (scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--text-muted);">No previous audits recorded. Run your first audit above!</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    scans.forEach(s => {
      const row = document.createElement("tr");
      const date = new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      row.innerHTML = `
        <td style="font-family:var(--font-mono); font-size:0.82rem;">${escapeHtml(s.target_url)}</td>
        <td>${date}</td>
        <td><strong style="color:${getScoreColor(s.score)}">${s.score}</strong> / 100</td>
        <td><span class="badge" style="background:rgba(99,102,241,0.2); color:#c7d2fe;">${escapeHtml(s.grade)}</span></td>
        <td>
          <span style="color:#f43f5e; font-weight:700;">${s.critical_count + s.high_count}</span> Fail /
          <span style="color:#10b981; font-weight:700;">${s.passed_count}</span> Pass
        </td>
        <td>
          <button class="btn-secondary" style="padding: 3px 8px; font-size:0.75rem;" onclick="viewHistoryScan(${s.id})">
            Inspect
          </button>
        </td>
      `;
      tbody.appendChild(row);
    });
  } catch (e) {
    console.error("Failed to load history", e);
  }
}

async function viewHistoryScan(id) {
  try {
    const res = await fetch(`/api/scans/${id}`);
    if (res.ok) {
      const data = await res.json();
      currentScanData = data;
      renderDashboard(data);
    }
  } catch (e) {
    alert("Could not load historical scan: " + e.message);
  }
}

function exportScanJson() {
  if (!currentScanData) return;
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentScanData, null, 2));
  const downloadAnchor = document.createElement("a");
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `cybersentinel_audit_${Date.now()}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

function triggerReportModal() {
  if (!currentScanData) {
    alert("Please execute an audit first to generate the report.");
    return;
  }
  generateFormalReport(currentScanData);
}

function copySnippet(btn, code) {
  navigator.clipboard.writeText(code).then(() => {
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy Code"; }, 1500);
  });
}

function getSnippetForCategory(category) {
  if (category === "HTTP Security Headers") {
    return `# Nginx Hardening Directives (/etc/nginx/conf.d/security.conf)\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self';" always;\nadd_header X-Frame-Options "DENY" always;\nadd_header X-Content-Type-Options "nosniff" always;`;
  } else if (category === "Cookie Hygiene") {
    return `// Express.js Cookie Hardening Flag Configuration\nres.cookie('session_id', token, {\n  secure: true,\n  httpOnly: true,\n  sameSite: 'strict',\n  maxAge: 3600000\n});`;
  } else if (category === "Attack Surface Recon") {
    return `# Suppress Server Version Tokens in Nginx & Apache\n# Nginx:\nserver_tokens off;\n\n# Apache:\nServerTokens Prod\nServerSignature Off`;
  } else if (category === "CORS Policy Audit") {
    return `# Safe CORS Whitelist Configuration (FastAPI)\nfrom fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=["https://yourdomain.com"],\n    allow_credentials=True,\n    allow_methods=["GET", "POST"]\n)`;
  } else {
    return `# DNS SPF & DMARC Anti-Spoofing TXT Records\n# SPF:\nv=spf1 include:_spf.google.com ~all\n\n# DMARC:\nv=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com`;
  }
}

function escapeJs(str) {
  return str.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$/g, "\\$");
}
