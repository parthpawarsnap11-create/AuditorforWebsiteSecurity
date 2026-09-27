// CyberSentinel Academic Report Generator (STCS225 Aligned)

function generateFormalReport(scanData) {
  const modal = document.getElementById("report-modal");
  const container = document.getElementById("report-modal-body");
  if (!modal || !container) return;

  const dateStr = new Date(scanData.timestamp).toLocaleString();
  const counts = scanData.counts || { critical: 0, high: 0, medium: 0, low: 0, passed: 0 };
  const meta = scanData.meta_info || {};

  let findingsRows = "";
  (scanData.findings || []).forEach((f, idx) => {
    findingsRows += `
      <tr style="border-bottom: 1px solid #e2e8f0;">
        <td style="padding: 10px; font-weight: 600;">#${idx + 1} ${escapeHtml(f.title)}</td>
        <td style="padding: 10px;">${escapeHtml(f.category)}</td>
        <td style="padding: 10px; font-weight: 700; color: ${getSeverityColor(f.severity)};">${escapeHtml(f.severity)}</td>
        <td style="padding: 10px;">${escapeHtml(f.status)}</td>
        <td style="padding: 10px; font-size: 0.85rem;">${escapeHtml(f.cwe_owasp || "Standard")}</td>
      </tr>
    `;
  });

  let reportHtml = `
    <div style="font-family: Arial, sans-serif; color: #1e293b; line-height: 1.6;">
      <!-- Title Header -->
      <div style="text-align: center; border-bottom: 2px solid #6366f1; padding-bottom: 1.5rem; margin-bottom: 2rem;">
        <h1 style="font-size: 1.8rem; color: #1e1b4b; margin-bottom: 0.25rem;">CYBERSENTINEL</h1>
        <h3 style="font-size: 1.1rem; color: #4338ca; font-weight: 600;">Defensive Web Security & Vulnerability Posture Assessment Report</h3>
        <p style="font-size: 0.9rem; color: #64748b; margin-top: 0.5rem;">
          <strong>Course:</strong> Foundation of Cyber Security (STCS225) | <strong>University:</strong> Vijaybhoomi University (VSST)<br>
          <strong>Team:</strong> Parth Pawar — 2024SEPVUGP0021 | Aryaman V Saboo — 2024SEPVUGP0039
        </p>
      </div>

      <!-- Section 1: Executive Assessment Summary -->
      <h2 style="font-size: 1.25rem; color: #0f172a; border-left: 4px solid #6366f1; padding-left: 10px; margin-bottom: 1rem;">
        1. Executive Assessment Summary
      </h2>
      <div style="display: flex; gap: 20px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.75rem;">
        <div style="text-align: center; border-right: 1px solid #cbd5e1; padding-right: 20px; min-width: 140px;">
          <div style="font-size: 2.75rem; font-weight: 800; color: ${getScoreColor(scanData.score)};">${scanData.score}</div>
          <div style="font-size: 0.8rem; color: #64748b;">SCORE (0-100)</div>
          <div style="display: inline-block; background: #e0e7ff; color: #3730a3; padding: 3px 10px; border-radius: 12px; font-weight: 800; font-size: 0.85rem; margin-top: 5px;">
            GRADE ${escapeHtml(scanData.grade)}
          </div>
        </div>
        <div style="flex: 1;">
          <p><strong>Target URL:</strong> <code>${escapeHtml(scanData.target_url)}</code></p>
          <p><strong>Audit Timestamp:</strong> ${dateStr}</p>
          <p><strong>Security Status:</strong> ${escapeHtml(scanData.posture?.status_label || "Evaluated")}</p>
          <p style="font-size: 0.9rem; color: #475569; margin-top: 6px;">${escapeHtml(scanData.posture?.summary || "")}</p>
        </div>
      </div>

      <!-- Section 2: Severity Distribution -->
      <h2 style="font-size: 1.25rem; color: #0f172a; border-left: 4px solid #6366f1; padding-left: 10px; margin-bottom: 1rem;">
        2. Vulnerability Severity Distribution
      </h2>
      <table style="width: 100%; border-collapse: collapse; margin-bottom: 2rem; font-size: 0.9rem;">
        <thead>
          <tr style="background: #f1f5f9;">
            <th style="padding: 8px 12px; text-align: center; border: 1px solid #cbd5e1;">Critical (-20 pts)</th>
            <th style="padding: 8px 12px; text-align: center; border: 1px solid #cbd5e1;">High (-12 pts)</th>
            <th style="padding: 8px 12px; text-align: center; border: 1px solid #cbd5e1;">Medium (-6 pts)</th>
            <th style="padding: 8px 12px; text-align: center; border: 1px solid #cbd5e1;">Low (-2 pts)</th>
            <th style="padding: 8px 12px; text-align: center; border: 1px solid #cbd5e1;">Passed (Compliant)</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style="padding: 10px; text-align: center; font-weight: 700; color: #e11d48; border: 1px solid #cbd5e1;">${counts.critical}</td>
            <td style="padding: 10px; text-align: center; font-weight: 700; color: #ea580c; border: 1px solid #cbd5e1;">${counts.high}</td>
            <td style="padding: 10px; text-align: center; font-weight: 700; color: #d97706; border: 1px solid #cbd5e1;">${counts.medium}</td>
            <td style="padding: 10px; text-align: center; font-weight: 700; color: #2563eb; border: 1px solid #cbd5e1;">${counts.low}</td>
            <td style="padding: 10px; text-align: center; font-weight: 700; color: #16a34a; border: 1px solid #cbd5e1;">${counts.passed}</td>
          </tr>
        </tbody>
      </table>

      <!-- Section 3: Technical Findings Log -->
      <h2 style="font-size: 1.25rem; color: #0f172a; border-left: 4px solid #6366f1; padding-left: 10px; margin-bottom: 1rem;">
        3. Detailed Technical Findings Matrix
      </h2>
      <table style="width: 100%; border-collapse: collapse; margin-bottom: 2rem; font-size: 0.88rem;">
        <thead>
          <tr style="background: #f1f5f9; text-align: left;">
            <th style="padding: 10px;">Finding Title</th>
            <th style="padding: 10px;">Category</th>
            <th style="padding: 10px;">Severity</th>
            <th style="padding: 10px;">Status</th>
            <th style="padding: 10px;">Standard Reference</th>
          </tr>
        </thead>
        <tbody>
          ${findingsRows}
        </tbody>
      </table>

      <!-- Section 4: Academic Compliance & Ethics Statement -->
      <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.25rem; font-size: 0.85rem; color: #475569;">
        <strong>Ethical & Academic Compliance:</strong> This security assessment was executed in strict accordance with defensive cybersecurity guidelines. No active exploitation, intrusive payloads, denial of service, or unauthorized tampering was attempted. Assessment was restricted to passive HTTP response analysis, TLS handshake evaluation, and DNS policy inspection.
      </div>

      <!-- Action Buttons -->
      <div style="margin-top: 2rem; display: flex; gap: 12px; justify-content: flex-end;" class="no-print">
        <button onclick="window.print()" style="background: #4f46e5; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 700; cursor: pointer;">
          🖨️ Print / Save as PDF
        </button>
        <button onclick="closeReportModal()" style="background: #e2e8f0; color: #334155; border: none; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer;">
          Close
        </button>
      </div>
    </div>
  `;

  container.innerHTML = reportHtml;
  modal.classList.add("active");
}

function closeReportModal() {
  const modal = document.getElementById("report-modal");
  if (modal) modal.classList.remove("active");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function getSeverityColor(sev) {
  switch (sev?.toUpperCase()) {
    case "CRITICAL": return "#e11d48";
    case "HIGH": return "#ea580c";
    case "MEDIUM": return "#d97706";
    case "LOW": return "#2563eb";
    default: return "#16a34a";
  }
}

function getScoreColor(score) {
  if (score >= 85) return "#16a34a";
  if (score >= 70) return "#2563eb";
  if (score >= 55) return "#d97706";
  return "#e11d48";
}
