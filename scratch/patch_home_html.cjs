const fs = require('fs');
const file = 'src/components/home.tsx';
let content = fs.readFileSync(file, 'utf8');

const startRegex = /const handleGenerateReport = \(\) => \{/;
const startMatch = startRegex.exec(content);

if (startMatch) {
  const startIndex = startMatch.index;
  let braces = 0;
  let endIndex = -1;
  let started = false;

  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === '{') {
      braces++;
      started = true;
    } else if (content[i] === '}') {
      braces--;
      if (started && braces === 0) {
        endIndex = i;
        break;
      }
    }
  }

  if (endIndex !== -1) {
    const replacement = `const handleGenerateReport = () => {
    if (!scanResults) {
      alert("No scan results available. Please run a scan first.");
      return;
    }

    const vulns = scanResults.vulnerabilities || [];
    const meta  = scanResults.scanMetadata || {};
    const recon = scanResults.reconnaissance || {};
    const owasp = scanResults.owaspCompliance || { findings: [] };

    const criticalCount = vulns.filter((v: any) => v.severity === "critical").length;
    const highCount     = vulns.filter((v: any) => v.severity === "high").length;
    const mediumCount   = vulns.filter((v: any) => v.severity === "medium").length;
    const lowCount      = vulns.filter((v: any) => v.severity === "low").length;
    const riskScore     = meta.riskScore ?? 0;

    const severityColor = (s: string) => ({
      critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#2563eb", info: "#6b7280",
    }[s] ?? "#6b7280");

    const vulnRows = vulns.map((v: any, i: number) => \`
      <div class="vuln-card">
        <div class="vuln-header" style="background:\${severityColor(v.severity)}">
          <span class="vuln-num">\${i + 1}</span>
          <span class="vuln-title">\${v.title}</span>
          <span class="badge">\${v.severity.toUpperCase()}</span>
        </div>
        <div class="vuln-body">
          <div class="meta-row"><span class="label">OWASP Category</span><span>\${v.owaspCategory || v.category || "—"}</span></div>
          <div class="meta-row"><span class="label">CVSS Score</span><span>\${v.cvss ?? "N/A"}</span></div>
          <div class="meta-row"><span class="label">Confidence</span><span>\${v.confidence ?? "—"}</span></div>
          <div class="meta-row"><span class="label">Affected</span><span>\${(v.affectedComponents || []).join(", ")}</span></div>
          <p class="section-label">Evidence / Technical Detail</p>
          <p class="evidence">\${v.evidence || v.technicalDetails || "—"}</p>
          <p class="section-label">Description</p>
          <p>\${v.description}</p>
          <p class="section-label">Impact (Business View)</p>
          <p>\${v.impact}</p>
          <p class="section-label">Remediation (Tech View)</p>
          <p class="remediation">\${v.remediation}</p>
          \${v.references?.length ? \`<p class="section-label">References</p><ul>\${v.references.map((r: any) => \`<li><a href="\${r.url}" target="_blank">\${r.title}</a></li>\`).join("")}</ul>\` : ""}
        </div>
      </div>\`).join("");

    const owaspRows = owasp.findings?.map((f: any) => \`
      <tr>
        <td style="font-weight:600">\${f.category}</td>
        <td><span style="color:\${f.status === 'Compliant' ? '#16a34a' : '#dc2626'}; font-weight: bold;">\${f.status}</span></td>
        <td>\${f.findings}</td>
        <td style="color:#64748b">\${f.details.join(", ")}</td>
      </tr>\`).join("");

    const portRows = recon.portResults?.map((p: any) => \`
      <tr>
        <td>\${p.port}/tcp</td>
        <td>\${p.service}</td>
        <td><span style="color:\${p.open ? '#dc2626' : '#16a34a'}; font-weight: bold;">\${p.open ? 'OPEN' : 'CLOSED'}</span></td>
        <td style="color:#64748b; font-family: monospace;">\${p.banner || "—"}</td>
      </tr>\`).join("") || "<tr><td colspan='4'>No port scan data available</td></tr>";

    const dnsRows = [
      \`<tr><td>A Records (IPs)</td><td>\${(recon.dnsResult?.A || []).join(", ") || "—"}</td></tr>\`,
      \`<tr><td>MX Records (Mail)</td><td>\${(recon.dnsResult?.MX || []).join(", ") || "—"}</td></tr>\`,
      \`<tr><td>NS Records (Nameservers)</td><td>\${(recon.dnsResult?.NS || []).join(", ") || "—"}</td></tr>\`,
      \`<tr><td>TXT Records (Security)</td><td style="font-family: monospace; word-break: break-all;">\${(recon.dnsResult?.TXT || []).join("<br/>") || "—"}</td></tr>\`
    ].join("");

    const html = \`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VAPT Report — \${meta.targetValue}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "Segoe UI", Arial, sans-serif; font-size: 13px; color: #1e293b; background: #f8fafc; }
  .page { max-width: 1000px; margin: 20px auto; padding: 40px 48px; background: #fff; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); border-radius: 8px; }
  .header { border-bottom: 3px solid #090514; padding-bottom: 20px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: flex-end; }
  .header h1 { font-size: 26px; color: #090514; letter-spacing: -0.5px; }
  .header .sub { color: #64748b; font-size: 13px; margin-top: 4px; }
  .print-btn { background: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; transition: background 0.2s; }
  .print-btn:hover { background: #2563eb; }
  .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .meta-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; text-align: center; }
  .meta-card .num { font-size: 28px; font-weight: 800; color: #090514; }
  .meta-card .lbl { font-size: 11px; color: #64748b; text-transform: uppercase; margin-top: 4px; }
  h2 { font-size: 18px; font-weight: 700; margin: 32px 0 16px; border-left: 4px solid #3b82f6; padding-left: 10px; color: #1e293b; background: #f1f5f9; padding: 8px 12px; border-radius: 0 4px 4px 0; }
  .info-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
  .info-table td { padding: 9px 12px; border: 1px solid #e2e8f0; font-size: 13px; }
  .info-table td:first-child { font-weight: 600; background: #f8fafc; width: 220px; }
  .vuln-card { border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 24px; overflow: hidden; page-break-inside: avoid; }
  .vuln-header { display: flex; align-items: center; gap: 10px; padding: 12px 16px; color: white; }
  .vuln-num { background: rgba(255,255,255,0.25); border-radius: 50%; width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; flex-shrink: 0; }
  .vuln-title { flex: 1; font-weight: 600; font-size: 15px; }
  .badge { background: rgba(255,255,255,0.2); border-radius: 12px; padding: 2px 10px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }
  .vuln-body { padding: 20px; }
  .meta-row { display: flex; gap: 12px; font-size: 13px; margin-bottom: 8px; border-bottom: 1px dashed #e2e8f0; padding-bottom: 4px; }
  .label { font-weight: 600; color: #475569; min-width: 150px; }
  .section-label { font-weight: 700; color: #1e293b; margin: 16px 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #e2e8f0; display: inline-block; padding-bottom: 2px; }
  .evidence { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; font-family: "Consolas", monospace; font-size: 12px; margin-bottom: 12px; border-left: 4px solid #3b82f6; overflow-x: auto; }
  .remediation { background: #f0fdf4; border: 1px solid #bbf7d0; border-left: 4px solid #16a34a; padding: 12px; border-radius: 6px; color: #166534; line-height: 1.5; }
  ul { padding-left: 20px; margin-top: 8px; }
  li { margin: 4px 0; color: #475569; } a { color: #2563eb; text-decoration: none; font-weight: 500; } a:hover { text-decoration: underline; }
  .owasp-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 24px; }
  .owasp-table th { background: #0f172a; color: white; padding: 10px 12px; text-align: left; }
  .owasp-table td { padding: 9px 12px; border: 1px solid #e2e8f0; }
  .owasp-table tr:nth-child(even) td { background: #f8fafc; }
  .footer { margin-top: 60px; padding-top: 20px; border-top: 2px solid #e2e8f0; color: #64748b; font-size: 12px; text-align: center; }
  @media print { 
    body { background: #fff; }
    .page { box-shadow: none; margin: 0; padding: 0; }
    .print-btn { display: none; }
    .vuln-card { break-inside: avoid; }
    h2 { break-after: avoid; }
  }
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div>
      <h1>Automated Sentinel Threat Engine™</h1>
      <div class="sub">Comprehensive Vulnerability Assessment Report</div>
    </div>
    <button class="print-btn" onclick="window.print()">Download PDF / Print</button>
  </div>

  <div class="meta-grid">
    <div class="meta-card"><div class="num">\${vulns.length}</div><div class="lbl">Total Vulnerabilities</div></div>
    <div class="meta-card"><div class="num" style="color:#dc2626">\${criticalCount}</div><div class="lbl">Critical Risk</div></div>
    <div class="meta-card"><div class="num" style="color:#ea580c">\${highCount}</div><div class="lbl">High Risk</div></div>
    <div class="meta-card"><div class="num" style="color:#2563eb">\${riskScore}/10</div><div class="lbl">Overall Risk Score</div></div>
  </div>

  <h2>1. Assessment Metadata</h2>
  <table class="info-table">
    <tr><td>Target Assessed</td><td><a href="\${meta.targetValue}" target="_blank">\${meta.targetValue}</a></td></tr>
    <tr><td>Target Classification</td><td><span style="background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-transform: uppercase;">\${meta.tier ?? meta.riskLevel ?? "Standard"}</span></td></tr>
    <tr><td>Assessment Profile</td><td>\${meta.profile}</td></tr>
    <tr><td>Analysis Confidence</td><td>\${meta.confidence}%</td></tr>
    <tr><td>Scan Duration</td><td>\${meta.scanDuration}</td></tr>
    <tr><td>Report Generated On</td><td>\${new Date().toLocaleString()}</td></tr>
  </table>

  <h2>2. Network Reconnaissance & OSINT</h2>
  <table class="info-table">
    \${dnsRows}
    <tr><td>HTTP Reachability</td><td>\${meta.liveChecks ? "<span style='color:#16a34a;font-weight:bold'>Online (Verified)</span>" : "<span style='color:#dc2626;font-weight:bold'>Unreachable</span>"}</td></tr>
    <tr><td>Server Technology (Tech View)</td><td>\${recon.server || "Hidden / Obfuscated"}</td></tr>
    <tr><td>Subdomains Discovered</td><td>\${(recon.subdomains || []).join(", ") || "None discovered in passive scan"}</td></tr>
  </table>

  <h2>3. TCP Port & Service Enumeration</h2>
  <table class="owasp-table">
    <thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Banner / Notes</th></tr></thead>
    <tbody>\${portRows}</tbody>
  </table>

  <h2>4. OWASP Top 10 (2021) Compliance Posture</h2>
  <table class="owasp-table">
    <thead><tr><th>OWASP Category</th><th>Compliance Status</th><th>Findings Count</th><th>Technical Details</th></tr></thead>
    <tbody>\${owaspRows || "<tr><td colspan='4'>No compliance data generated</td></tr>"}</tbody>
  </table>

  <h2>5. Detailed Vulnerability Findings (\${vulns.length})</h2>
  \${vulns.length > 0 ? vulnRows : "<p style='color:#16a34a; font-weight: 600; padding: 20px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px;'>No vulnerabilities discovered. The target currently exhibits a strong security posture against automated checks.</p>"}

  <div class="footer">
    <p><strong>Sentinel Threat Engine™</strong> by VJTI IT Branch Student</p>
    <p>This report contains highly confidential security data. Unauthorized distribution or exploitation is strictly prohibited under the IT Act 2000.</p>
  </div>
</div>
</body>
</html>\`;

    const win = window.open("", "_blank");
    if (!win) {
      alert("Popup blocked. Please allow popups for this site and try again.");
      return;
    }
    win.document.write(html);
    win.document.close();
  }`;

    content = content.substring(0, startIndex) + replacement + content.substring(endIndex + 1);
    fs.writeFileSync(file, content, 'utf8');
    console.log("Successfully replaced handleGenerateReport");
  } else {
    console.log("Could not find end of function");
  }
} else {
  console.log("Could not find start of function");
}
