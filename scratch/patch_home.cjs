const fs = require('fs');
const file = 'src/components/home.tsx';
let content = fs.readFileSync(file, 'utf8');

// 1. Add import
if (!content.includes('generateProfessionalReport')) {
  content = content.replace(
    'import { runAudit } from "@/lib/auditEngine";',
    'import { runAudit } from "@/lib/auditEngine";\nimport { generateProfessionalReport } from "@/lib/reportGenerator";'
  );
}

// 2. Replace handleGenerateReport
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
    const riskScore = meta.riskScore ?? 0;

    // Trigger true professional PDF generation
    generateProfessionalReport(
      meta.targetValue || "Unknown Target",
      vulns,
      riskScore,
      scanResults.liveResult
    );
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
