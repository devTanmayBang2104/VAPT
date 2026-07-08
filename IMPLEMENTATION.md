# Sentinel Threat Engine™ - Hybrid VAPT Framework
**Implementation Documentation**

## 1. Architecture Overview
Sentinel Threat Engine™ is a Hybrid Web Application Vulnerability Assessment & Penetration Testing (VAPT) Framework. It bridges the gap between passive OSINT simulation and active network exploitation.

### 1.1 Tech Stack
- **Frontend Layer:** React.js, Tailwind CSS, Lucide Icons, ShadCN (Presentation, Visualization, and Dashboarding).
- **Backend Layer:** Node.js, Custom Vite Middleware `node:net`, `node:dns`, `node:https` (Active Probing, Network Requests, Proxying).
- **Reporting Engine:** Custom comprehensive HTML/Print pipeline mapped to OWASP standards.

### 1.2 Core Paradigm: The "Hybrid" Model
Most student projects rely entirely on mock data or third-party CLI tools (like Nmap or Nuclei) running via `exec()`. Sentinel avoids heavy external dependencies by implementing native Node.js network protocols to perform **real penetration testing**, while using a fallback heuristic logic to guarantee a rich dashboard experience (Hybrid).

---

## 2. Active Probing Engine (Backend Implementation)
The core feature of this framework is the custom middleware built inside `vite.config.ts`. It securely bypasses CORS restrictions and performs actual network attacks.

### 2.1 TCP Port Scanner (`/api/ports`)
- **Technology:** `node:net`
- **Mechanism:** Creates raw TCP socket connections (`createConnection`) to the target IP address on an array of standard ports (e.g., 80, 443, 22, 3306).
- **Execution:** Uses `Promise.allSettled` to asynchronously ping ports with a strict 2.5s timeout. If the socket triggers a `"connect"` event, the port is flagged as `OPEN`.
- **Banner Grabbing:** Listens to the first chunk of incoming buffer data upon connection to attempt service banner identification.

### 2.2 Active Directory Fuzzing (`/api/fuzz`)
- **Technology:** `node:https` / `node:http`
- **Mechanism:** Initiates high-speed `HTTP HEAD` requests against the target domain, appending a list of commonly vulnerable paths (e.g., `/.env`, `/.git/config`, `/admin`, `/backup.zip`).
- **Detection:** Analyzes the returned HTTP Status Codes. A `200 OK` or `401/403 Forbidden` confirms the file/directory exists, resulting in a Data Exposure finding.

### 2.3 SQL Injection Verifier (`/api/sqli`)
- **Technology:** `node:https`
- **Mechanism:** Bypasses simple heuristic checks by actively firing a raw SQLi payload (`1'`) at a known URL parameter (e.g., `?cat=1'`).
- **Confirmation:** Downloads the raw HTML response body and parses it for active MySQL stack traces (e.g., `mysql_fetch_array()`, `syntax error`). This confirms 100% exploitability without altering the database (Safe Verification).

### 2.4 DNS & HTTP Header Reconnaissance (`/api/dns`, `/api/headers`)
- **Mechanism:** Actively resolves `A`, `MX`, `NS`, and `TXT` records using `node:dns`. Fetches live HTTP response headers to identify missing cryptographic security configurations (HSTS, CSP, X-Frame-Options).

---

## 3. Threat Intelligence Logic (Frontend Implementation)
Located primarily in `src/lib/auditEngine.ts`.

### 3.1 Risk Scoring Algorithm
Findings are mapped to a mathematical weight array:
- **Critical:** 10.0 points
- **High:** 7.5 points
- **Medium:** 5.0 points
- **Low:** 2.5 points

The engine aggregates the weights and applies a normalizing function to output a clean `X/10` Risk Score, ensuring it remains scalable and readable.

### 3.2 OWASP Top 10 (2021) Mapping
Every finding object contains an `owaspCategory` tag (e.g., `A01:2021-Broken Access Control`). The engine groups these tags dynamically and updates the Compliance Dashboard, assigning a boolean Pass/Fail status to each of the 10 pillars.

---

## 4. Reporting Engine
The platform includes an Enterprise-grade HTML Report Generator.
- **Workflow:** When "Generate Report" is clicked, it compiles the state objects (Reconnaissance, Vulnerabilities, OWASP Compliance) into a single, sanitized DOM tree.
- **Data Layers Provided:**
  - Executive Metadata (Scores, Targets, Duration)
  - Reconnaissance Tables (DNS Arrays, Live Ports, Server Banners)
  - Business View (Impact analysis)
  - Technical View (Remediation and payload evidence)
- **Output:** Renders a new browser window natively formatted for `window.print()` / "Save as PDF", mimicking the delivery format of professional cybersecurity firms.

---

## 5. Security & Scope Safety
To ensure the framework is safe for academic environments:
- **Target Tiering:** The engine actively checks if a target is `hardened` (e.g., `google.com`). If it detects a major domain, it skips aggressive fuzzing and SQLi payloads to prevent WAF blocks and illegal exploitation.
- **Non-Destructive Testing:** The SQLi and XSS checks rely exclusively on *Reflected* payload confirmation. No data is modified, `INSERT`, or `DROP` commands are executed.
