import path from "path";
import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react-swc";
import { tempo } from "tempo-devtools/dist/vite";
import type { IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";

// ── Helper: one-shot JSON responder with double-send guard ─────────────────────
function makeResponder(res: any) {
  let sent = false;
  return (status: number, data: object) => {
    if (sent) return;
    sent = true;
    res.writeHead(status, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify(data));
  };
}

// ── /api/audit?url=<url>  ── real HTTPS HEAD for header analysis ───────────────
function auditHeaderPlugin(): Plugin {
  return {
    name: "vapt-audit-headers",
    configureServer(server) {
      server.middlewares.use("/api/audit", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const rawUrl = params.get("url");
        const send = makeResponder(res);

        if (!rawUrl) return send(400, { reachable: false, error: "Missing url", headers: {} });

        let targetUrl: URL;
        try { targetUrl = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`); }
        catch { return send(400, { reachable: false, error: "Invalid URL", headers: {} }); }

        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        fetch(targetUrl.href, {
          method: "GET",
          redirect: "follow",
          headers: { "User-Agent": "VAPT-Framework/1.0 (Educational Security Scanner)", Accept: "*/*" }
        })
        .then(async (response) => {
          try { if (response.body && typeof response.body.cancel === 'function') await response.body.cancel(); } catch(e){}
          const hdrs: Record<string, string> = {};
          response.headers.forEach((value, key) => { hdrs[key.toLowerCase()] = value; });
          
          send(200, {
            reachable: true, statusCode: response.status, headers: hdrs,
            server: hdrs["server"] ?? null, poweredBy: hdrs["x-powered-by"] ?? null,
          });
        })
        .catch((e: Error) => send(503, { reachable: false, error: e.message, headers: {} }));
      });
    },
  };
}

// ── /api/dns?hostname=<hostname>  ── real DNS resolution via Node dns module ───
function auditDNSPlugin(): Plugin {
  return {
    name: "vapt-audit-dns",
    configureServer(server) {
      server.middlewares.use("/api/dns", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const hostname = params.get("hostname");
        const send = makeResponder(res);
        if (!hostname) return send(400, { error: "Missing hostname" });

        import("node:dns/promises").then(async (dns) => {
          const result: Record<string, any> = {};
          await Promise.allSettled([
            dns.resolve4(hostname).then(a => { result.A = a; }).catch(() => {}),
            dns.resolveMx(hostname).then(m => { result.MX = m.map((r: any) => `${r.priority} ${r.exchange}`); }).catch(() => {}),
            dns.resolveNs(hostname).then(n => { result.NS = n; }).catch(() => {}),
            dns.resolveTxt(hostname).then(t => { result.TXT = t.flat(); }).catch(() => {}),
            dns.resolveCname(hostname).then(c => { result.CNAME = c; }).catch(() => {}),
            dns.resolveTxt(`_dmarc.${hostname}`).then(t => { result.DMARC = t.flat(); }).catch(() => {}),
          ]);
          
          console.log(`\x1b[36m[DNS Recon]\x1b[0m Resolved ${hostname}: \x1b[32m${result.A ? result.A.join(", ") : "No A records"}\x1b[0m`);
          send(200, { hostname, records: result });
        }).catch((e: Error) => send(500, { error: e.message }));
      });
    },
  };
}

// ── /api/ports?hostname=<hostname>&ports=<csv>  ── TCP port probe via net ───────
function auditPortPlugin(): Plugin {
  return {
    name: "vapt-audit-ports",
    configureServer(server) {
      server.middlewares.use("/api/ports", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const hostname = params.get("hostname");
        const portsParam = params.get("ports") ?? "80,443,22,21,25,8080,8443,3306,5432,6379,27017";
        const send = makeResponder(res);
        if (!hostname) return send(400, { error: "Missing hostname" });

        const ports = portsParam.split(",").map(Number).filter(n => n > 0 && n < 65536).slice(0, 30);

        import("node:net").then(({ createConnection }) => {
          const results: { port: number; open: boolean; banner?: string }[] = [];
          let done = 0;

          for (const port of ports) {
            const sock = createConnection({ host: hostname, port, timeout: 2500 });
            let banner = "";

            sock.once("connect", () => {
              results.push({ port, open: true, banner: banner.trim() || undefined });
              console.log(`\x1b[32m[+] PORT OPEN:\x1b[0m ${hostname}:${port}/tcp`);
              sock.destroy();
              if (++done === ports.length) send(200, { hostname, results });
            });
            sock.once("data", (d: Buffer) => { banner = d.toString("utf8", 0, 80).trim(); });
            sock.once("timeout", () => {
              sock.destroy();
              results.push({ port, open: false });
              if (++done === ports.length) send(200, { hostname, results });
            });
            sock.once("error", () => {
              results.push({ port, open: false });
              if (++done === ports.length) send(200, { hostname, results });
            });
          }
        }).catch((e: Error) => send(500, { error: e.message }));
      });
    },
  };
}

// ── /api/fuzz?url=<url>&paths=<csv>  ── Real directory fuzzing ───────────────────
function auditFuzzPlugin(): Plugin {
  return {
    name: "vapt-audit-fuzz",
    configureServer(server) {
      server.middlewares.use("/api/fuzz", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const rawUrl = params.get("url");
        const pathsParam = params.get("paths") ?? "/admin,/login,/.git/config,/.env,/backup.zip";
        const send = makeResponder(res);

        if (!rawUrl) return send(400, { error: "Missing url" });
        const targetUrl = rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`;
        const paths = pathsParam.split(",").filter(Boolean);

        import("node:https").then((https) => {
          import("node:http").then((http) => {
            const results: { path: string; status: number; verified?: boolean }[] = [];
            let done = 0;
            const u = new URL(targetUrl);
            const client = u.protocol === "http:" ? http : https;

            for (const p of paths) {
              const reqUrl = new URL(p.startsWith('/') ? p : `/${p}`, targetUrl);
              const requestOptions: RequestOptions = {
                method: "GET",
                timeout: 5000,
                rejectUnauthorized: false
              };
              
              const request = client.request(reqUrl, requestOptions, (response) => {
                let body = "";
                let verified: boolean | undefined = undefined;
                const isTarget = (p === "/.env" || p === "/.git/config" || p === "/server-status");
                
                response.on("data", (chunk) => {
                  if (body.length < 16384) {
                    body += chunk.toString();
                  } else if (isTarget) {
                    response.destroy();
                  }
                });

                let checked = false;
                const checkContent = () => {
                  if (checked) return;
                  checked = true;
                  
                  if (response.statusCode === 200 && isTarget) {
                    verified = false;
                    if (p === "/.env" && (body.includes("DB_PASSWORD") || body.includes("SECRET_KEY") || body.includes("API_KEY"))) {
                      verified = true;
                    } else if (p === "/.git/config" && (body.includes("[core]") || body.includes("repositoryformatversion"))) {
                      verified = true;
                    } else if (p === "/server-status" && (body.includes("Apache Status") || body.includes("Server uptime"))) {
                      verified = true;
                    }
                  }

                  if (response.statusCode === 200 && (verified === true || !isTarget)) {
                    console.log(`\x1b[33m[FUZZ HIT]\x1b[0m Discovered sensitive endpoint: \x1b[31m${targetUrl}${p}\x1b[0m (HTTP 200)`);
                  }
                  
                  results.push({ path: p, status: response.statusCode || 0, verified });
                  if (++done === paths.length) send(200, { url: targetUrl, results });
                };

                response.on("end", checkContent);
                response.on("close", checkContent);
              });

              request.on("error", () => {
                results.push({ path: p, status: 0 });
                if (++done === paths.length) send(200, { url: targetUrl, results });
              });

              request.on("timeout", () => {
                request.destroy();
              });

              request.end();
            }
          });
        }).catch((e: Error) => send(500, { error: e.message }));
      });
    },
  };
}

// ── /api/sqli?url=<url>  ── Real Active SQL Injection Probe ────────────────────
function auditSqliPlugin(): Plugin {
  return {
    name: "vapt-audit-sqli",
    configureServer(server) {
      server.middlewares.use("/api/sqli", (req, res) => {
        const params = new URLSearchParams(req.url?.split("?")[1] ?? "");
        const rawUrl = params.get("url");
        const send = makeResponder(res);

        if (!rawUrl) return send(400, { error: "Missing url" });
        const targetUrl = rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`;

        import("node:https").then((https) => {
          import("node:http").then((http) => {
            const u = new URL(targetUrl);
            const client = u.protocol === "http:" ? http : https;
            
            const payload = "1' OR '1'='1";
            const reqUrl = new URL(targetUrl);
            const isLogin = reqUrl.pathname.toLowerCase().includes("login");
            
            if (!isLogin) {
              reqUrl.searchParams.set("id", "1'");
              reqUrl.searchParams.set("cat", "1'");
            }
            
            const postData = isLogin ? `username=admin' OR 1=1 --&password=invalid` : "";
            const requestOptions: RequestOptions = { 
              method: isLogin ? "POST" : "GET", 
              timeout: 4000, 
              rejectUnauthorized: false,
              headers: isLogin ? { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(postData) } : {}
            };
            
            console.log(`\x1b[35m[ATTACK]\x1b[0m Firing SQLi payload at: \x1b[31m${reqUrl.href}\x1b[0m`);

            const request = client.request(reqUrl, requestOptions, (response) => {
              let body = "";
              response.on("data", (chunk) => { body += chunk.toString(); });
              response.on("end", () => {
                const isVuln = body.includes("mysql_fetch_array()") || body.includes("You have an error in your SQL syntax");
                if (isVuln) {
                  console.log(`\x1b[41m\x1b[37m[EXPLOIT SUCCESS]\x1b[0m SQL Injection confirmed at ${targetUrl}`);
                } else {
                  console.log(`\x1b[36m[SAFE]\x1b[0m SQLi payload blocked or failed at ${targetUrl}`);
                }
                send(200, { url: targetUrl, vulnerable: isVuln, payload: "1'", endpoint: reqUrl.pathname });
              });
            });

            request.on("error", () => send(200, { url: targetUrl, vulnerable: false }));
            request.on("timeout", () => request.destroy());
            if (isLogin) request.write(postData);
            request.end();
          });
        }).catch((e: Error) => send(500, { error: e.message }));
      });
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  base: process.env.NODE_ENV === "development" ? "/" : process.env.VITE_BASE_PATH || "/",
  optimizeDeps: { entries: ["src/main.tsx", "src/tempobook/**/*"] },
  plugins: [
    react(),
    tempo(),
    auditHeaderPlugin(),
    auditDNSPlugin(),
    auditPortPlugin(),
    auditFuzzPlugin(),
    auditSqliPlugin(),
  ],
  resolve: {
    preserveSymlinks: true,
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    // @ts-ignore
    allowedHosts: true,
  },
});
