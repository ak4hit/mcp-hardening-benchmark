# MCP Server Hardening Benchmark

> **CIS-Style Security Checklist for MCP Server Deployments**
> Author: ak4hit | github.com/ak4hit/mcp-hardening-benchmark

This checklist can be used **without the CLI tool** as a manual security review guide.
Each item maps to a specific vulnerability class observed in real MCP deployments.

---

## How to Use This Checklist

- ✅ **PASS** — Control is implemented correctly
- ❌ **FAIL** — Control is missing or misconfigured — remediation required
- ⚠️ **WARN** — Partially implemented or unverifiable without local access
- ⏭ **SKIP** — Not applicable to this deployment

---

## Category 1 — Authentication

| ID | Check | Method | Expected |
|----|-------|--------|----------|
| 1.1 | Auth enforced on `/tools/list` | GET /tools/list (no key) | 401 |
| 1.2 | Auth enforced on `/tools/call` | POST /tools/call (no key) | 401 |
| 1.3 | No default/blank API key accepted | Try `""`, `admin`, `test` | 401 |
| 1.4 | Auth enforced on all endpoints | Probe /health, /config, /debug | 401/404 |
| 1.5 | Rate limiting on failed auth | 20 failed requests | 429 or block |

---

## Category 2 — Transport Security

| ID | Check | Method | Expected |
|----|-------|--------|----------|
| 2.1 | No unauthenticated SSE endpoint | GET /sse (no key) | 401 |
| 2.2 | TLS enforced if non-localhost | Check URL scheme | https:// |
| 2.3 | CORS not wildcard | Check Access-Control-Allow-Origin | Not `*` |
| 2.4 | No debug port exposed publicly | TCP probe 6274, 6277 | Not reachable |

---

## Category 3 — Tool Exposure

| ID | Check | Method | Expected |
|----|-------|--------|----------|
| 3.1 | No hidden callable tools | POST /tools/call with wordlist | 404 for all |
| 3.2 | Dangerous tool names absent | Check /tools/list names | No admin/dump/exec/shell |
| 3.3 | Tool inputs validated | Send oversized/null arguments | 400, not 500 |
| 3.4 | Tool list doesn't leak paths | Parse tool descriptions | No /home/, /root/, secrets |
| 3.5 | No tool executes shell commands | Shell metachar payloads | No uid= in response |

---

## Category 4 — Process Isolation

| ID | Check | Method | Expected |
|----|-------|--------|----------|
| 4.1 | Server not running as root | HTTP error heuristic / ps aux | No uid=0 |
| 4.2 | Dedicated service user exists | `grep -i mcp /etc/passwd` | mcp-server user exists |
| 4.3 | NoNewPrivileges in systemd | `grep NoNewPrivileges /etc/systemd/...` | yes |
| 4.4 | Filesystem access restricted | `grep ReadOnlyPaths /etc/systemd/...` | Configured |

---

## Category 5 — Secret Management

| ID | Check | Method | Expected |
|----|-------|--------|----------|
| 5.1 | No secrets in tool descriptions | Parse /tools/list | No tokens/passwords |
| 5.2 | No secrets in error responses | Trigger errors | No credentials in body |
| 5.3 | API key not echoed in headers | Check response headers | Key not present |
| 5.4 | No .env file accessible | GET /.env, /app/.env | 404 |

---

## Category 6 — Logging & Monitoring

| ID | Check | Method | Expected |
|----|-------|--------|----------|
| 6.1 | Tool calls produce log output | Make call, check syslog | Log entry present |
| 6.2 | Auth failures logged | Send bad key, check logs | Failure logged |
| 6.3 | /health doesn't expose internals | Parse /health body | No paths/credentials |
| 6.4 | Server version not in headers | Check Server: header | No version string |

---

## Category 7 — Network Controls

| ID | Check | Method | Expected |
|----|-------|--------|----------|
| 7.1 | Management port not public | TCP probe 6274, 6277 | Not reachable |
| 7.2 | Binds to expected interface | `netstat -tlnp` | Not 0.0.0.0 |
| 7.3 | No unexpected MCP ports | Port scan 5000,6274,6277,8888 | Only expected |

---

*MCP Server Hardening Benchmark · ak4hit · MIT License*
