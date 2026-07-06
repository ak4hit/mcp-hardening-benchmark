# mcp-hardening-benchmark

> **CIS-Style Security Audit Tool for MCP Server Deployments**

A CLI tool that connects to a live MCP server, probes it across 7 security categories, scores it, and outputs a detailed report — pass/fail per check, overall score, and remediation advice. Every check maps directly to a vulnerability class seen in real MCP deployments.

---

## Real-World Basis

Every check in this tool is grounded in real vulnerabilities observed in MCP server deployments — including:
- Hidden callable tools not shown in `/tools/list` (e.g. `ops._admin_dump`)
- Servers running as `uid=0` (root)
- Plaintext API tokens visible in process command-line arguments
- Unauthenticated inspector ports exposed to the internet (ports 6274/6277)
- SSE endpoints with no authentication (CVE-2025-49596)

---

## Install

```bash
git clone https://github.com/ak4hit/mcp-hardening-benchmark.git
cd mcp-hardening-benchmark
pip install .
```

---

## Usage

### Interactive mode (recommended for first use)
```bash
mcp-audit
```
Prompts for all options with sensible defaults.

### Non-interactive / CI mode
```bash
mcp-audit --target http://localhost:5000 --api-key <key>
```

### All flags
```bash
# Bearer token auth
mcp-audit --target http://localhost:5000 --api-key <token> --auth-type bearer

# Hardened profile (all 28 checks)
mcp-audit --target http://localhost:5000 --api-key <key> --profile level2

# JSON report
mcp-audit --target http://localhost:5000 --api-key <key> --json --output report.json

# HTML report (self-contained, offline-safe)
mcp-audit --target http://localhost:5000 --api-key <key> --html --output report.html

# SARIF report (GitHub Code Scanning)
mcp-audit --target http://localhost:5000 --api-key <key> --sarif --output results.sarif

# Single category
mcp-audit --target http://localhost:5000 --api-key <key> --category tools

# Passive mode (no /tools/call probes — read-only)
mcp-audit --target http://localhost:5000 --api-key <key> --passive

# CI gate — exit 1 if score below threshold
mcp-audit --target http://localhost:5000 --api-key <key> --min-score 80

# Verbose — show remediation for all checks
mcp-audit --target http://localhost:5000 --api-key <key> --verbose

# List all checks and exit
mcp-audit --list-checks
```

---

## Check Categories

### Category 1 — Authentication (5 checks)
| ID | Description |
|----|-------------|
| 1.1 | Auth enforced on /tools/list |
| 1.2 | Auth enforced on /tools/call |
| 1.3 | No default/blank API key accepted |
| 1.4 | Auth enforced on all discovered endpoints |
| 1.5 | Rate limiting on failed auth |

### Category 2 — Transport Security (4 checks)
| ID | Description |
|----|-------------|
| 2.1 | No unauthenticated SSE endpoint |
| 2.2 | TLS enforced if non-localhost |
| 2.3 | CORS policy not wildcard |
| 2.4 | No debug/inspector port exposed publicly |

### Category 3 — Tool Exposure (5 checks)
| ID | Description |
|----|-------------|
| 3.1 | No hidden callable tools (brute-force wordlist) |
| 3.2 | Dangerous tool names absent |
| 3.3 | Tool inputs validated |
| 3.4 | Tool list doesn't leak paths |
| 3.5 | No tool executes shell commands |

### Category 4 — Process Isolation (4 checks)
| ID | Description |
|----|-------------|
| 4.1 | Server not running as root (HTTP heuristic) |
| 4.2 | Dedicated service user exists (local) |
| 4.3 | NoNewPrivileges set in systemd (local) |
| 4.4 | Filesystem access restricted (local) |

### Category 5 — Secret Management (4 checks)
| ID | Description |
|----|-------------|
| 5.1 | No secrets in tool descriptions |
| 5.2 | No secrets in error responses |
| 5.3 | API key not echoed in server headers |
| 5.4 | No .env file accessible |

### Category 6 — Logging & Monitoring (4 checks)
| ID | Description |
|----|-------------|
| 6.1 | Tool calls produce log output (local) |
| 6.2 | Auth failures logged (local) |
| 6.3 | /health endpoint doesn't expose internals |
| 6.4 | Server version not exposed in headers |

### Category 7 — Network Controls (3 checks)
| ID | Description |
|----|-------------|
| 7.1 | Management port not publicly bound |
| 7.2 | Server listens on expected interface (local) |
| 7.3 | No other MCP-related ports exposed |

---

## Profiles

| Profile | Checks | Purpose |
|---------|--------|---------|
| `level1` (default) | 14 critical checks | Minimum security baseline — every MCP deployment must pass |
| `level2` | All 28 checks | Hardened production profile |

---

## Sample Output

```text
+-------------------- MCP Server Hardening Benchmark v1.0 --------------------+
|  Target : http://127.0.0.1:15000                                            |
|  Profile: Level 1 (Basic)                                                   |
+-----------------------------------------------------------------------------+

[~] Fingerprinting...
[~] Framework : Flask
[~] Version   : v1.0.0
[+] No CVEs matched for detected framework/version

Running audit...
--------------------------------------------------


Authentication
  [PASS] 1.1  Auth enforced on /tools/list
  [PASS] 1.2  Auth enforced on /tools/call
  [PASS] 1.3  No default/blank API key accepted
  [FAIL] 1.4  Auth enforced on all discovered endpoints
         Unprotected endpoints found (200 without auth): /health
         -> Fix: Apply authentication middleware to all exposed endpoints, 
including health/debug/admin routes.
  [WARN] 1.5  Rate limiting on failed auth

Transport Security
  [PASS] 2.1  No unauthenticated SSE endpoint
  [SKIP] 2.2  TLS enforced if non-localhost
  [PASS] 2.3  CORS policy configured
  [SKIP] 2.4  No debug/inspector port exposed publicly

Tool Exposure
  [FAIL] 3.1  No hidden callable tools
         Hidden tool(s) responded (not 404): ops._admin_dump
         -> Fix: Remove all unlisted/hidden tools or gate them behind a 
separate elevated auth mechanism.
  [PASS] 3.2  Dangerous tool names absent
  [PASS] 3.3  Tool inputs validated
  [PASS] 3.4  Tool list doesn't leak paths
  [PASS] 3.5  No tool executes shell commands

Process Isolation
  [FAIL] 4.1  Server not running as root
         Root execution indicators found in HTTP responses: /health: 'uid=0'
         -> Fix: Run the MCP server as a dedicated non-root service user. Never
run production services as uid=0.
  [SKIP] 4.2  Dedicated service user exists
  [SKIP] 4.3  NoNewPrivileges set in systemd
  [SKIP] 4.4  Filesystem access restricted

Secret Management
  [PASS] 5.1  No secrets in tool descriptions
  [PASS] 5.2  No secrets in error responses
  [PASS] 5.3  API key not in server headers
  [PASS] 5.4  No .env file accessible

Logging & Monitoring
  [SKIP] 6.1  Tool calls produce log output
  [SKIP] 6.2  Auth failures logged
  [FAIL] 6.3  /health endpoint does not expose internals
         /health response contains internal information: 'uid=0'
         -> Fix: Sanitize /health endpoint output. It should return only: 
status (ok/degraded) and uptime. Remove all internal paths, credentials, and 
version strings.
  [FAIL] 6.4  Server version not exposed in headers
         Version strings found in headers: Server: Werkzeug/3.1.8 Python/3.14.4
         -> Fix: Configure your web server to suppress version information from
headers (e.g., server_tokens off in Nginx).

Network Controls
  [SKIP] 7.1  Management port not publicly bound
  [SKIP] 7.2  Server listens on expected interface only
  [SKIP] 7.3  No other MCP-related ports exposed

--------------------------------------------------
Score   : 8 / 12   (67%)
Profile : Level 1 - [FAIL] FAIL
--------------------------------------------------
```

---

## Contributing — Adding New Checks

1. Add your check function to the appropriate `mcp_benchmark/checks/*.py` file
2. Follow the signature: `def check_N_N(target, api_key, headers) -> CheckResult`
3. Set `.check_id`, `.category`, `.description` as function attributes
4. Register it in `mcp_benchmark/core/runner.py` under `_CATEGORY_MAP` and `_ALL_CHECKS`
5. Add the check ID to the appropriate profile set in `mcp_benchmark/core/scorer.py`
6. Write a test in `tests/`

---

## Use the Checklist Without the Tool

The human-readable benchmark checklist is available as a standalone document:

**[benchmark/MCP-Benchmark-v1.0.md](benchmark/MCP-Benchmark-v1.0.md)**

---

## License

MIT — see [LICENSE](LICENSE)

---

*mcp-hardening-benchmark · ak4hit · Defensive Security / Blue Team*
