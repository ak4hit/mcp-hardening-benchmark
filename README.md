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

```
╔══════════════════════════════════════════════════════╗
║   MCP Server Hardening Benchmark v1.0                ║
║   Target : http://localhost:15000                    ║
║   Profile: Level 1 (Basic)                          ║
╚══════════════════════════════════════════════════════╝

[~] Fingerprinting...
[~] Framework : MCPJam Inspector
[~] Version   : v1.4.2
[!] CVE-2026-23744  CRITICAL (CVSS 9.8) — Unauthenticated RCE via stdio proxy
    → https://github.com/InzegoSec/CVE-2026-23744

Running audit...
──────────────────────────────────────────────────

Authentication
  [PASS] 1.1  Auth enforced on /tools/list
  [FAIL] 1.3  Blank API key accepted — server returned 200

Tool Exposure
  [FAIL] 3.1  Hidden tool detected: ops._admin_dump
  [FAIL] 3.2  Dangerous tool name matched: *dump*

Process Isolation
  [FAIL] 4.1  Server appears to run as root (uid=0 in error response)

──────────────────────────────────────────────────
Score   : 11 / 17   (64%)
Profile : Level 1 — ❌ FAIL
──────────────────────────────────────────────────
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
