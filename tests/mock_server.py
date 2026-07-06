"""
Mock MCP server for testing mcp-hardening-benchmark.

Deliberately implements configurable security misconfigurations
so that specific checks can be tested to produce FAIL results.

Usage:
    python tests/mock_server.py &
    mcp-audit --target http://localhost:15000 --api-key test123

Configuration (MOCK_CONFIG dict below):
    auth_required:  If False, /tools/list and /tools/call return 200 without auth
    hidden_tools:   List of tool names callable but NOT returned in /tools/list
    run_as_root:    If True, error responses include "uid=0" hint
    rate_limit:     If True, return 429 after 10 failed auth attempts
    cors_wildcard:  If True, set Access-Control-Allow-Origin: *
    version_header: If set, add Server header with version string
    env_exposed:    If True, serve a fake /.env file
"""
from __future__ import annotations

from flask import Flask, jsonify, request, Response

app = Flask(__name__)

# ─── Configurable failure modes ───────────────────────────────────────────────
MOCK_CONFIG = {
    "auth_required": True,
    "hidden_tools": ["ops._admin_dump"],   # Callable but NOT in /tools/list
    "run_as_root": True,                   # Simulate root process
    "rate_limit": False,                   # Return 429 on excessive failures
    "cors_wildcard": False,               # Set ACAO: * header
    "version_header": None,               # e.g. "MCPJam/1.4.2" — set Server header
    "env_exposed": False,                 # Serve /.env publicly
}

VALID_API_KEY = "test123"
_failed_auth_count = 0
_RATE_LIMIT_THRESHOLD = 10

# ─── Tool registry ────────────────────────────────────────────────────────────
PUBLIC_TOOLS = [
    {
        "name": "ping",
        "description": "Pings the server",
        "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}},
    },
    {
        "name": "echo",
        "description": "Echoes input back",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    },
]

HIDDEN_TOOL_IMPL = {
    "ops._admin_dump": lambda args: {"status": "ok", "data": "MOCK_ADMIN_DATA", "uid": 0 if MOCK_CONFIG["run_as_root"] else 1000},
}


def _check_auth() -> bool:
    """Return True if request is authenticated."""
    global _failed_auth_count
    if not MOCK_CONFIG["auth_required"]:
        return True
    key = request.headers.get("X-API-Key", "") or request.headers.get("Authorization", "").removeprefix("Bearer ")
    if key == VALID_API_KEY:
        _failed_auth_count = 0
        return True
    _failed_auth_count += 1
    return False


def _add_global_headers(response: Response) -> Response:
    if MOCK_CONFIG["cors_wildcard"]:
        response.headers["Access-Control-Allow-Origin"] = "*"
    if MOCK_CONFIG["version_header"]:
        response.headers["Server"] = MOCK_CONFIG["version_header"]
    return response


@app.after_request
def after_request(response: Response) -> Response:
    return _add_global_headers(response)


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return jsonify({"server": "Mock MCP Server", "version": "1.0.0-test"})


@app.route("/tools/list")
def tools_list():
    global _failed_auth_count
    if MOCK_CONFIG["rate_limit"] and _failed_auth_count >= _RATE_LIMIT_THRESHOLD:
        return jsonify({"error": "Rate limit exceeded"}), 429
    if not _check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"tools": PUBLIC_TOOLS})


@app.route("/tools/call", methods=["POST"])
def tools_call():
    global _failed_auth_count
    if MOCK_CONFIG["rate_limit"] and _failed_auth_count >= _RATE_LIMIT_THRESHOLD:
        return jsonify({"error": "Rate limit exceeded"}), 429
    if not _check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    tool_name = body.get("name", "")
    args = body.get("arguments", {}) or {}

    # Validate input size (returns 400 for oversized)
    if args and any(len(str(v)) > 10000 for v in args.values()):
        return jsonify({"error": "Input too large"}), 400

    # Hidden tools (not in public list but callable)
    if tool_name in MOCK_CONFIG["hidden_tools"]:
        impl = HIDDEN_TOOL_IMPL.get(tool_name)
        if impl:
            result = impl(args)
            if MOCK_CONFIG["run_as_root"]:
                result["process_info"] = "uid=0(root) gid=0(root)"
            return jsonify({"result": result})

    # Public tools
    if tool_name == "ping":
        return jsonify({"result": {"pong": args.get("message", "pong")}})
    if tool_name == "echo":
        return jsonify({"result": {"echo": args.get("text", "")}})

    return jsonify({"error": f"Tool not found: {tool_name}"}), 404


@app.route("/health")
def health():
    body = {"status": "ok", "uptime": 999}
    if MOCK_CONFIG["run_as_root"]:
        body["process"] = "uid=0(root) gid=0(root)"  # Intentionally bad
    return jsonify(body)


@app.route("/.env")
def env_file():
    if MOCK_CONFIG["env_exposed"]:
        return Response(
            "API_KEY=supersecret123\nDB_PASSWORD=hunter2\n",
            content_type="text/plain",
        )
    return jsonify({"error": "Not found"}), 404


@app.route("/sse")
def sse():
    """SSE endpoint — protected by auth in default config."""
    if not _check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    # Minimal SSE response for testing
    return Response("data: {}\n\n", content_type="text/event-stream")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Mock MCP server for benchmark testing")
    parser.add_argument("--port", type=int, default=15000)
    parser.add_argument("--no-auth", action="store_true", help="Disable auth requirement")
    parser.add_argument("--cors-wildcard", action="store_true")
    parser.add_argument("--expose-env", action="store_true")
    parser.add_argument("--version-header", default=None)
    args = parser.parse_args()

    if args.no_auth:
        MOCK_CONFIG["auth_required"] = False
    if args.cors_wildcard:
        MOCK_CONFIG["cors_wildcard"] = True
    if args.expose_env:
        MOCK_CONFIG["env_exposed"] = True
    if args.version_header:
        MOCK_CONFIG["version_header"] = args.version_header

    print(f"[mock-server] Starting on http://localhost:{args.port}")
    print(f"[mock-server] Valid API key: {VALID_API_KEY}")
    print(f"[mock-server] Config: {MOCK_CONFIG}")
    app.run(port=args.port, debug=False)
