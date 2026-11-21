"""Zero-dependency Streamable HTTP / JSON-RPC 2.0 MCP Reverse Proxy (`glassbox proxy-http`).

Guards remote SaaS or local HTTP MCP servers with the exact same dynamic taint lattice,
MCP tool-annotation classification, SHA-256 schema pinning, SHADOW_SIMULATE forensic
capture, and Merkle-chained `.gbx` flight recorder as stdio `glassbox wrap`.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from glassbox.demo_server import _base_tools, _execute_tool
from glassbox.lattice import Action, PolicyConfig, TaintLattice
from glassbox.ledger import MerkleLedger, hash_tool_schema


class HTTPProxyCore:
    """Stateful JSON-RPC 2.0 HTTP interceptor shared across requests in a session."""

    def __init__(
        self,
        upstream_url: str,
        *,
        policy: PolicyConfig | None = None,
        trace_path: Path | None = None,
        quiet: bool = False,
    ) -> None:
        self.upstream_url = upstream_url
        self.policy = policy or PolicyConfig.preset("balanced")
        self.lattice = TaintLattice(policy=self.policy)
        default_dir = Path(".glassbox") / "traces"
        self.trace_path = trace_path or (default_dir / f"http-session-{int(time.time())}.gbx")
        self.ledger = MerkleLedger(self.trace_path, policy_name=self.policy.name)
        self.pinned_schemas: dict[str, str] = {}
        self.drifted_tools: set[str] = set()
        self.quiet = quiet

    def _log(self, msg: str) -> None:
        if not self.quiet:
            sys.stderr.write(f"[glassbox-http] {msg}\n")
            sys.stderr.flush()

    def _forward_upstream(self, msg: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        payload = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        req_headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if headers:
            for k, v in headers.items():
                if k.lower() in ("authorization", "x-api-key", "mcp-session-id"):
                    req_headers[k] = v
        req = urllib.request.Request(self.upstream_url, data=payload, headers=req_headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw)

    def handle_jsonrpc(self, msg: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        method = msg.get("method", "")
        msg_id = msg.get("id")
        t0 = time.perf_counter()

        if method == "tools/list":
            resp = self._forward_upstream(msg, headers)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            for tool in resp.get("result", {}).get("tools", []):
                name = str(tool.get("name", ""))
                if not name:
                    continue
                self.lattice.register_tool_annotations(name, tool.get("annotations"))
                digest = hash_tool_schema(tool)
                if name not in self.pinned_schemas:
                    self.pinned_schemas[name] = digest
                    self.ledger.append(
                        event_type="schema_pin",
                        tool_name=name,
                        arguments={"description": tool.get("description", ""), "annotations": tool.get("annotations", {})},
                        schema_hash=digest,
                        action=Action.ALLOW.value,
                        rule_triggered="SCHEMA_PINNED",
                        reason=f"Pinned initial SHA-256 schema for HTTP MCP tool '{name}'.",
                        taint_before=self.lattice.snapshot(),
                        taint_after=self.lattice.snapshot(),
                        tool_classification=["SCHEMA_PIN"],
                        risk_score=0,
                        latency_ms=latency_ms,
                        response={"pinned_sha256": digest},
                    )
                elif self.pinned_schemas[name] != digest:
                    self.drifted_tools.add(name)
                    self.ledger.append(
                        event_type="schema_drift",
                        tool_name=name,
                        arguments={"expected_sha256": self.pinned_schemas[name], "observed_sha256": digest},
                        schema_hash=digest,
                        action=self.policy.on_schema_drift.value,
                        rule_triggered="SCHEMA_DRIFT_RUGPULL",
                        reason=f"HTTP MCP tool '{name}' schema mutated mid-session!",
                        taint_before=self.lattice.snapshot(),
                        taint_after=self.lattice.snapshot(),
                        tool_classification=["SCHEMA_DRIFT"],
                        risk_score=98,
                        latency_ms=latency_ms,
                        response={"alert": "MCPoison / rug-pull schema mutation detected"},
                    )
            return resp

        if method == "tools/call":
            params = msg.get("params", {}) or {}
            tool_name = str(params.get("name", ""))
            arguments = dict(params.get("arguments", {}) or {})
            schema_hash = self.pinned_schemas.get(tool_name, "")
            schema_drifted = tool_name in self.drifted_tools
            decision = self.lattice.evaluate_pre_call(tool_name, arguments, schema_drifted=schema_drifted)

            if decision.action == Action.ALLOW:
                resp = self._forward_upstream(msg, headers)
                latency_ms = (time.perf_counter() - t0) * 1000.0
                result_payload = resp.get("result", resp)
                taint_after = self.lattice.observe_response(tool_name, result_payload)
                self.ledger.append(
                    event_type="tool_call",
                    tool_name=tool_name,
                    arguments=arguments,
                    schema_hash=schema_hash,
                    action=Action.ALLOW.value,
                    rule_triggered=decision.rule_triggered,
                    reason=decision.reason,
                    taint_before=decision.taint_before,
                    taint_after=taint_after,
                    tool_classification=decision.tool_classification,
                    risk_score=decision.risk_score,
                    latency_ms=latency_ms,
                    response=result_payload,
                )
                return resp

            if decision.action == Action.SHADOW_SIMULATE:
                latency_ms = (time.perf_counter() - t0) * 1000.0
                shadow = decision.shadow_response or {}
                self.ledger.append(
                    event_type="tool_call",
                    tool_name=tool_name,
                    arguments=arguments,
                    schema_hash=schema_hash,
                    action=Action.SHADOW_SIMULATE.value,
                    rule_triggered=decision.rule_triggered,
                    reason=decision.reason,
                    taint_before=decision.taint_before,
                    taint_after=decision.taint_after,
                    tool_classification=decision.tool_classification,
                    risk_score=decision.risk_score,
                    latency_ms=latency_ms,
                    response=shadow,
                )
                self._log(f"SHADOW_SIMULATE [{decision.rule_triggered}] intercepted '{tool_name}'")
                return {"jsonrpc": "2.0", "id": msg_id, "result": shadow}

            latency_ms = (time.perf_counter() - t0) * 1000.0
            err_payload = {
                "code": -32001,
                "message": f"[GLASSBOX BLOCKED :: {decision.rule_triggered}] {decision.reason}",
            }
            self.ledger.append(
                event_type="tool_call",
                tool_name=tool_name,
                arguments=arguments,
                schema_hash=schema_hash,
                action=Action.BLOCK.value,
                rule_triggered=decision.rule_triggered,
                reason=decision.reason,
                taint_before=decision.taint_before,
                taint_after=decision.taint_after,
                tool_classification=decision.tool_classification,
                risk_score=decision.risk_score,
                latency_ms=latency_ms,
                response={"error": err_payload},
            )
            self._log(f"BLOCKED [{decision.rule_triggered}] '{tool_name}'")
            return {"jsonrpc": "2.0", "id": msg_id, "error": err_payload}

        return self._forward_upstream(msg, headers)


def make_http_proxy_handler(core: HTTPProxyCore) -> type[BaseHTTPRequestHandler]:
    class ProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            try:
                msg = json.loads(raw)
                resp = core.handle_jsonrpc(msg, headers=dict(self.headers.items()))
                status = 200
            except Exception as exc:
                resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(exc)}}
                status = 502
            body = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ProxyHandler


def make_demo_http_mcp_handler() -> type[BaseHTTPRequestHandler]:
    """Built-in Streamable HTTP MCP test server (includes MCP annotations on custom tools)."""

    class DemoHTTPMCPHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            msg = json.loads(self.rfile.read(length).decode("utf-8"))
            method = msg.get("method", "")
            msg_id = msg.get("id")
            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "serverInfo": {"name": "glassbox-demo-http-mcp", "version": "0.2.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            elif method == "tools/list":
                tools = _base_tools(mutated=False)
                # Add a custom-named tool with ONLY MCP annotations (no regex match!)
                tools.append(
                    {
                        "name": "acme_custom_relay",
                        "description": "Custom enterprise relay endpoint.",
                        "annotations": {"readOnlyHint": False, "openWorldHint": True, "destructiveHint": False},
                        "inputSchema": {"type": "object", "properties": {"payload": {"type": "string"}}},
                    }
                )
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools}}
            elif method == "tools/call":
                params = msg.get("params", {}) or {}
                name = str(params.get("name", ""))
                args = dict(params.get("arguments", {}) or {})
                if name == "acme_custom_relay":
                    result = {"content": [{"type": "text", "text": f"Relayed {len(str(args))} bytes"}], "isError": False}
                else:
                    result = _execute_tool(name, args)
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": result}
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"ok": True}}

            body = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DemoHTTPMCPHandler


def serve_http_proxy(
    upstream_url: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    policy: PolicyConfig | None = None,
    trace_path: Path | None = None,
    quiet: bool = False,
) -> int:
    core = HTTPProxyCore(upstream_url, policy=policy, trace_path=trace_path, quiet=quiet)
    server = ThreadingHTTPServer((host, port), make_http_proxy_handler(core))
    if not quiet:
        print(f"GlassBox Streamable HTTP MCP Proxy listening on http://{host}:{port} -> {upstream_url}")
        print(f"Policy: {core.policy.name} | Trace: {core.trace_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
