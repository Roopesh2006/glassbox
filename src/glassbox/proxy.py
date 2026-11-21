"""Real stdio JSON-RPC 2.0 MCP Wire Proxy (`glassbox wrap -- <server_cmd>`).

Sits transparently between any MCP client (Claude Code, Cursor, Codex CLI, Windsurf,
OpenClaw, Hermes) and any stdio MCP server. Intercepts:
  - `tools/list` responses -> registers MCP tool annotations + pins SHA-256 schema hash; detects mid-session rug-pulls.
  - `tools/call` requests  -> evaluates dynamic 3-bit taint lattice + schema pin before forwarding.
     * ALLOW           -> forwards to downstream MCP server, observes response for leaked secrets, records Merkle entry.
     * SHADOW_SIMULATE -> suppresses real side effect, returns synthetic dry-run receipt, captures payload forensically.
     * BLOCK           -> returns JSON-RPC error (-32001) directly to agent, never touches downstream server.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from glassbox.lattice import Action, PolicyConfig, TaintLattice
from glassbox.ledger import MerkleLedger, hash_tool_schema


class MCPWireProxy:
    """Synchronous line-delimited JSON-RPC 2.0 MCP stdio proxy."""

    def __init__(
        self,
        command: list[str],
        *,
        policy: PolicyConfig | None = None,
        trace_path: Path | None = None,
        quiet: bool = False,
    ) -> None:
        if not command:
            raise ValueError("No downstream MCP server command provided.")
        self.command = command
        self.policy = policy or PolicyConfig.preset("balanced")
        self.lattice = TaintLattice(policy=self.policy)
        default_dir = Path(".glassbox") / "traces"
        self.trace_path = trace_path or (default_dir / f"session-{int(time.time())}.gbx")
        self.ledger = MerkleLedger(self.trace_path, policy_name=self.policy.name)
        self.pinned_schemas: dict[str, str] = {}
        self.drifted_tools: set[str] = set()
        self.quiet = quiet
        self.proc: subprocess.Popen[str] | None = None

    def _log(self, msg: str) -> None:
        if not self.quiet:
            sys.stderr.write(f"[glassbox] {msg}\n")
            sys.stderr.flush()

    def start_downstream(self) -> None:
        self.proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

    def stop_downstream(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()
            self.proc.wait(timeout=2)
        finally:
            if self.proc.stdout and not self.proc.stdout.closed:
                self.proc.stdout.close()
            self.proc = None

    def _forward_and_read(self, msg: dict[str, Any], expect_response: bool = True) -> dict[str, Any] | None:
        assert self.proc is not None and self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        if not expect_response:
            return None
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line)

    def _handle_tools_list_response(self, resp: dict[str, Any], latency_ms: float) -> dict[str, Any]:
        tools = resp.get("result", {}).get("tools", [])
        for tool in tools:
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
                    reason=f"Pinned initial SHA-256 schema for '{name}'.",
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
                    reason=f"Tool '{name}' schema mutated mid-session! Expected {self.pinned_schemas[name][:12]}, got {digest[:12]}.",
                    taint_before=self.lattice.snapshot(),
                    taint_after=self.lattice.snapshot(),
                    tool_classification=["SCHEMA_DRIFT"],
                    risk_score=98,
                    latency_ms=latency_ms,
                    response={"alert": "MCPoison / rug-pull schema mutation detected"},
                )
                self._log(f"ALERT: Tool '{name}' schema mutated mid-session (rug-pull detected)!")
        return resp

    def handle_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method", "")
        msg_id = msg.get("id")
        is_notification = "id" not in msg

        t0 = time.perf_counter()

        if is_notification:
            self._forward_and_read(msg, expect_response=False)
            return None

        if method == "tools/list":
            resp = self._forward_and_read(msg, expect_response=True)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            if resp is not None:
                return self._handle_tools_list_response(resp, latency_ms)
            return None

        if method == "tools/call":
            params = msg.get("params", {}) or {}
            tool_name = str(params.get("name", ""))
            arguments = dict(params.get("arguments", {}) or {})
            schema_hash = self.pinned_schemas.get(tool_name, "")
            schema_drifted = tool_name in self.drifted_tools

            decision = self.lattice.evaluate_pre_call(
                tool_name,
                arguments,
                schema_drifted=schema_drifted,
            )

            if decision.action == Action.ALLOW:
                resp = self._forward_and_read(msg, expect_response=True)
                latency_ms = (time.perf_counter() - t0) * 1000.0
                result_payload = resp.get("result", resp) if isinstance(resp, dict) else resp
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

        return self._forward_and_read(msg, expect_response=True)

    def serve_streams(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> int:
        """Main stdio proxy loop."""
        self.start_downstream()
        self._log(f"Wrapping {' '.join(self.command)} | policy={self.policy.name} | trace={self.trace_path}")
        try:
            for raw_line in stdin:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError as exc:
                    err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}}
                    stdout.write(json.dumps(err) + "\n")
                    stdout.flush()
                    continue

                resp = self.handle_message(msg)
                if resp is not None:
                    stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                    stdout.flush()
        finally:
            self.stop_downstream()
        return 0
