"""Content-Addressed Merkle Execution Ledger (.gbx) for deterministic replay and time-travel forking.

Every intercepted MCP JSON-RPC frame is stored as a JSONL entry chained via SHA-256:
    entry_hash = sha256(prev_hash + canonical_json(entry_body))

This guarantees:
  1. Cryptographic tamper-evidence (modifying 1 byte breaks `verify_cassette`).
  2. Cryptographic tool-schema pinning (detecting MCPoison / rug-pull schema mutations).
  3. <50ms offline deterministic replay & counterfactual policy forking at $0.00 cost.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from glassbox.lattice import Action, PolicyConfig, TaintLattice

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_tool_schema(tool_def: dict[str, Any]) -> str:
    """Compute a stable SHA-256 fingerprint of an MCP tool's name, description, and inputSchema."""
    pinned = {
        "name": tool_def.get("name", ""),
        "description": tool_def.get("description", ""),
        "inputSchema": tool_def.get("inputSchema", {}),
    }
    return sha256_hex(canonical_json(pinned))


@dataclass
class LedgerEntry:
    step: int
    timestamp: float
    event_type: str  # session_start | schema_pin | tool_call | schema_drift
    tool_name: str
    arguments: dict[str, Any]
    args_hash: str
    schema_hash: str
    action: str
    rule_triggered: str
    reason: str
    taint_before: list[str]
    taint_after: list[str]
    tool_classification: list[str]
    risk_score: int
    latency_ms: float
    response: Any
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "args_hash": self.args_hash,
            "schema_hash": self.schema_hash,
            "action": self.action,
            "rule_triggered": self.rule_triggered,
            "reason": self.reason,
            "taint_before": self.taint_before,
            "taint_after": self.taint_after,
            "tool_classification": self.tool_classification,
            "risk_score": self.risk_score,
            "latency_ms": round(self.latency_ms, 3),
            "response": self.response,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "LedgerEntry":
        return cls(
            step=int(d["step"]),
            timestamp=float(d["timestamp"]),
            event_type=str(d["event_type"]),
            tool_name=str(d["tool_name"]),
            arguments=dict(d.get("arguments", {})),
            args_hash=str(d["args_hash"]),
            schema_hash=str(d.get("schema_hash", "")),
            action=str(d["action"]),
            rule_triggered=str(d["rule_triggered"]),
            reason=str(d["reason"]),
            taint_before=list(d.get("taint_before", [])),
            taint_after=list(d.get("taint_after", [])),
            tool_classification=list(d.get("tool_classification", [])),
            risk_score=int(d.get("risk_score", 0)),
            latency_ms=float(d.get("latency_ms", 0.0)),
            response=d.get("response"),
            prev_hash=str(d["prev_hash"]),
            entry_hash=str(d["entry_hash"]),
        )


def compute_entry_hash(body: dict[str, Any], prev_hash: str) -> str:
    payload = {k: v for k, v in body.items() if k != "entry_hash"}
    return sha256_hex(prev_hash + "|" + canonical_json(payload))


class MerkleLedger:
    """Append-only Merkle-chained flight recorder (.gbx)."""

    def __init__(self, path: Path, session_id: str | None = None, policy_name: str = "balanced") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or f"gbx-{uuid.uuid4().hex[:10]}"
        self.policy_name = policy_name
        self.prev_hash = GENESIS_HASH
        self.step = 0
        self.schema_pins: dict[str, str] = {}
        self.entries: list[LedgerEntry] = []

    def append(
        self,
        *,
        event_type: str,
        tool_name: str,
        arguments: dict[str, Any],
        schema_hash: str,
        action: str,
        rule_triggered: str,
        reason: str,
        taint_before: list[str],
        taint_after: list[str],
        tool_classification: list[str],
        risk_score: int,
        latency_ms: float,
        response: Any,
        timestamp: float | None = None,
    ) -> LedgerEntry:
        self.step += 1
        body = {
            "step": self.step,
            "timestamp": round(timestamp if timestamp is not None else time.time(), 4),
            "event_type": event_type,
            "tool_name": tool_name,
            "arguments": arguments,
            "args_hash": sha256_hex(canonical_json(arguments)),
            "schema_hash": schema_hash,
            "action": action,
            "rule_triggered": rule_triggered,
            "reason": reason,
            "taint_before": taint_before,
            "taint_after": taint_after,
            "tool_classification": tool_classification,
            "risk_score": risk_score,
            "latency_ms": round(latency_ms, 3),
            "response": response,
            "prev_hash": self.prev_hash,
        }
        entry_hash = compute_entry_hash(body, self.prev_hash)
        body["entry_hash"] = entry_hash
        entry = LedgerEntry.from_dict(body)
        self.prev_hash = entry_hash
        self.entries.append(entry)

        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return entry


@dataclass
class VerificationResult:
    valid: bool
    total_steps: int
    merkle_root: str
    broken_at_step: int | None = None
    error: str | None = None


def load_cassette(path: Path) -> list[LedgerEntry]:
    entries: list[LedgerEntry] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entries.append(LedgerEntry.from_dict(json.loads(line)))
    return entries


def verify_cassette(path: Path) -> VerificationResult:
    """Verify cryptographic Merkle integrity of every step in a .gbx cassette."""
    entries = load_cassette(path)
    if not entries:
        return VerificationResult(valid=False, total_steps=0, merkle_root=GENESIS_HASH, error="Empty cassette.")

    expected_prev = GENESIS_HASH
    for idx, entry in enumerate(entries, start=1):
        if entry.prev_hash != expected_prev:
            return VerificationResult(
                valid=False,
                total_steps=len(entries),
                merkle_root=expected_prev,
                broken_at_step=idx,
                error=f"Chain discontinuity at step {idx}: prev_hash mismatch.",
            )
        recomputed = compute_entry_hash(entry.to_dict(), expected_prev)
        if recomputed != entry.entry_hash:
            return VerificationResult(
                valid=False,
                total_steps=len(entries),
                merkle_root=expected_prev,
                broken_at_step=idx,
                error=f"Tamper detected at step {idx}: SHA-256 digest mismatch.",
            )
        expected_prev = entry.entry_hash

    return VerificationResult(valid=True, total_steps=len(entries), merkle_root=expected_prev)


@dataclass
class ForkStepDiff:
    step: int
    tool_name: str
    original_action: str
    counterfactual_action: str
    original_rule: str
    counterfactual_rule: str
    changed: bool
    taint_after: list[str]
    reason: str


@dataclass
class ForkResult:
    source_path: str
    fork_step: int
    policy_name: str
    elapsed_ms: float
    original_merkle_root: str
    forked_merkle_root: str
    prefix_hashes_identical: bool
    diffs: list[ForkStepDiff] = field(default_factory=list)
    output_path: str | None = None


def counterfactual_fork(
    source_path: Path,
    *,
    at_step: int = 1,
    policy_name: str = "strict",
    output_path: Path | None = None,
) -> ForkResult:
    """Offline time-travel fork & counterfactual policy re-simulation (<50ms, $0.00 cost).

    Replays steps 1..(at_step-1) verbatim (preserving identical Merkle prefix hashes),
    then re-evaluates steps at_step..N against the new policy without invoking any live tools.
    """
    t0 = time.perf_counter()
    entries = load_cassette(source_path)
    if not entries:
        raise ValueError(f"Cassette '{source_path}' is empty.")

    policy = PolicyConfig.preset(policy_name)
    lattice = TaintLattice(policy=policy)
    pinned_schemas: dict[str, str] = {}
    diffs: list[ForkStepDiff] = []

    fork_ledger: MerkleLedger | None = None
    if output_path is not None:
        if output_path.exists():
            output_path.unlink()
        fork_ledger = MerkleLedger(output_path, policy_name=policy.name)

    prev_hash = GENESIS_HASH
    prefix_identical = True

    for entry in entries:
        if entry.event_type == "schema_pin":
            if entry.tool_name and entry.schema_hash:
                pinned_schemas[entry.tool_name] = entry.schema_hash
            if fork_ledger is not None:
                new_e = fork_ledger.append(
                    event_type=entry.event_type,
                    tool_name=entry.tool_name,
                    arguments=entry.arguments,
                    schema_hash=entry.schema_hash,
                    action=entry.action,
                    rule_triggered=entry.rule_triggered,
                    reason=entry.reason,
                    taint_before=entry.taint_before,
                    taint_after=entry.taint_after,
                    tool_classification=entry.tool_classification,
                    risk_score=entry.risk_score,
                    latency_ms=entry.latency_ms,
                    response=entry.response,
                    timestamp=entry.timestamp,
                )
                prev_hash = new_e.entry_hash
            else:
                prev_hash = compute_entry_hash(entry.to_dict(), prev_hash)
            if entry.step < at_step and prev_hash != entry.entry_hash:
                prefix_identical = False
            continue

        schema_drifted = False
        if entry.tool_name in pinned_schemas and entry.schema_hash:
            if pinned_schemas[entry.tool_name] != entry.schema_hash:
                schema_drifted = True
        elif entry.rule_triggered == "SCHEMA_DRIFT_RUGPULL":
            schema_drifted = True

        if entry.step < at_step:
            # Advance lattice state identically to historical prefix
            lattice.evaluate_pre_call(entry.tool_name, entry.arguments, schema_drifted=schema_drifted)
            if entry.action == Action.ALLOW.value:
                lattice.observe_response(entry.tool_name, entry.response)

            if fork_ledger is not None:
                new_e = fork_ledger.append(
                    event_type=entry.event_type,
                    tool_name=entry.tool_name,
                    arguments=entry.arguments,
                    schema_hash=entry.schema_hash,
                    action=entry.action,
                    rule_triggered=entry.rule_triggered,
                    reason=entry.reason,
                    taint_before=entry.taint_before,
                    taint_after=entry.taint_after,
                    tool_classification=entry.tool_classification,
                    risk_score=entry.risk_score,
                    latency_ms=entry.latency_ms,
                    response=entry.response,
                    timestamp=entry.timestamp,
                )
                prev_hash = new_e.entry_hash
            else:
                prev_hash = compute_entry_hash(entry.to_dict(), prev_hash)

            if prev_hash != entry.entry_hash:
                prefix_identical = False

            diffs.append(
                ForkStepDiff(
                    step=entry.step,
                    tool_name=entry.tool_name,
                    original_action=entry.action,
                    counterfactual_action=entry.action,
                    original_rule=entry.rule_triggered,
                    counterfactual_rule=entry.rule_triggered,
                    changed=False,
                    taint_after=entry.taint_after,
                    reason="(prefix preserved verbatim)",
                )
            )
            continue

        # Counterfactual evaluation from at_step onward
        decision = lattice.evaluate_pre_call(entry.tool_name, entry.arguments, schema_drifted=schema_drifted)
        if decision.action == Action.ALLOW:
            taint_after = lattice.observe_response(entry.tool_name, entry.response)
            new_response = entry.response
        elif decision.action == Action.SHADOW_SIMULATE:
            taint_after = decision.taint_after
            new_response = decision.shadow_response
        else:
            taint_after = decision.taint_after
            new_response = {
                "error": {
                    "code": -32001,
                    "message": f"[GLASSBOX BLOCKED :: {decision.rule_triggered}] {decision.reason}",
                }
            }

        changed = decision.action.value != entry.action or decision.rule_triggered != entry.rule_triggered
        diffs.append(
            ForkStepDiff(
                step=entry.step,
                tool_name=entry.tool_name,
                original_action=entry.action,
                counterfactual_action=decision.action.value,
                original_rule=entry.rule_triggered,
                counterfactual_rule=decision.rule_triggered,
                changed=changed,
                taint_after=taint_after,
                reason=decision.reason,
            )
        )

        if fork_ledger is not None:
            new_e = fork_ledger.append(
                event_type=entry.event_type,
                tool_name=entry.tool_name,
                arguments=entry.arguments,
                schema_hash=entry.schema_hash,
                action=decision.action.value,
                rule_triggered=decision.rule_triggered,
                reason=decision.reason,
                taint_before=decision.taint_before,
                taint_after=taint_after,
                tool_classification=decision.tool_classification,
                risk_score=decision.risk_score,
                latency_ms=0.1,
                response=new_response,
                timestamp=entry.timestamp,
            )
            prev_hash = new_e.entry_hash
        else:
            body = entry.to_dict()
            body.update(
                {
                    "action": decision.action.value,
                    "rule_triggered": decision.rule_triggered,
                    "reason": decision.reason,
                    "taint_before": decision.taint_before,
                    "taint_after": taint_after,
                    "response": new_response,
                    "prev_hash": prev_hash,
                }
            )
            prev_hash = compute_entry_hash(body, prev_hash)

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    return ForkResult(
        source_path=str(source_path),
        fork_step=at_step,
        policy_name=policy.name,
        elapsed_ms=elapsed_ms,
        original_merkle_root=entries[-1].entry_hash,
        forked_merkle_root=prev_hash,
        prefix_hashes_identical=prefix_identical,
        diffs=diffs,
        output_path=str(output_path) if output_path else None,
    )
