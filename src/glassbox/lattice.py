"""Dynamic 3-bit Information-Flow Taint Lattice & Policy Engine for MCP tool calls.

Implements a deterministic state machine tracking three security lattice bits per session:
  - PRIVATE   (bit 0): Session has read sensitive/private data (e.g., .env, secrets, private repos, DB rows).
  - UNTRUSTED (bit 1): Session has ingested untrusted external data (e.g., GitHub issues, web pages, emails).
  - EGRESS    (bit 2): Tool call attempts external communication or irreversible destructive mutation.

Classifies tools via three layered signals:
  1. Standard MCP tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) from `tools/list`.
  2. Built-in top-12 official MCP server profiles (`--profile github,postgres,...` or `all`).
  3. Argument & secret-value pattern matching (`.env`, private keys, `DROP TABLE`, etc.).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from glassbox.profiles import merge_profile_into_policy


class Action(str, Enum):
    ALLOW = "ALLOW"
    SHADOW_SIMULATE = "SHADOW_SIMULATE"
    BLOCK = "BLOCK"


class TaintFlag(str, Enum):
    PRIVATE = "PRIVATE"
    UNTRUSTED = "UNTRUSTED"
    EGRESS_ATTEMPTED = "EGRESS_ATTEMPTED"


@dataclass
class PolicyConfig:
    name: str
    mode: str = "balanced"  # balanced | strict | audit
    on_lethal_trifecta: Action = Action.SHADOW_SIMULATE
    on_destructive: Action = Action.BLOCK
    on_schema_drift: Action = Action.BLOCK
    block_destructive_always: bool = True
    private_tool_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)(read|get|cat|dump|export).*(secret|env|key|token|cred|ssh|private|vault)",
            r"(?i)^(read_file|view_file|fs_read|get_secret|query_db|sql_query)$",
        ]
    )
    private_arg_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)(\.env|id_rsa|\.pem|credentials|secrets?\.json|\.aws/|\.ssh/|password|api_key|token|prod_db|customers)",
        ]
    )
    untrusted_tool_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)(fetch|scrape|browse|search|web|http_get|curl|github_issue|pull_request|comment|email|inbox|slack|discord|tweet|rss)",
        ]
    )
    egress_tool_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)(http_post|http_put|send_email|post_comment|create_comment|create_issue|webhook|upload|push|publish|curl|slack_send|send_message|exfil)",
        ]
    )
    destructive_tool_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)(delete|drop|truncate|destroy|wipe|rm_rf|force_push|reset_hard|format_disk)",
        ]
    )
    destructive_arg_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*(;|$)|rm\s+-rf\s+/|git\s+push\s+--force)\b",
        ]
    )
    secret_value_patterns: list[str] = field(
        default_factory=lambda: [
            r"(?i)(sk-[a-zA-Z0-9]{12,}|ghp_[a-zA-Z0-9]{12,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|STRIPE_SECRET|DB_PASSWORD=)",
        ]
    )

    @classmethod
    def preset(cls, name: str, profile: str = "") -> "PolicyConfig":
        key = name.strip().lower()
        if key == "balanced":
            cfg = cls(
                name="balanced",
                mode="balanced",
                on_lethal_trifecta=Action.SHADOW_SIMULATE,
                on_destructive=Action.BLOCK,
                on_schema_drift=Action.BLOCK,
                block_destructive_always=True,
            )
        elif key == "strict":
            cfg = cls(
                name="strict",
                mode="strict",
                on_lethal_trifecta=Action.BLOCK,
                on_destructive=Action.BLOCK,
                on_schema_drift=Action.BLOCK,
                block_destructive_always=True,
            )
        elif key == "audit":
            cfg = cls(
                name="audit",
                mode="audit",
                on_lethal_trifecta=Action.ALLOW,
                on_destructive=Action.ALLOW,
                on_schema_drift=Action.ALLOW,
                block_destructive_always=False,
            )
        else:
            p = Path(name)
            if p.exists() and p.is_file():
                raw = json.loads(p.read_text(encoding="utf-8"))
                cfg = cls.preset(raw.get("extends", "balanced"))
                cfg.name = raw.get("name", p.stem)
                if "on_lethal_trifecta" in raw:
                    cfg.on_lethal_trifecta = Action(raw["on_lethal_trifecta"])
                if "on_destructive" in raw:
                    cfg.on_destructive = Action(raw["on_destructive"])
                if "on_schema_drift" in raw:
                    cfg.on_schema_drift = Action(raw["on_schema_drift"])
                if "block_destructive_always" in raw:
                    cfg.block_destructive_always = bool(raw["block_destructive_always"])
                for list_field in (
                    "private_tool_patterns",
                    "private_arg_patterns",
                    "untrusted_tool_patterns",
                    "egress_tool_patterns",
                    "destructive_tool_patterns",
                    "destructive_arg_patterns",
                ):
                    if list_field in raw:
                        setattr(cfg, list_field, list(raw[list_field]))
            else:
                raise ValueError(
                    f"Unknown policy '{name}'. Choose 'balanced', 'strict', 'audit', or a JSON policy file path."
                )

        if profile:
            merge_profile_into_policy(cfg, profile)
        return cfg


@dataclass
class EvaluationDecision:
    action: Action
    rule_triggered: str
    reason: str
    taint_before: list[str]
    taint_after: list[str]
    tool_classification: list[str]
    risk_score: int  # 0..100
    shadow_response: dict[str, Any] | None = None


class TaintLattice:
    """Tracks session-level information-flow taint across MCP tool invocations."""

    def __init__(self, policy: PolicyConfig | None = None) -> None:
        self.policy = policy or PolicyConfig.preset("balanced")
        self.taint: set[str] = set()
        self.private_sources: list[str] = []
        self.untrusted_sources: list[str] = []
        self.tool_annotations: dict[str, dict[str, Any]] = {}

    def register_tool_annotations(self, tool_name: str, annotations: dict[str, Any] | None) -> None:
        """Record standard MCP tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`)."""
        if annotations and isinstance(annotations, dict):
            self.tool_annotations[tool_name] = dict(annotations)

    def snapshot(self) -> list[str]:
        return sorted(self.taint)

    def _matches_any(self, text: str, patterns: list[str]) -> bool:
        return any(re.search(pat, text) for pat in patterns)

    def classify_call(self, tool_name: str, arguments: dict[str, Any]) -> list[str]:
        args_blob = json.dumps(arguments, sort_keys=True, ensure_ascii=False)
        classes: list[str] = []
        ann = self.tool_annotations.get(tool_name, {})

        # 1. MCP standard tool annotations (works for ANY custom server tool name!)
        if ann.get("destructiveHint") is True:
            classes.append("DESTRUCTIVE_SINK")
        if ann.get("openWorldHint") is True:
            if ann.get("readOnlyHint") is True:
                classes.append("UNTRUSTED_SOURCE")
            else:
                classes.append("EGRESS_SINK")

        # 2. Private source check
        if self._matches_any(args_blob, self.policy.private_arg_patterns) or (
            self._matches_any(tool_name, self.policy.private_tool_patterns)
            and (
                "secret" in tool_name.lower()
                or "sql" in tool_name.lower()
                or "db" in tool_name.lower()
                or "customer" in tool_name.lower()
                or self._matches_any(args_blob, self.policy.private_arg_patterns)
            )
        ):
            if "PRIVATE_SOURCE" not in classes:
                classes.append("PRIVATE_SOURCE")

        # 3. Regex / profile classifiers
        if self._matches_any(tool_name, self.policy.untrusted_tool_patterns):
            if "UNTRUSTED_SOURCE" not in classes:
                classes.append("UNTRUSTED_SOURCE")

        if self._matches_any(tool_name, self.policy.egress_tool_patterns):
            if "EGRESS_SINK" not in classes:
                classes.append("EGRESS_SINK")

        if self._matches_any(tool_name, self.policy.destructive_tool_patterns) or self._matches_any(
            args_blob, self.policy.destructive_arg_patterns
        ):
            if "DESTRUCTIVE_SINK" not in classes:
                classes.append("DESTRUCTIVE_SINK")

        if not classes:
            classes.append("LOCAL_BENIGN")
        return classes

    def evaluate_pre_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        schema_drifted: bool = False,
    ) -> EvaluationDecision:
        before = self.snapshot()
        classes = self.classify_call(tool_name, arguments)
        args_blob = json.dumps(arguments, sort_keys=True, ensure_ascii=False)
        contains_secret_literal = self._matches_any(args_blob, self.policy.secret_value_patterns)

        if schema_drifted:
            return EvaluationDecision(
                action=self.policy.on_schema_drift,
                rule_triggered="SCHEMA_DRIFT_RUGPULL",
                reason=(
                    f"Tool '{tool_name}' mutated its pinned SHA-256 schema mid-session "
                    f"(MCPoison / Plugin4Shell rug-pull defense)."
                ),
                taint_before=before,
                taint_after=before,
                tool_classification=classes,
                risk_score=98,
                shadow_response=self._build_shadow(tool_name, arguments, "SCHEMA_DRIFT_RUGPULL")
                if self.policy.on_schema_drift == Action.SHADOW_SIMULATE
                else None,
            )

        if "DESTRUCTIVE_SINK" in classes and (
            self.policy.block_destructive_always or TaintFlag.UNTRUSTED.value in self.taint
        ):
            return EvaluationDecision(
                action=self.policy.on_destructive,
                rule_triggered="DESTRUCTIVE_SINK_GUARD",
                reason=(
                    f"Destructive operation detected in '{tool_name}' "
                    f"(physical gate enforced outside LLM prompt context)."
                ),
                taint_before=before,
                taint_after=before,
                tool_classification=classes,
                risk_score=95,
                shadow_response=self._build_shadow(tool_name, arguments, "DESTRUCTIVE_SINK_GUARD")
                if self.policy.on_destructive == Action.SHADOW_SIMULATE
                else None,
            )

        has_private = TaintFlag.PRIVATE.value in self.taint or contains_secret_literal
        has_untrusted = TaintFlag.UNTRUSTED.value in self.taint
        if "EGRESS_SINK" in classes and has_private and has_untrusted:
            after = sorted(self.taint | {TaintFlag.EGRESS_ATTEMPTED.value})
            self.taint.add(TaintFlag.EGRESS_ATTEMPTED.value)
            action = self.policy.on_lethal_trifecta
            return EvaluationDecision(
                action=action,
                rule_triggered="LETHAL_TRIFECTA",
                reason=(
                    f"Lethal Trifecta tripped on '{tool_name}': session holds PRIVATE "
                    f"({', '.join(self.private_sources) or 'secret literal'}) + UNTRUSTED "
                    f"({', '.join(self.untrusted_sources) or 'external input'}) and attempted EGRESS. "
                    f"Dynamically downgraded to {action.value}."
                ),
                taint_before=before,
                taint_after=after,
                tool_classification=classes,
                risk_score=100,
                shadow_response=self._build_shadow(tool_name, arguments, "LETHAL_TRIFECTA")
                if action == Action.SHADOW_SIMULATE
                else None,
            )

        if "PRIVATE_SOURCE" in classes:
            self.taint.add(TaintFlag.PRIVATE.value)
            self.private_sources.append(tool_name)
        if "UNTRUSTED_SOURCE" in classes:
            self.taint.add(TaintFlag.UNTRUSTED.value)
            self.untrusted_sources.append(tool_name)

        after = self.snapshot()
        risk = 0
        if TaintFlag.PRIVATE.value in self.taint:
            risk += 25
        if TaintFlag.UNTRUSTED.value in self.taint:
            risk += 35
        if "EGRESS_SINK" in classes:
            risk += 20

        return EvaluationDecision(
            action=Action.ALLOW,
            rule_triggered="NONE",
            reason="Permitted under current taint lattice state (zero-prompt safe autonomy).",
            taint_before=before,
            taint_after=after,
            tool_classification=classes,
            risk_score=min(risk, 85),
        )

    def observe_response(self, tool_name: str, response_payload: Any) -> list[str]:
        """Post-call inspection: if a tool returns secret material, latch PRIVATE retroactively."""
        blob = json.dumps(response_payload, ensure_ascii=False)
        if self._matches_any(blob, self.policy.secret_value_patterns):
            self.taint.add(TaintFlag.PRIVATE.value)
            if tool_name not in self.private_sources:
                self.private_sources.append(f"{tool_name}:response")
        return self.snapshot()

    @staticmethod
    def _build_shadow(tool_name: str, arguments: dict[str, Any], rule: str) -> dict[str, Any]:
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"[GLASSBOX SHADOW_SIMULATE :: {rule}] "
                        f"External side effect for '{tool_name}' was intercepted and NOT executed. "
                        f"Arguments captured in tamper-evident flight recorder for human review."
                    ),
                }
            ],
            "isError": False,
            "_glassbox": {
                "intercepted": True,
                "mode": "SHADOW_SIMULATE",
                "rule": rule,
                "suppressed_tool": tool_name,
                "captured_arg_keys": sorted(arguments.keys()),
            },
        }
