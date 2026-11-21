"""SARIF 2.1.0 CI Security Exporter & Side-by-Side Cassette Diff Engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from glassbox import __version__
from glassbox.ledger import load_cassette, verify_cassette


def export_sarif(cassette_path: Path) -> dict[str, Any]:
    """Convert intercepted GlassBox findings in a .gbx cassette to SARIF 2.1.0 JSON
    for direct upload to GitHub Code Scanning / Security tab."""
    entries = load_cassette(cassette_path)
    ver = verify_cassette(cassette_path)
    results: list[dict[str, Any]] = []

    rule_defs = {
        "LETHAL_TRIFECTA": {
            "id": "GBX001",
            "name": "LethalTrifectaExfiltration",
            "shortDescription": {"text": "Private data + untrusted input reached an egress MCP tool."},
            "defaultConfiguration": {"level": "error"},
        },
        "DESTRUCTIVE_SINK_GUARD": {
            "id": "GBX002",
            "name": "DestructiveMCPAction",
            "shortDescription": {"text": "Destructive MCP operation intercepted at the wire."},
            "defaultConfiguration": {"level": "error"},
        },
        "SCHEMA_DRIFT_RUGPULL": {
            "id": "GBX003",
            "name": "MCPSchemaRugPull",
            "shortDescription": {"text": "MCP tool mutated its SHA-256 schema mid-session."},
            "defaultConfiguration": {"level": "error"},
        },
    }

    for e in entries:
        if e.action in ("SHADOW_SIMULATE", "BLOCK") or e.rule_triggered in rule_defs:
            rdef = rule_defs.get(
                e.rule_triggered,
                {
                    "id": "GBX099",
                    "name": e.rule_triggered,
                    "shortDescription": {"text": e.reason},
                    "defaultConfiguration": {"level": "warning"},
                },
            )
            results.append(
                {
                    "ruleId": rdef["id"],
                    "level": "error" if e.risk_score >= 90 else "warning",
                    "message": {
                        "text": f"[{e.action}] Step #{e.step} tool '{e.tool_name}': {e.reason} (taint={e.taint_after})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(cassette_path)},
                                "region": {"startLine": e.step},
                            }
                        }
                    ],
                    "properties": {
                        "tool_name": e.tool_name,
                        "action": e.action,
                        "risk_score": e.risk_score,
                        "entry_hash": e.entry_hash,
                        "merkle_verified": ver.valid,
                    },
                }
            )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GlassBox",
                        "version": __version__,
                        "informationUri": "https://github.com/glassbox/glassbox",
                        "rules": list(rule_defs.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def diff_cassettes(path_a: Path, path_b: Path) -> list[dict[str, Any]]:
    """Compare two .gbx cassettes step-by-step and return structured differences."""
    a_entries = [e for e in load_cassette(path_a) if e.event_type != "schema_pin"]
    b_entries = [e for e in load_cassette(path_b) if e.event_type != "schema_pin"]
    max_len = max(len(a_entries), len(b_entries))
    rows: list[dict[str, Any]] = []
    for i in range(max_len):
        ea = a_entries[i] if i < len(a_entries) else None
        eb = b_entries[i] if i < len(b_entries) else None
        changed = (
            ea is None
            or eb is None
            or ea.tool_name != eb.tool_name
            or ea.action != eb.action
            or ea.rule_triggered != eb.rule_triggered
        )
        rows.append(
            {
                "index": i + 1,
                "tool_a": ea.tool_name if ea else "(none)",
                "action_a": ea.action if ea else "(none)",
                "tool_b": eb.tool_name if eb else "(none)",
                "action_b": eb.action if eb else "(none)",
                "changed": changed,
            }
        )
    return rows
