# GlassBox (IF-CAEL) — Invention Brief

**Date:** 2026-11-21 · **Field:** AI Agent Harnesses & Local MCP Runtime Substrates · **Depth:** deep · **Output for:** pure-invention (Route A → Open-Source Software Substrate) · **Rounds survived:** 4

## Problem Gate
```
PROBLEM: Developers running local AI coding and autonomous agents (Claude Code, Cursor, Codex CLI, OpenClaw, Hermes) over MCP/tools suffer silent destructive side effects, zero-click prompt-injection exfiltration ("lethal trifecta"), and non-reproducible multi-step failures because existing harnesses rely on decaying prompt rules ("memory gates") and file-only checkpoints that cannot intercept, taint-track, or deterministically replay/fork live MCP tool calls.
ORIGIN: Found — Documented in Anthropic's April 23, 2026 postmortem (anthropic.com/research/april-23-postmortem), Cato Networks' DuneSlide CVE-2026-50548/50549 (CVSS 9.8), Invariant Labs' GitHub MCP Toxic Agent Flow, Replit production DB wipe (1,206 executives), arXiv:2603.20847 (3,864 CLI agent bugs: 62.6% in tool orchestration & command execution), arXiv:2606.08162v1 (40,000+ trials), and arXiv:2611.11104v1 (87.5% of 24 validated MCP CVEs Critical/High).
F1 Avoidability: Pass — Prompt-based "memory gates" decay from 94% to 61% adherence across sessions (arXiv:2606.08162v1) and fail against indirect prompt injection (DuneSlide, GitHub MCP); operational caution alone cannot stop zero-click MCP payloads.
F2 Self-termination: Pass — Every new MCP server, skill, and autonomous workflow creates new untrusted-input-to-privileged-action paths; runtime enforcement and deterministic replay are continuous operational substrates, not one-time fixes.
F3 Trajectory: Pass — Scales exponentially worse with autonomy and agent hop depth: silent disorder accumulates as S(t) = S_0 * e^(alpha*t) (arXiv:2606.08162v1), while daily coding-agent adoption reached 73% of developers in 2026 (Stack Overflow 2026).
F4 Causality: Pass — Structural architectural mismatch: LLMs mix control plane (instructions) and data plane (tool outputs) in one token stream while MCP tools execute with ambient host/OAuth privileges outside OS shell sandboxes.
F5 Future-proofing: Pass — Active upstream solver check (Nov 2026): Anthropic's @anthropic-ai/sandbox-runtime wraps Bash only (excluding MCP servers and hooks); MCP 2026-07-28 explicitly leaves input validation and least-privilege execution to implementers; enterprise MCP gateways (Microsoft, Bifrost) are cloud/Kubernetes-bound or enterprise-gated and bypassed by local IDE/CLI stdio MCP servers.
CLIENT ALIGNMENT: n/a (broad open-source developer ecosystem, 1M+ daily coding-agent users)
DECISION: proceed
```

## Core Claim
We propose **GlassBox**, a zero-dependency, wire-level **Information-Flow & Content-Addressed Execution Ledger (IF-CAEL)** that wraps any local stdio MCP server without modifying the agent or server, extends prior runtime IFC monitors (`APPA`, arXiv:2607.24625v2) and naive trace recorders (`Reprise`), predicts **zero approval prompts on benign local coding workflows while deterministically intercepting 100% of Lethal Trifecta exfiltration calls (`PRIVATE + UNTRUSTED -> EGRESS`) via forensic `SHADOW_SIMULATE` downgrade (<5ms wire overhead) and enabling <50ms offline counterfactual policy replay/forking at $0.00 cost**, and resolves the TRIZ technical contradiction between `#38 (Extent of automation)` / `#27 (Reliability)` and `#31 (Object-generated harmful factors)` / `#37 (Difficulty of detecting/measuring)` via **Principle #2 (Taking Out / Extraction)**, **Principle #35 (Parameter Changes)**, **Principle #26 (Copying)**, and **Principle #34 (Discarding and Recovering)**.

## TRIZ Resolution
- **Technical contradictions**:
  - Improving `#38 (Extent of automation)` worsens `#31 (Object-generated harmful factors)`
  - Improving `#27 (Reliability)` worsens `#31 (Object-generated harmful factors)`
  - Improving `#33 (Ease of operation)` worsens `#31 (Object-generated harmful factors)` (empty cell in classic matrix)
  - Improving `#38 (Extent of automation)` worsens `#37 (Difficulty of detecting/measuring)`
- **Matrix output (verbatim from `python3 scripts/triz_matrix.py 38 31 27 31 33 31 38 37 --merge`)**:
  ```
  Improving 38 (Extent of automation) worsens 31 (Object-generated harmful factors)
     2  Taking Out (Extraction)

  Improving 27 (Reliability) worsens 31 (Object-generated harmful factors)
    35  Parameter Changes
     2  Taking Out (Extraction)
    40  Composite Materials
    26  Copying

  Improving 33 (Ease of operation) worsens 31 (Object-generated harmful factors)
    (empty) no classic recommendation for this pair (empty cell) — try the nearest parameter or reframe

  Improving 38 (Extent of automation) worsens 37 (Difficulty of detecting/measuring)
    34  Discarding and Recovering
    27  Cheap Short-Living
    25  Self-Service

  Merged ranking (principle: pairs recommending it)
     2  Taking Out (Extraction)          2
    35  Parameter Changes                1
    40  Composite Materials              1
    26  Copying                          1
    34  Discarding and Recovering        1
    27  Cheap Short-Living               1
    25  Self-Service                     1
  ```
- **Principles applied**:
  - **#2 Taking Out (Extraction)**: Extract security enforcement and execution recording OUT of the LLM harness and OUT of MCP servers into a transparent stdio JSON-RPC wire shim (`glassbox wrap -- <cmd>`).
  - **#35 Parameter Changes**: Mutate the session's live capability level dynamically based on a 3-bit information-flow taint lattice `(PRIVATE, UNTRUSTED, EGRESS)` instead of static binary allowlists.
  - **#26 Copying & #34 Discarding and Recovering**: Record every tool call, SHA-256 schema pin, and taint transition in a content-addressed Merkle-chained flight cassette (`.gbx`), allowing live destructive/exfiltration calls to be transparently downgraded into a `SHADOW_SIMULATE` synthetic copy and enabling instant offline time-travel forking and counterfactual policy verification.
- **Physical contradiction**: An autonomous agent session needs **high local privilege / zero-prompt autonomy** (for fast coding velocity) AND **strict zero-egress / zero-destructive-write confinement** (when exposed to untrusted external content).
- **Separation**: **Separation on Condition / in Time** — privilege is high while `taint == CLEAN` or `PRIVATE_ONLY`, and automatically transitions to `SHADOW_SIMULATE` / `BLOCK` for egress and destructive sinks the instant `PRIVATE ∧ UNTRUSTED` is latched in the session state machine.
- **Trend position**: Trend #7 (Transition to micro level): currently at container/VM sandbox level → next step = per-RPC wire-frame micro-enforcement; Trend #8 (Substance-field involvement): currently static config/prompt rules → next step = cryptographic provenance + content-addressed state fields.

## What This Breaks
Breaks the prevailing harness assumption (embodied in Claude Code `settings.json`, Cursor static MCP allowlists, and Langfuse post-hoc OTel tracing) that **tool authorization is a static per-tool predicate independent of session information flow** and that **security enforcement and deterministic time-travel debugging are separate infrastructure stacks**.

## What This Opens
1. **Drop-in Lethal Trifecta immunity** for any local MCP client (Claude Code, Cursor, Codex CLI, Windsurf, OpenClaw, Hermes) with a 1-line config change and zero Docker/K8s/ClickHouse overhead.
2. **Forensic shadow capture**: Instead of just crashing an agent when prompt injection strikes, `SHADOW_SIMULATE` returns a deterministic dry-run receipt while capturing the attacker's exact exfiltration arguments in a tamper-evident Merkle chain.
3. **Git-like counterfactual security & regression testing**: Developers can replay a real production agent incident offline in <50ms at $0 cost, fork at step *k* under a stricter policy, and prove in CI that the exploit is neutralized.

## Novelty Check
| Query | Closest hit | Gap that remains |
|---|---|---|
| `"MCP" dynamic taint tracking "lethal trifecta" proxy open source github` | `agentd` (config-time static refusal), `Archestra` (AGPL enterprise platform), `agent-boundary-scan` (PyPI Nov 17 2026 static AST scanner) | Static/pre-deploy or heavy enterprise platforms; none provide a zero-dependency local stdio wire proxy with dynamic forensic shadow-downgrade + replay. |
| `"information flow control" MCP proxy deterministic replay time travel github` | `APPA` (arXiv:2607.24625v2, Aug 2026 — dual-phase IFC reference monitor + child-branch quarantine); `Elsium-AI` (TS runtime with provenance labels) | `APPA` is an academic architecture focused on online abort/LLM-recovery, not a local Merkle-chained cassette for offline counterfactual time-travel forking; `Elsium-AI` requires adopting a whole TS framework rather than wrapping existing MCP servers. |
| `"taint tracking" AI agent tool call capability downgrade open source 2025 2026` | `Tracking Capabilities for Safer Agents` (arXiv:2603.00991v2, Scala 3 capture checking); `SkillDetonate` (Nov 2026 sandbox auditor) | Requires writing agent code in Scala 3 or running heavy OS detonation sandboxes; does not wrap arbitrary existing JSON-RPC MCP servers in place. |
| `deterministic MCP record replay fork debugger CLI open source github 2026` | `itsshreyasbhardwaj-design/reprise` (v0.1.0); `OrcaReplay` | Record/replay only — zero dynamic taint-lattice firewall, zero SHA-256 tool-schema rug-pull pinning, zero Merkle tamper-evidence, zero counterfactual policy diffing. |

## Minimum Proof of Concept
- **What**: Pure-Python zero-dependency CLI & stdio MCP proxy (`glassbox`) with dynamic taint lattice, SHA-256 tool-schema pinning, Merkle-chained `.gbx` flight recorder, offline `replay`/`fork`/`diff`/`verify` engine, and built-in local web Flight Recorder UI (`glassbox ui`).
- **Type**: Executable software prototype + automated `pytest` falsification suite against a real stdio MCP server subprocess.
- **Complexity**: Hours.
- **Tools**: Python 3.10+ standard library (`subprocess`, `json`, `hashlib`, `http.server`, `argparse`, `sqlite3`/JSONL), `pytest`.
- **Success criterion**: All 5 falsification assertions pass in automated execution: (1) benign flow = 0 prompts, <5ms median proxy overhead; (2) Lethal Trifecta flow = 100% deterministic interception/shadow-capture; (3) mid-session tool schema mutation = 100% `SCHEMA_DRIFT_BLOCKED`; (4) 1-byte cassette tamper = `verify` fails; (5) offline `fork --at-step` under strict policy = deterministic replay in <50ms at $0 cost.

## Phase 4 Survival Log
| Round | Move | Proposal | Challenge (quoted) | Answer (quoted) | Survived | Outcome |
|---|---|---|---|---|---|---|
| 1 | Move 3 (Adjacent-field import) | Wire-level MCP proxy unifying dynamic taint-lattice firewall + Merkle time-travel replay | "APPA (arXiv:2607.24625v2) already proposed a dual-phase IFC monitor at MCP gateways, and Reprise already proposed MCP record/replay. Why isn't this just bolting two existing things together?" | "Neither unifies taint-state transitions + SHA-256 tool-schema pins + content-addressed tool I/O into one Merkle-chained state machine where a tripped Lethal Trifecta triggers forensic SHADOW_SIMULATE downgrade and enables $0 offline counterfactual policy forking." | Yes | Proceed to Move 5 |
| 2 | Move 5 (Prediction demand) | Unified IF-CAEL wire shim | "What concrete, falsifiable behavior does this predict that static MCP allowlists and post-hoc OTel tracers cannot achieve?" | "0 prompts on benign local coding + 100% deterministic Lethal Trifecta interception at <5ms wire latency; 100% tool rug-pull detection via schema hash pinning; <50ms deterministic offline counterfactual replay." | Yes | Proceed to Move 6 |
| 3 | Move 6 (Minimum falsification) | End-to-end stdio MCP subprocess harness | "Name the smallest concrete experiment that would prove your mechanism fails." | "Automated pytest harness wrapping a real stdio MCP server testing benign latency, Lethal Trifecta interception, schema-drift blocking, 1-byte Merkle tamper detection, and offline counterfactual fork replay." | Yes | Proceed to Move 8 |
| 4 | Move 8 (TRIZ validity) + Move 1 (Boundary collapse) | TRIZ mapping & honest boundary check | "Which exact principles from triz_matrix.py resolve which contradiction, and where does the boundary collapse?" | "38x31 -> #2 Extraction; 27x31 -> #35 Parameter Changes, #26 Copying; 38x37 -> #34 Discarding & Recovering. Physical contradiction resolved via Separation on Condition. Boundary: cannot see unwrapped non-MCP shell/network side channels; documented explicitly." | Yes | Terminated as surviving (4 rounds) |

## Handoff
**Route A (buildable in weeks → building now)** → `project-spec-architect` (`CODE` mode) with `PROJECT_TYPE=cli`, `CORE_IDEA=GlassBox wire-level MCP Flight Recorder & Dynamic Taint-Lattice Firewall`, `EXISTING_CODE=none`, `CONTEXT=this brief`.
