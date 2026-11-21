# GlassBox — Human Setup & Build Guide

## Research Audit
- **Phase 0–1 (Operational Crisis & Upstream Solver Check)**: Searched 2025–Nov 2026 coding agent bug studies (`arXiv:2603.20847`), multi-agent silent failure studies (`arXiv:2606.08162v1`), MCP CVE datasets (`arXiv:2611.11104v1`), Anthropic postmortems (Sep 2025, Apr 23 2026), DuneSlide (`CVE-2026-50548/50549`), CurXecute, Plugin4Shell, GitHub MCP Toxic Agent Flow, and upstream vendor releases (Anthropic `sandbox-runtime`, OpenAI Agents SDK, MCP 2026-07-28, Microsoft/Docker/Bifrost MCP gateways).
- **Phase 1B (Viral OSS & Launch Benchmarks)**: Audited 2025–Nov 2026 top viral GitHub repos (`openclaw`, `obra/superpowers`, `affaan-m/ECC`, `hermes-agent`, `firecrawl`, `browser-use`, `langfuse`, `reprise`) and 2026 HN/Reddit/X launch velocity mechanics.
- **Phase 3–5 (TRIZ & Novelty Check)**: Executed `scripts/triz_matrix.py 38 31 27 31 33 31 38 37 --merge` and ran 4 decomposed novelty queries (identifying `APPA`, `Fides`, `Elsium-AI`, `agent-boundary-scan`, `Reprise`).
- `ASSUMED: PROJECT_TYPE = cli` (developer infrastructure / local MCP runtime substrate; consumer-saas forms/WhatsApp omitted).
- `ASSUMED: OUTPUT_MODE = CODE` (full tested, runnable repository zip).
- `ASSUMED: TIMELINE = immediate autonomous build`.

### Gap Selected
**[NEW] Wire-level MCP Flight Recorder & Dynamic Taint-Lattice Firewall**: Existing tools split security (static allowlists / cloud gateways) and observability (heavy OTel tracers or nascent recorders) into separate stacks; none unify zero-dependency stdio MCP wrapping, dynamic `SHADOW_SIMULATE` Lethal-Trifecta downgrade, SHA-256 schema pinning, and `<5ms` Merkle-verified offline counterfactual forking.

### Skipped Directions
- *Cloud multi-tenant MCP gateway*: Saturated by Bifrost, Microsoft MCP Gateway, and Docker MCP Gateway; high ops friction kills viral developer adoption.
- *Prompt-only `CLAUDE.md` skill pack*: Vulnerable to prompt decay (`94% -> 61%`) and saturated by `obra/superpowers` and `affaan-m/ECC`.

### Unverified Items
**Count: 0 `[UNVERIFIED]` / `[NOT FOUND]` tags in the spec.** Every external runtime dependency was eliminated (pure Python 3.10+ stdlib), and all core falsification criteria were executed and verified in the sandbox.

## Environment Setup

### Prerequisites
```bash
python3 --version   # Requires Python 3.10+
git --version       # For publishing to GitHub
```

### Install & Verify Locally
```bash
unzip glassbox.zip
cd glassbox
pip install -e .
python3 -m unittest discover -s tests -v
```

### Run the 30-Second Keyless Demo & Web UI
```bash
glassbox demo
glassbox ui
# Open http://127.0.0.1:8765 in your browser
```

## Publish to GitHub (30 Seconds)
```bash
chmod +x push-to-github.sh
./push-to-github.sh
```
Then follow `LAUNCH_PLAYBOOK.md` to execute the coordinated Tuesday–Thursday 8:30 AM ET Show HN + X + Reddit launch.

## Common Failure Points
1. **`glassbox` command not found after `pip install -e .`**: Ensure your Python user bin directory (`~/.local/bin` or virtualenv `bin/`) is on `PATH`, or run via `python3 -m glassbox <cmd>`.
2. **Port 8765 already in use**: Pass `--port 8899` to `glassbox ui`.
3. **Custom MCP server tool names not matching built-in regexes**: Pass `--policy path/to/custom-policy.json` extending `balanced` with your exact `private_tool_patterns`, `untrusted_tool_patterns`, and `egress_tool_patterns`.
