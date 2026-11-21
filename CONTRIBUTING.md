# Contributing to GlassBox

Thanks for helping make AI agent runtimes safer and debuggable!

## Local Setup
```bash
git clone https://github.com/<your-username>/glassbox.git
cd glassbox
pip install -e .
python3 -m unittest discover -s tests -v
```

## Design Principles
1. **Zero external runtime dependencies**: Core CLI, wire proxy, Merkle ledger, and Web UI must run on Python 3.10+ standard library alone.
2. **Sub-5ms wire overhead**: Every pre-call evaluation must remain deterministic and O(1) — never call an LLM on the hot path.
3. **Falsifiable tests**: Every new rule, transport, or policy preset must include a unit test in `tests/test_glassbox.py` that reproduces both the benign case and the attack/failure case.

## High-Impact Good First Issues
- Add Streamable HTTP / SSE MCP transport support alongside stdio.
- Add SARIF export format for `glassbox verify` and `glassbox fork` in CI pipelines.
- Add pre-tuned JSON policy profiles for official GitHub, Postgres, Slack, and Playwright MCP servers.
- Add `glassbox diff <cassette_a> <cassette_b>` for comparing two runs side by side.
