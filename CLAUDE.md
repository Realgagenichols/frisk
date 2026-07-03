# frisk — Project Instructions

`frisk` vets a third-party MCP server before you trust it: connect & enumerate the server
(sandboxed), run deterministic security detectors on the tool/resource/prompt definitions the
model would see, and emit a risk-scored report + a `frisk.lock` rug-pull baseline.

See `SPEC.md` for requirements (source of truth) and `docs/design/frisk-design.md` for the why.

## Architecture

- **Detector core** — pure, network-free, LLM-free Python package. Single source of truth for
  all detection logic (R23). Imported directly by the CLI; run under Pyodide in the M2
  playground. Detectors D1–D7 each take a normalized Inventory and emit Findings
  (`detector, severity, item, field, evidence`). Deterministic; a detector error is a finding,
  never a silent pass.
- **Connector** — the only component that touches the untrusted target. Spawns a stdio server
  or connects to a remote URL, completes the MCP handshake, enumerates tools/resources/prompts,
  and normalizes them (with raw bytes) into an Inventory. Owns the sandbox.
- **Sandbox (macOS)** — seatbelt profile (deny network, confine FS) + throwaway fake `$HOME` +
  scrubbed env + CPU/mem rlimits + hard timeout. `--no-sandbox` opt-out; warned lightweight
  fallback when seatbelt is unavailable (never a silent downgrade).
- **Reporter** — computes a weighted risk score + verdict, renders human/JSON reports, sets CI
  exit codes (0 clean / 1 warn / 2 high+). C0-escapes all read-back values before terminal
  output.
- **Lockfile / verify** — `frisk.lock` hashes every definition; `frisk verify` re-enumerates and
  diffs to catch rug-pulls. Explicit `"\n"` framing for hashing/diffing.
- **Playground (M2)** — static GitHub Pages site running the same detector core via Pyodide;
  paste `tools/list` JSON or best-effort CORS direct-connect; zero backend, nothing uploaded.

## Conventions

- Python 3.12, `uv` for deps, `ruff` for lint (run `uv run ruff check .` before done),
  `pytest` for tests. Fixture MCP server harness advertises poisoned/benign definitions.
- Never log or report raw secret/PII/auth-token values — categories, field names, and offsets
  only (S3).
- Work milestone-by-milestone (M1 → M2 → M3); `tasks/todo.md` holds only the active milestone.
