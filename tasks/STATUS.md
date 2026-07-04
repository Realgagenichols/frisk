# STATUS — frisk

**Updated:** 2026-07-03
**Active milestone:** M1 (CLI core) — ✅ COMPLETE and merged to `main`.
**Last done:** M1 merged (commit 0bcb9c7). 150 tests pass, ruff clean. Plan archived to
`tasks/todo.2026-07-03.md`. Review gate passed (1 warning fixed: unwritable-lock handling).
**In progress:** none.
**Next action:** `/clear`, then `/plan` M2 (playground — R20–R23: GitHub Pages + Pyodide
running the same detector core; paste-JSON + best-effort CORS direct-connect; zero backend).
**Blockers:** none.

M2 note: the detector core (`frisk/core/`) is already pure/stdlib-only/Pyodide-safe by design
(N1/R23). The reporter (`frisk/core/report.py`) is in core too, so the playground reuses it.
The connector/sandbox/CLI are CLI-only and out of the browser's reach.
