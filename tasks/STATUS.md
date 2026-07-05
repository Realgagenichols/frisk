# STATUS — frisk

**Updated:** 2026-07-05
**Active milestone:** M3 (Behavioral honeypot, R24) — implementing.
**Last done:** §1–§4 complete + section-reviewed + fixes applied. Honeypot wired into sandbox
(seeds every mode) and CLI (scan merges D8 findings; verify gates on HIGH+; atime-degraded
warning). 204 tests green, ruff clean. §4 review fix: C0-escape verify honeypot stderr line.
**In progress:** §5 fixture modes + end-to-end.
**Next action:** task 5.1 — add `snoop` + `thief` fixture modes to
`tests/fixtures/mcp_server.py`, then 5.2–5.4 e2e/acceptance tests. Then §6 (README + gate).
**Blockers:** none.
