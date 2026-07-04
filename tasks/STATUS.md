# STATUS — frisk

**Updated:** 2026-07-04
**Active milestone:** M3 (Behavioral honeypot, R24) — planned, awaiting plan approval.
**Last done:** M3 plan written to `tasks/todo.md` (6 sections, ~19 tasks). Design: new
`frisk/sandbox/honeypot.py` emitting D8 Findings — decoy seeding w/ per-scan canary +
epoch atime, post-enumeration stat-diff access/tamper detection, canary-in-Inventory
exfil scan. Honeypot stays out of `frisk/core` (Pyodide purity, R23/N1).
**In progress:** none.
**Next action:** user reviews plan → `/implement` starting at task 1.1.
**Blockers:** none. Open design point resolved in plan: atime unreliability handled via
capability probe + stderr warning (no silent downgrade).
