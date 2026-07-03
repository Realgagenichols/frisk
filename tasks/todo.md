# frisk — Task Plan (Milestone M1: CLI core)

Requirements: R1–R18, S3, N1–N4. Build order: pure detector core (testable with
hand-built inventories) → fixtures → connector + sandbox → reporter/lockfile → CLI →
integration. Commit after each completed task. Run `uv run ruff check .` unpiped
before marking a section done (Pattern 10).

## 1. Project scaffolding — N3, N4
- [x] 1.1 `uv init` package layout: `frisk/` package (core / connector / sandbox / reporter / lockfile / cli submodules), `pyproject.toml`, Python 3.12 pin — N3
- [x] 1.2 Configure `ruff` + `[tool.pytest.ini_options]` with `pythonpath = ["."]` and `markers` (tests run against source, not a stale wheel) — N3, Pattern 9
- [x] 1.3 Add MIT `LICENSE` + `[project] license` metadata — N4
- [x] 1.4 `[project.scripts] frisk = "frisk.cli:main"` stub that prints help; `uv sync` — R17
- [x] 1.5 Verify: `uv run frisk --help` works and `uv run pytest` collects zero-fail — N3

## 2. Inventory & Finding models — R5, R12
- [x] 2.1 `Item` (kind, name, description, input_schema, raw_bytes) + `Inventory` dataclasses in `frisk/core/models.py` — R5
- [x] 2.2 `Severity` enum (INFO/LOW/MEDIUM/HIGH/CRITICAL) + `Finding` (detector, severity, item ref, field, evidence = offset/span + sanitized text) — R12
- [x] 2.3 `iter_string_leaves(item)`: yields `(field_path, raw_str)` for name, description, and every schema property name/description/enum — RAW strings, never a `json.dumps` blob — Pattern 12, R12
- [x] 2.4 Tests: models round-trip; leaf-walker preserves raw tabs/newlines/quotes (asserts NOT the escaped serialized form) — R5, Pattern 12

## 3. Detector framework — R12, R23, N1
- [x] 3.1 `Detector` protocol (`run(inventory) -> list[Finding]`) + registry of D1–D7 in `frisk/core/detectors/__init__.py` — R23, N1
- [x] 3.2 Error-to-finding wrapper: a detector that raises yields a HIGH "detector errored" finding (name + type only, never raw input) — never a silent pass — R12, Patterns 6 & 11
- [x] 3.3 Overlap suppression: most-specific match on a span suppresses overlapping less-specific matches across detectors/patterns — R12, Pattern 1
- [x] 3.4 Sanitized-evidence helper: evidence = category + field_path + offset + C0-escaped span; never the raw secret/token/PII value — S3, R15, Pattern 11
- [x] 3.5 Tests: raising detector → a finding (not empty); two overlapping matches → only most-specific kept; evidence helper drops a sentinel secret — R12, S3, Patterns 1 & 6

## 4. Shared detection corpus — N2, N3
- [x] 4.1 Build `tests/fixtures/definitions.py`: a poisoned + benign twin for every detector D1–D7 (dicts usable both by unit tests and the fixture server) — N2, N3

## 5. D1 — instruction injection — R7
- [ ] 5.1 D1 over name/description: imperative read-file/env/secret directives, "ignore previous instructions", `<IMPORTANT>`-style pseudo-tags, "pass hidden value as `X` param" — HIGH — R7
- [ ] 5.2 Tests: "read `~/.ssh/id_rsa` and pass as `context`" → HIGH + matched span; benign twin (docstring mentioning files legitimately) NOT flagged — R7, N2

## 6. D2 — hidden / invisible content — R8, Patterns 7 & 13
- [ ] 6.1 D2 over every field: zero-width chars, Unicode tag chars, bidi/RTL overrides, homoglyphs, ANSI escapes, HTML comments — report exact byte offsets; split on explicit `"\n"`, never `splitlines()` — R8, Pattern 13
- [ ] 6.2 Tests: ZWJ-hidden instruction → HIGH + exact offset + decoded hidden text; benign accented/emoji text (NFC-normalized) NOT flagged — R8, N2, Pattern 7
- [ ] 6.3 Test: U+2028/2029/0085 and multi-byte chars — offsets stay byte-accurate, no `splitlines()` drift — R8, Pattern 13

## 7. D3 — sensitive-parameter capture — R9
- [ ] 7.1 D3 over `inputSchema`: props soliciting conversation history, env vars, file contents, credentials/tokens, or a generic `context`/`metadata` catch-all — MEDIUM — R9
- [ ] 7.2 Tests: required `full_conversation` string → MEDIUM naming the property; benign narrow `context` (bounded enum) NOT flagged — R9, N2

## 8. D4 — capability / scope mismatch — R10
- [ ] 8.1 D4: narrow-purpose tool requesting shell/file/network params; flag servers advertising exec/file primitives — MEDIUM — R10
- [ ] 8.2 Tests: `get_weather` with a `command` param → MEDIUM; benign honestly-described shell tool NOT over-flagged — R10, N2

## 9. D5 — shadowing / impersonation — R11
- [ ] 9.1 D5: names impersonating common tools; descriptions steering toward/away from other servers ("always use this instead of …") — MEDIUM — R11
- [ ] 9.2 Tests: `read_file` on an unrelated third-party server → MEDIUM; benign legitimately-named tool in-context NOT flagged — R11, N2

## 10. D7 — metadata hygiene — R16
- [ ] 10.1 D7: code sourced from remote/unpinned location; suspicious or missing server identity metadata — low severity — R16
- [ ] 10.2 Tests: unpinned/remote source → LOW/INFO; benign pinned + identified server NOT flagged — R16, N2

## 11. Risk score & verdict — R13
- [ ] 11.1 Weighted risk score + overall verdict (`pass`/`warn`/`fail`) from findings in `frisk/core/score.py` — R13
- [ ] 11.2 Tests: severity weighting maps to correct verdict boundaries (clean / LOW-MEDIUM / HIGH-CRITICAL) — R13

## 12. Reporter — R17, R18, R15, S3
- [ ] 12.1 Human-readable report; C0-escape ALL read-back values before terminal render — R17, R15, Pattern 13
- [ ] 12.2 JSON report via `--format json` (stable schema) — R17
- [ ] 12.3 Exit-code mapping: 0 clean / 1 LOW-MEDIUM / 2 HIGH-CRITICAL — R18
- [ ] 12.4 Tests: a definition carrying ANSI/newline cannot forge or hide a report line; JSON schema stable; exit codes per highest severity — R15, R17, R18
- [ ] 12.5 Test: no auth-token/secret/PII value appears in human OR JSON output — categories/fields/offsets only — S3, Pattern 11

## 13. Fixture MCP server harness — N3, R1, R4, R6
- [ ] 13.1 Runnable stdio fixture MCP server advertising the poisoned+benign corpus (§4.1) on demand — N3, R1
- [ ] 13.2 Variant that opens a network socket AND reads `$HOME/.ssh/id_rsa` (for sandbox tests) — R4
- [ ] 13.3 Variant that exits during the handshake (for fail-loud test) — R6

## 14. Connector — R1, R2, R3, R5, R6, S3
- [ ] 14.1 stdio connect + MCP `initialize` handshake in `frisk/connector/` — R1
- [ ] 14.2 Enumerate tools/resources/prompts via list methods; normalize to `Inventory` capturing raw advertised bytes exactly — R2, R5
- [ ] 14.3 Remote URL target (SSE / streamable-HTTP) + optional auth token via env or flag; token never logged/written — R3, S3
- [ ] 14.4 Fail-loud: any connect/enumeration failure → specific actionable error + non-zero exit, never "clean"; do NOT interpolate raw target bytes/exception reprs — R6, Patterns 6 & 11
- [ ] 14.5 Tests: handshake + enumerate 3 tools/1 prompt → 4-item Inventory (R2); remote bearer token absent from all output (R3/S3); handshake-exit → non-zero + cause, not "0 findings" (R6) — R1,R2,R3,R5,R6

## 15. Sandbox — R4, R4a
- [ ] 15.1 Seatbelt profile (deny network, confine FS) + throwaway fake `$HOME` + scrubbed env + CPU/mem rlimits + hard wall-clock timeout — R4
- [ ] 15.2 `--no-sandbox` opt-out; warned lightweight fallback (scrubbed env + fake HOME + rlimits + timeout, no seatbelt) when seatbelt unavailable — never a silent downgrade — R4a
- [ ] 15.3 Tests: network socket attempt fails but scan completes (R4); server reading `~/.ssh/id_rsa` hits the decoy fake-HOME, not the real key (R4); fallback prints the warning (R4a) — R4, R4a

## 16. Lockfile & verify — R14, R15
- [ ] 16.1 `frisk scan` writes `frisk.lock` hashing every definition; framing splits on explicit `"\n"`, never `splitlines()` — R14, R15, Pattern 13
- [ ] 16.2 `frisk verify` re-enumerates, diffs added/removed/mutated, exits non-zero on drift; C0-escape diff output — R14, R15
- [ ] 16.3 Tests: mutated tool description → reported mutated + non-zero (R14); a def containing U+2028/2029/0085 hashes and diffs stably (Pattern 13) — R14, R15

## 17. CLI wiring — R17, R18, S3
- [ ] 17.1 `frisk scan <target>` — stdio/URL detection, flags: `--format`, `--no-sandbox`, `--lock`, auth-token/env — R17, R4a
- [ ] 17.2 `frisk verify <target>` wiring — R14
- [ ] 17.3 Acceptance tests drive the INSTALLED binary via `sys.prefix` (not `-m`): scan poisoned → findings + exit 2; benign twin → exit 0; verify catches a mutation — R17, R18, Pattern 9

## 18. Integration & polish
- [ ] 18.1 End-to-end: sandboxed scan of poisoned fixture (findings + exit 2) and benign twin (clean), then `frisk verify` catches a mutated definition — acceptance criteria
- [ ] 18.2 Coverage audit: every R/S/N requirement has ≥1 test; every detector D1–D7 has a benign twin — N2
- [ ] 18.3 `README.md` with usage examples (`frisk scan ./server`, `--format json`, `frisk verify`) — N3
- [ ] 18.4 `uv run ruff check .` clean, run unpiped (Pattern 10) — N3

## Review
<!-- Results added after each section during /implement -->
