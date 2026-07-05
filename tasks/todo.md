# frisk — M3 Task Plan (Behavioral honeypot, R24)

**Design (approved via /plan):** New module `frisk/sandbox/honeypot.py` — lives in the
sandbox package (needs FS), NOT in `frisk/core` (core stays pure for Pyodide, R23/N1).
Emits standard `Finding` objects with detector id `D8` so score/report/exit-code pipelines
work unchanged. Three mechanisms:
1. **Seed** — decoy credential files in the fake HOME, each embedding a unique per-scan
   canary token; atime deliberately set to epoch (< mtime, so even relatime-style mounts
   update it on first read).
2. **Access/tamper inspection** — post-enumeration stat diff against the seeded baseline:
   atime advanced → `decoy-access` HIGH; mtime/size/content changed or file deleted →
   `decoy-tamper` HIGH.
3. **Exfil canary scan** — canary token found in the enumerated Inventory (raw bytes or
   server_info) → `canary-exfiltration` CRITICAL (the MCP channel is the only exfil path
   the seatbelt leaves open).
No silent downgrade: an atime capability probe warns when the FS can't support access
detection (canary scan still works). Remote targets get no honeypot (no sandbox → no fake
HOME). Applies in all sandbox modes (seatbelt / fallback / disabled) since fake HOME always
exists.

## 1. Decoy seeding — `frisk/sandbox/honeypot.py`
- [x] 1.1 `DecoySet` dataclass (canary token, decoy paths, per-file stat baseline) +
      `seed_decoys(fake_home) -> DecoySet`: write decoys `.ssh/id_rsa` (fake PEM),
      `.aws/credentials`, `.netrc`, `.config/gh/hosts.yml` with realistic-shaped fake
      content embedding one per-scan random canary (`secrets.token_hex`), then
      `os.utime(atime=0)` and record `(st_atime_ns, st_mtime_ns, st_size)` baselines — R24
- [x] 1.2 Atime capability probe in `seed_decoys`: seed+read a probe file; if atime did not
      advance, set `DecoySet.atime_reliable = False` (consumed by 4.2 warning) — R24, R4a spirit
- [x] 1.3 Tests `tests/test_honeypot.py`: seeding creates all decoys with canary inside;
      baseline recorded; our own seed/stat sequence does NOT count as access (inspect
      immediately after seed → zero findings); two scans get different canaries — R24
      (`uv run pytest tests/test_honeypot.py`)

## 2. Access / tamper inspection
- [x] 2.1 `inspect_decoys(decoys) -> list[Finding]`: stat each decoy vs baseline —
      atime advanced → HIGH `D8` finding (category `decoy-access`); mtime/size changed →
      HIGH `decoy-tamper`; missing file → HIGH `decoy-tamper`. Evidence = decoy relative
      path + category only, NEVER file contents (S3); `item_ref` = `honeypot:<relpath>` — R24, R12, S3
- [x] 2.2 Inspection error path: a stat failure other than FileNotFoundError emits an INFO
      `honeypot-error` finding — a detector error is a finding, never a silent pass — R12
- [x] 2.3 Tests: untouched decoys → no findings; `read_text()` on a decoy → `decoy-access`;
      append to a decoy → `decoy-tamper`; delete → `decoy-tamper`; unique field paths for
      evidence anchors (lesson: evidence anchors need unique field paths) — R24
- [x] 2.4 Benign-twin test (N2 + lesson "breaking-string treatment"): full seed → sleep-free
      no-op → inspect twice in a row stays clean; `os.stat`/`os.path.exists` on decoys by
      the inspector itself must not flip atime — N2

## 3. Exfiltration canary scan
- [x] 3.1 `scan_for_canary(inventory, decoys) -> list[Finding]`: search each item's
      `raw_bytes` (raw form, not a re-serialization — Pattern 12) and `server_info` values
      for the canary token → CRITICAL `D8` finding (category `canary-exfiltration`) with
      item ref + field + offset; snippet is the category label, not surrounding decoy
      content (S3) — R24, S3
- [x] 3.2 Tests: inventory with canary embedded in a tool description raw bytes → CRITICAL
      with correct item_ref/offset; canary in `server_info.instructions` → CRITICAL; benign
      inventory containing a hex string of the same length/shape as a canary → NOT flagged
      (N2, false-positive twin) — R24, N2

## 4. Sandbox + CLI integration
- [x] 4.1 `prepare_stdio` calls `seed_decoys` for every mode (seatbelt/fallback/disabled);
      `SandboxResult` gains `decoys: DecoySet`; drop the now-obsolete bare
      `.ssh` mkdir + M3 comment in `_make_fake_home` — R24
- [x] 4.2 CLI `_enumerate` restructure (`frisk/cli.py`): after enumeration and BEFORE
      `_cleanup` rmtree, run `inspect_decoys` + `scan_for_canary`; return
      `(inventory, honeypot_findings)`; print the atime-degraded warning to stderr when
      `not decoys.atime_reliable` (no silent downgrade); remote targets return `[]` — R24
- [x] 4.3 `_cmd_scan`: merge honeypot findings with detector findings before `assess()` —
      they flow into score, verdict, human/JSON report, and exit code with no reporter
      changes (verify rendering of `honeypot:` item refs reads sensibly, adjust only if
      broken) — R24, R13, R17, R18
- [x] 4.4 `_cmd_verify`: honeypot findings printed to stderr and force exit 2 even when the
      lock diff is clean — a verify run that catches credential theft must not exit 0 — R24, R18
- [x] 4.5 Unit tests: sandbox result carries decoys in all three modes; scan of a
      poisoned-inventory + honeypot-clean run produces identical output to M2 behavior
      (regression: honeypot integration changes nothing when decoys untouched); update
      `test_seatbelt_reads_decoy_home_not_real_key` — probe now READS decoy content
      (assert canary present, real key absent) instead of "unreadable" — R24

## 5. Fixture modes + end-to-end
- [x] 5.1 Add fixture modes to `tests/fixtures/mcp_server.py`: `snoop` (reads
      `$HOME/.ssh/id_rsa` at startup, serves benign tools) and `thief` (reads
      `$HOME/.aws/credentials`, embeds its contents in a tool description → exfil via the
      enumeration channel) — R24, N3
- [x] 5.2 Integration tests (`tests/test_integration.py` or new `test_honeypot_e2e.py`),
      spawning through `prepare_stdio` + `enumerate_target`:
      *Given* the `snoop` server, *Then* a `decoy-access` HIGH finding and exit 2;
      *Given* the `thief` server, *Then* `canary-exfiltration` CRITICAL and exit 2;
      *Given* the `benign` server (twin, N2 — includes Python interpreter startup noise),
      *Then* ZERO D8 findings and exit code unchanged from M2 — R24, N2, R18
- [x] 5.3 CLI acceptance tests: `frisk scan --format json` on `thief` includes the D8
      finding in JSON; report stdout NEVER contains the decoy private-key body or raw
      canary-adjacent decoy content (S3 sentinel test, Pattern 11 style); `frisk verify`
      against `snoop` exits 2 with honeypot warning on stderr — R24, S3, R17
- [x] 5.4 `--no-sandbox` e2e: honeypot still seeds and detects in disabled mode — R24

## 6. Polish & gate
- [ ] 6.1 README: honeypot section (what's seeded, what's detected, D8 severities) — R24
- [ ] 6.2 `uv run ruff check .` clean + full `uv run pytest` green — N3
- [ ] 6.3 `/review --fix` final gate; check M3 milestone box in SPEC.md; update STATUS.md
- [ ] 6.4 Commit per section, staging by explicit path (Pattern 15 — no `git add -A`)

## Review
<!-- Results added after each section -->
