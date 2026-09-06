# Changelog

Notable changes to `mcp-frisk`. Dates are release dates; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- **`--fail-on {info,low,medium,high,critical}`** — the lowest severity that exits `2`.
  Default `high`, which is the previous behaviour exactly. It moves the exit code and
  nothing else: every finding still appears in the report.
- **Accepted-finding baselines** — `--write-baseline PATH` records a scan's findings;
  `--baseline PATH` stops them gating the build. Findings are keyed on
  `(detector, item, field, evidence category)`, so rewording a description does not
  invalidate the baseline, and a *new* category of finding on an already-accepted item is
  never suppressed. Accepted findings are still reported, and entries that no longer match
  anything are flagged as stale.
- **`--format sarif`** — SARIF 2.1.0 for GitHub code scanning. One rule per detector with a
  stable id; the result fingerprint is the same key the baseline uses, so a suppression in
  GitHub's UI and an entry in `frisk.baseline` mean the same thing.
- **`--config PATH`** — scan every server declared in a client config
  (`claude_desktop_config.json` / `.mcp.json`) in one pass. The exit code is the worst across
  all servers; one server failing to enumerate is reported without aborting the rest.
- **`--quiet`** — suppresses stderr warnings only. stdout and the exit code are untouched, so
  `--format json --quiet` is safe to pipe.

### Changed

- GitHub Actions are pinned to commit SHAs, with Dependabot to keep them moving.

## [0.1.0] — 2026-09-06

First public release.

### Added

- `frisk scan` — sandboxed connect-and-enumerate of a stdio or remote MCP server, with
  detectors D1–D7 over every advertised definition, a weighted risk score and verdict, human
  and JSON reports, and CI exit codes.
- `frisk verify` — re-enumerates a target and diffs it against a `frisk.lock` baseline to
  catch rug-pulls.
- **Behavioural honeypot (D8)** — decoy credentials seeded in the sandbox's fake `$HOME`,
  with per-scan canaries; detects a server reading, tampering with, or exfiltrating them,
  including base64-encoded exfiltration.
- **macOS seatbelt sandbox** — no network, a throwaway fake `$HOME`, scrubbed environment, a
  denylist covering credential stores, shell startup and history files, browser and messaging
  data, plus `.env` files anywhere; CPU limit and a hard wall-clock timeout.
- **Playground** — the identical detector core running in the browser under Pyodide, with no
  backend and nothing uploaded.

### Security

- Detectors scan **every** string a server advertises — `title`, `annotations`,
  `outputSchema`, `uri`, `_meta` and author-chosen property names included. Previously only
  `name`, `description` and `inputSchema` were read, so moving a payload one field over
  scored zero findings.
- URL credentials (userinfo and query-string secrets) are masked everywhere they are
  rendered, including in `frisk.lock`.
- The lockfile diff compares definitions as a multiset, so a poisoned twin of an existing
  tool name can no longer hide behind its namesake.
- Resource limits are probed rather than assumed; a limit the platform cannot enforce is
  named in a warning instead of silently claimed.
- An unexpected failure exits `2`, never `1` — a crash must not read as the milder
  "warnings" result.

[Unreleased]: https://github.com/Realgagenichols/frisk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Realgagenichols/frisk/releases/tag/v0.1.0
