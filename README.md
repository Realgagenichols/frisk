# frisk

**Vet a third-party MCP server before you trust it.**

`frisk` connects to an MCP server — **sandboxed by default** — pulls the real
tool/resource/prompt definitions the model would see, runs deterministic security detectors
on them, and emits a risk-scored report. It also writes a `frisk.lock` baseline so a later
re-scan catches **rug-pulls** (a server that ships benign, then mutates after you approve it).

`frisk` is the "vet before you install" sibling to `tollbooth` (runtime firewall) and
`claude-dlp-guard` (read-time DLP): **vet → firewall → guard**.

## Why

People install third-party MCP servers like npm packages, with near-zero vetting. The tool
`description` the model reads is an instruction channel — and it can hide file-exfiltration
directives, zero-width/bidi-smuggled text, sensitive-parameter capture, capability creep, and
tool impersonation. `frisk` inspects exactly what the model would receive, before you connect
for real.

## Install

```bash
uv sync           # sets up the venv and the `frisk` console script
```

## Usage

```bash
# Scan a local stdio server (sandboxed by default). frisk options come BEFORE the command;
# everything after the command is passed through to the server.
frisk scan npx -y @acme/weather-mcp

# Machine-readable output for CI
frisk scan --format json npx -y @acme/weather-mcp

# Scan a remote server; the bearer token is read from an env var, never the command line
FRISK_AUTH_TOKEN=... frisk scan https://mcp.example.com/sse

# Re-scan later and diff against the baseline to catch a rug-pull
frisk verify npx -y @acme/weather-mcp
```

### Exit codes (CI gate)

| code | meaning |
|------|---------|
| `0`  | clean — no findings above INFO |
| `1`  | warnings — LOW/MEDIUM findings |
| `2`  | HIGH/CRITICAL findings, drift on `verify`, or an operational error |

## Detectors

| id | detects |
|----|---------|
| D1 | instruction injection (read-secrets directives, "ignore previous instructions", `<IMPORTANT>` pseudo-tags, covert exfil-as-parameter) |
| D2 | hidden/invisible content (zero-width, Unicode tag chars, bidi overrides, ANSI escapes, HTML comments, homoglyphs) with exact byte offsets |
| D3 | sensitive-parameter capture (conversation history, env vars, file contents, credentials, unbounded catch-alls) |
| D4 | capability/scope mismatch (a "weather" tool that also takes a `command`) |
| D5 | shadowing / impersonation (common tool-name collisions, steering language) |
| D6 | rug-pull (the `frisk.lock` baseline + `frisk verify` diff) |
| D7 | metadata hygiene (remote/unpinned code sourcing, missing/unpinned server identity) |

Detectors are pure, deterministic, network-free, and LLM-free — the single source of truth
shared by the CLI and (in M2) a browser playground running the same code under Pyodide.

## Sandbox (macOS)

Local stdio servers run under a seatbelt profile that **denies all network** and **denies the
real HOME's credential stores** (`~/.ssh`, `~/.aws`, keychains, …), inside a throwaway fake
`$HOME`, with a **scrubbed environment** (frisk's own secrets never reach the untrusted
server), CPU/memory rlimits, and a hard wall-clock timeout.

- `--no-sandbox` opts out of the seatbelt layer.
- Where `sandbox-exec` is unavailable, frisk falls back to the lightweight layers (fake HOME +
  scrubbed env + rlimits + timeout) **with a printed warning** — never a silent downgrade.

## Security posture

`frisk` never logs or reports the value of an auth token, secret, or sensitive schema field —
evidence references categories, field names, and byte offsets only. All server-derived text is
control-character-escaped before it reaches your terminal, so a malicious definition can't
forge or hide report lines.

## Development

```bash
uv run pytest          # full suite (fixture MCP server harness spins up real subprocesses)
uv run ruff check .    # lint
```

## License

MIT — see `LICENSE`.
