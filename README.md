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

## Playground (browser, nothing uploaded)

Try the detectors without installing anything:
**<https://realgagenichols.github.io/frisk/>**

Paste the JSON result of an MCP `tools/list` call (a bare array, a `{"tools": […]}` object,
or a full JSON-RPC response) and hit **BEGIN SCREENING**. The page runs the *identical*
detector core as the CLI — the same Python package, executed in your browser via
[Pyodide](https://pyodide.org) — so the verdict matches `frisk scan`.

- **Privacy:** the site is static. No backend, no analytics, no storage; your definitions
  and any auth token never leave the browser. The only third-party request is the pinned
  Pyodide CDN — fonts and detector code are served from the site itself.
- **Direct connect (best-effort):** for remote streamable-HTTP servers that send CORS
  headers, the page can fetch `tools/resources/prompts` itself (browser → server, optional
  bearer token kept in memory only). Most servers don't allow cross-origin requests —
  paste mode is the reliable path.
- The playground scans *pasted/fetched definitions only*. Sandboxed live enumeration of
  stdio servers, lockfiles, and `frisk verify` need the CLI.

To run it locally: `python scripts/build_site.py && python -m http.server -d site`.

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
| D8 | behavioral honeypot (a stdio server that reads, tampers with, or exfiltrates the sandbox's decoy credentials during enumeration) |

Detectors D1–D7 are pure, deterministic, network-free, and LLM-free — the single source of
truth shared by the CLI and the browser playground, which runs the same code under Pyodide.
D8 is a CLI-only behavioral check (it observes the sandboxed process), so it does not run in
the playground.

## Behavioral honeypot

Beyond inspecting the *definitions*, `frisk` watches what a local stdio server actually **does**
during enumeration. It seeds the throwaway fake `$HOME` with realistic-looking **decoy
credentials** — `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.netrc`, `~/.config/gh/hosts.yml` —
each carrying a unique per-scan canary token, then reports:

| finding | severity | when |
|---------|----------|------|
| `decoy-access` | HIGH | the server **read** a decoy (detected via access-time diff) |
| `decoy-tamper` | HIGH | the server **modified or deleted** a decoy |
| `canary-exfiltration` | CRITICAL | a decoy's canary token surfaces in the **advertised definitions** — the server is smuggling stolen credentials back over the MCP channel |

A well-behaved server touches none of these. The decoy values are fake, and — like every other
finding — evidence references categories, paths, and byte offsets only, never the decoy
contents (so the report itself never carries credential-shaped material). Access detection
relies on filesystem access times; where the filesystem doesn't update them, `frisk` prints a
warning and keeps tamper + exfiltration detection active — never a silent downgrade. The
honeypot runs in every sandbox mode, including `--no-sandbox`, and gates `frisk verify` too: a
verify run that catches credential theft exits non-zero even when the definitions are unchanged.

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
