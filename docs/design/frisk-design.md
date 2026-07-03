# frisk — Design Rationale

Records the *why* behind the decisions, and the alternatives considered and rejected.

## Context

The author's portfolio has a strong, differentiated thread in **AI-agent security**
(`tollbooth`, a runtime MCP firewall/DLP/audit gateway; `claude-dlp-guard`, a read-time DLP
hook). Fintech-domain products were deliberately avoided to steer clear of employment IP-
assignment entanglement. `frisk` extends the agent-security thread with the missing piece:
**pre-trust vetting** of an MCP server. The trio reads as **vet → firewall → guard**.

## Decision 1 — Product: MCP server security scanner

Chosen over an agent credential broker and other agent-security ideas. Rationale: novel and
unsolved (MCP adoption is exploding with near-zero vetting culture), deterministic and self-
contained (a rules engine + report, no service to run, no LLM), and maximally cohesive with
the existing portfolio. The credential broker was rejected as heavier, service-like, and
competing with established tools (Vault).

## Decision 2 — Analysis mode: connect & enumerate (sandboxed)

Alternatives: static-only (never execute) and hybrid.

- Static-only was rejected as blind to runtime-generated tool definitions — many servers build
  their `tools/list` in code, so the descriptions the model actually sees are not statically
  extractable. Ground truth requires enumeration.
- Connecting yields exactly what the model would receive, and is the natural motion of a
  "vet before you install" flow (you were going to run the server anyway).
- Hybrid (static + connect, with discrepancy detection) is genuinely valuable for catching
  deception but is ~1.5–2× the build; deferred as a possible future enhancement.

Consequence: `frisk` executes untrusted code, which forces a real sandbox story (Decision 4).

## Decision 3 — Web delivery: browser-only playground + CLI (hybrid)

GitHub Pages is static-only: it cannot spawn processes or bypass CORS. Therefore:

- Local **stdio** servers are unreachable from a browser, full stop — only the CLI can vet them.
- Remote **URL** servers are reachable via `fetch`/SSE but blocked by CORS unless the server
  opts in (rare).
- The **detector + report layer is pure** and runs perfectly in the browser.

Rejected: a hosted backend proxy that auto-connects to arbitrary URLs. It would take on SSRF
liability and — worse — put users' auth tokens in transit through our infrastructure, an
unacceptable custody burden for a security tool, while *still* being unable to reach local
stdio servers.

Chosen: the CLI does real sandboxed enumeration (the power tool); the Pages playground runs the
detectors client-side over pasted `tools/list` JSON (or a best-effort CORS direct-connect).
This is not a compromise — "everything runs in your browser, nothing is uploaded, your token
never leaves your machine" is a stronger, on-brand security posture (cf. `splashpass`).

## Decision 4 — Detector single-source: Python core + Pyodide

The detectors are the crown jewels and must give identical verdicts in the CLI and the
playground; a discrepancy would be an embarrassing bug for a security tool. Options:

- **Python + Pyodide (chosen):** one Python detector package, run natively by the CLI and under
  Pyodide (Python-in-WASM) in the browser. Single source of truth, 100% Python (portfolio-
  consistent), simplest. Cost: a heavier browser bundle and slower first load — acceptable for
  a demo playground.
- **Rust core → PyO3 + WASM (rejected for now):** the most elegant and the lightest/fastest in
  both frontends, but introduces Rust and a real toolchain to an all-Python body of work.
- **Dual Python + TypeScript with a shared conformance corpus (rejected):** snappy in each
  frontend but duplicates the core product logic, cutting against the simplicity-first
  principle; parity would depend on discipline.

## Decision 5 — Sandbox: seatbelt + fake HOME + rlimits

macOS `sandbox-exec` (seatbelt) profile denies network and confines the filesystem; a throwaway
fake `$HOME` prevents reads of the real `~/.ssh` / `~/.aws`; scrubbed env, CPU/memory rlimits,
and a hard timeout bound the blast radius. Zero external dependencies and it works today
(seatbelt is technically deprecated by Apple but still fully present, with no removal announced).
Docker was rejected as a default for requiring an installed/running daemon; it can return later
as an opt-in `--docker` flag. A lightweight, seatbelt-less mode is the warned fallback when
seatbelt is unavailable — never a silent downgrade. The fake `$HOME` is also the natural seam
for the M3 behavioral honeypot (decoy secrets).

## Decision 6 — Name: frisk

Border/inspection theme, pairing with `tollbooth`. Earlier candidates were rejected: `customs`
(too vague), `barbican` / `sallyport` / `declarant` (too obscure), `inspector` (collides with
the official MCP Inspector), `mcp-scan` (Invariant Labs' tool), `gatekeeper` (Apple's feature).
`frisk` is a common word, unmistakably about searching for hidden things, and reads well as a
command: `frisk ./mcp-server`.

## Cross-cutting lessons applied

- **Pattern 13** (writer/reader framing, control-char escaping): lockfile hashing and `verify`
  diffing use explicit `"\n"` framing; all read-back values are C0-escaped before terminal
  render (R15). Hidden-content detection (D2/R8) directly targets this class of smuggling.
- **Pattern 1** (overlapping specificity): most-specific detector/pattern match suppresses the
  less-specific overlap (R12).
- **Pattern 2** (false positives from valid data): every detector ships a benign twin (N2).
- **Pattern 6** (fail-fast): enumeration failure never reports "clean"; it fails loudly with a
  non-zero exit (R6).
