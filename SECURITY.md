# Security Policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub's private vulnerability reporting](https://github.com/Realgagenichols/frisk/security/advisories/new)
rather than opening a public issue.

Include the version or commit, your platform, and the smallest input that reproduces the
problem — for `frisk` that is usually a `tools/list` JSON payload or a minimal MCP server.
Expect an initial response within a week.

## What counts as a vulnerability in frisk

`frisk` runs untrusted code and reads untrusted definitions, so the interesting failures are
about containment and about lying to the user. These are vulnerabilities:

- **Sandbox escape.** A stdio server reaching the network, reading a credential store on the
  denylist, writing outside the sandbox scratch and temp roots, or surviving the wall-clock
  timeout.
- **Secret disclosure.** Any auth token, decoy canary, URL credential, or raw sensitive value
  reaching stdout, stderr, a report, or `frisk.lock`. Evidence is meant to carry categories,
  field paths, and byte offsets only (S3).
- **Terminal or report forgery.** Server-controlled text that escapes C0 sanitisation and
  forges, hides, or rewrites report lines.
- **A false clean.** Any path where enumeration fails or a detector errors and `frisk` still
  reports "no findings" or exits `0`. Failing loudly is a security property here, not a
  nicety.
- **Rug-pull evasion.** A definition change that `frisk verify` reports as unchanged.
- **Resource exhaustion** in the detector core, which runs on attacker-chosen input outside
  the enumeration timeout.

## What does not count

- **A detector missing a novel injection phrasing.** D1–D7 are deterministic heuristics.
  A PASS means "nothing detected", not "proven safe", and the README says so. Evasions are
  very welcome as issues — they make the tool better — but they are not treated as
  vulnerabilities and do not need private disclosure.
- **A false positive**, unless it is a denial of service in disguise.
- **Reads outside the sandbox denylist.** Filesystem reads are allow-by-default so that an
  arbitrary interpreter can start; the denylist and the closed network are the boundary. See
  "The sandbox" in the README for exactly where that line sits. A gap *in* the denylist —
  a common credential store that is readable — is a vulnerability; the design being
  allow-by-default is not.
- **Anything requiring `--no-sandbox`.** That flag is documented as opting out of
  containment.

## Supported versions

Pre-1.0: only the latest `main` is supported. There is no backporting yet.

## Scope

This policy covers the `frisk` CLI, the detector core, and the playground at
`realgagenichols.github.io/frisk`. The playground is static, has no backend, and stores
nothing — pasted definitions and any auth token never leave the browser. Its only
third-party request is the pinned Pyodide CDN.
