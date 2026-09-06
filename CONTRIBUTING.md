# Contributing

Bug reports, evasions, and false positives are all welcome. If you have found a way to slip
something past a detector, that is a *feature request with evidence* — open an issue with the
payload. For anything that looks like a containment failure or a leak, read
[SECURITY.md](SECURITY.md) first; those go through private disclosure.

## Setup

```bash
git clone https://github.com/Realgagenichols/frisk.git && cd frisk
uv sync
uv run pytest -q
uv run ruff check .
```

> **macOS:** if `uv run frisk` fails with `ModuleNotFoundError`, see the note at the end of
> the README's Development section — a background agent under `~/Desktop` / `~/Documents`
> re-hides the editable install's `.pth` file, and CPython skips hidden `.pth` files.

The browser end-to-end for the playground is separate and needs Playwright:

```bash
npm i playwright && npx playwright install chromium
uv run python scripts/build_site.py
uv run python -m http.server 8912 -d site &
node scripts/e2e_playground.mjs ./screenshots
```

## The bar for a detector change

frisk's whole value is that a `FAIL` is worth acting on and a `PASS` is worth something. Both
directions of error are costly, so a rule change needs both directions covered:

1. **A positive test** with the payload the rule is meant to catch.
2. **A benign twin** (N2) — the most ordinary sentence you can write that the rule might trip
   on, asserted clean. `"Pass your API key as the api_key parameter"` is normal REST
   documentation; `"credentials are read from ~/.aws/credentials by the AWS SDK"` is normal
   prose about a third party. A HIGH finding means exit `2`, so a false positive on an honest
   server is expensive.
3. **A watched failure** (N6). Delete or weaken your rule, run the suite, and confirm your new
   test goes red. A test that passes with the feature removed is not a test. Several rules in
   this repo were found to be entirely unguarded exactly this way.

If you add to a constant like `_COMMON_TOOL_NAMES`, extend the **literal expectation list** in
`tests/test_mutation_gaps.py` too — parametrizing over the constant itself renames the test
case along with the entry, so it cannot see the entry change.

## Conventions

- Python 3.12+, `uv` for dependencies, `ruff` for lint (100 columns), `pytest` for tests.
- `frisk/core/` is pure: no network, no filesystem, no LLM. It runs unchanged in the browser
  under Pyodide, so anything touching the outside world belongs in `connector/` or `sandbox/`.
- Never write a raw secret, decoy value, auth token, or credential-bearing URL into a report,
  a log line, or `frisk.lock`. Evidence carries categories, field paths, and byte offsets.
- Every server-derived string is C0-escaped before it reaches a terminal. If you add a new
  place that prints a `Finding` field, route it through `c0_escape`.
- Invisible characters in source — corpus, regexes, tests — are written as `\uXXXX` escapes,
  never literals. A literal zero-width character is unreviewable in a diff.
- Fail loudly. A scan that could not complete must never render as "no findings", and an
  error message names the phase and the exception *type*, never the target's bytes.

## Pull requests

CI runs ruff and pytest on macOS and Linux across Python 3.12 and 3.13; the macOS jobs are the
ones that exercise the seatbelt sandbox. Please keep the suite green and add a line to
`CHANGELOG.md` under *Unreleased* for anything user-visible.
