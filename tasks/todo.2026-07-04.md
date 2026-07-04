# frisk — Task Plan (M2: Playground — R20–R23)

> Context: detector core (`frisk/core/`) is verified Pyodide-safe (STATUS de-risk 2026-07-04).
> Gap found during planning: MCP-JSON → Inventory normalization (`_canonical_bytes`, item
> builders) lives in `frisk/connector/enumerate.py`, which the browser can't reach. Section 1
> moves it into core and makes the connector delegate — one normalization definition (R23).

## 1. Core ingest — paste-JSON → Inventory
- [x] 1.1 Create `frisk/core/ingest.py`: move `_canonical_bytes` + `_tool_item`/`_resource_item`/`_prompt_item` logic from `frisk/connector/enumerate.py`, reworked to take **plain dicts** (`item_from_tool(d)`, etc.). Connector converts SDK models via `model_dump(mode="json", exclude_none=True)` and delegates. Verify hashes unchanged: `uv run pytest tests/test_connector.py tests/test_lockfile.py` — R23
- [x] 1.2 Add `inventory_from_json(text: str) -> Inventory` to ingest: accept a bare tools array, `{"tools": [...], "resources": [...], "prompts": [...]}` (any subset), and a JSON-RPC envelope `{"result": {...}}`; optional `serverInfo`/`instructions` → `Inventory.server_info`. Anything else raises `IngestError` with a specific, actionable message (Pattern 6) — R21
- [x] 1.3 Write `tests/test_ingest.py`: one test per accepted shape; malformed inputs (non-JSON, wrong top-level type, item missing `name`) each raise `IngestError` naming the problem. `uv run pytest tests/test_ingest.py` — R21
- [x] 1.4 Parity test: the same definition through connector normalization and through ingest yields **byte-identical** `raw_bytes` and identical findings (guards lockfile-hash compatibility). Include a case where pasted JSON carries `‍`-escaped hidden chars — they decode to raw chars before scanning (Pattern 12; lesson: keep escapes as `\uXXXX` in source/fixtures) — R23
- [x] 1.5 Benign-twin paste fixture: ordinary `tools/list` output with legit-but-odd fields (e.g. `annotations`, extra vendor keys) → parses clean, zero findings — N2, R21

## 2. Pyodide bundle — single-source build
- [x] 2.1 `scripts/build_site.py`: zip `frisk/__init__.py` + `frisk/core/**` from the repo source tree into `site/dist/frisk_core.zip`; gitignore `site/dist/`. The bundle is always *generated* from source — no committed/hand-copied detector code anywhere — R23, R20
- [x] 2.2 Write `tests/test_site_bundle.py`: run the build script, unpack the zip to a temp dir, and in a subprocess with `mcp`/`anyio`/`pydantic`/HTTP modules blocked (recreate the de-risk import-blocker), run the full pipeline: `inventory_from_json` → `run_detectors` → `assess` → `render_json` on a poisoned paste. `uv run pytest tests/test_site_bundle.py` — R20, R23

## 3. Playground site — paste mode
- [x] 3.1 Scaffold `site/` (index.html, style.css, app.js) — invoke the **frontend-design skill** for the UI; pin Pyodide to an exact CDN version (Pattern 5) — R20
- [x] 3.2 `site/scan.py` (Pyodide bootstrap, loaded by JS): unpack `frisk_core.zip`, define `scan_json(text) -> str` = ingest → `run_detectors` → `assess` → `render_json`, with verdict + score included. Site-glue only; zero detector logic — R20, R23
- [x] 3.3 app.js: init Pyodide + load bundle with a visible loading state; paste textarea + Scan button; `IngestError` message shown as an error banner (loud, never a blank "clean") — R21
- [x] 3.4 Report rendering: verdict badge, risk score, findings list (severity, item ref, field, message, evidence snippet/offset). **Every dynamic value inserted via `textContent`/`createTextNode` — never `innerHTML`** (evidence snippets are attacker-controlled; browser analog of R15's C0-escaping) — R21, R15
- [x] 3.5 Bundled example JSONs (poisoned + benign twin) with "Load example" buttons; invisible chars stored as `\uXXXX` escapes in the fixture files (lesson) — R21, N2
- [x] 3.6 Zero-backend audit: page makes no requests except the pinned Pyodide CDN and same-origin assets; no analytics, no storage; footer states nothing leaves the browser — R22

## 4. Direct-connect (best-effort CORS)
- [x] 4.1 `site/connect.js`: minimal MCP streamable-HTTP client via `fetch` — JSON-RPC `initialize` handshake, then `tools/list`, `resources/list`, `prompts/list`; optional Bearer token from a `type=password` input. (Connector logic, not detector logic — a JS transport doesn't violate R23) — R22
- [x] 4.2 Feed fetched lists through the exact same `scan_json` path as paste mode — one scan path, no divergence — R22, R23
- [x] 4.3 Token hygiene: token held in memory only (no localStorage/cookies/URL params), sent only to the user-typed target URL — R22, S3
- [x] 4.4 CORS/network failure → specific error naming the failure + guidance to fall back to paste mode; never renders a clean report from a failed fetch (R6 spirit) — R22

## 5. Deploy
- [x] 5.1 `.github/workflows/pages.yml`: on push to `main` — checkout, `python scripts/build_site.py`, upload `site/` artifact, deploy to GitHub Pages (note: enabling Pages "GitHub Actions" source in repo settings is a manual step for Gage) — R20
- [x] 5.2 README: Playground section — URL, paste-mode usage, direct-connect caveats (CORS), privacy note — R20, R22

## 6. Integration & polish
- [x] 6.1 Local browser verification (`python -m http.server -d site`): poisoned example → findings + verdict match `frisk scan` on the equivalent fixture; benign example → clean. Record results in Review — R20, R21, R23
- [x] 6.2 Verify direct-connect failure path against a non-CORS URL (error + paste-mode guidance shown) — R22
- [x] 6.3 `uv run ruff check .` clean; full `uv run pytest` passes — N3
- [x] 6.4 Check off M2 in SPEC.md Milestones; overwrite tasks/STATUS.md

## Review

**§1 (core ingest)** — reviewer: ready. 1 WARNING (paste-vs-CLI raw_bytes divergence on
`_meta`/AnyUrl/null-key shapes) resolved as a documented deliberate limitation + lesson;
fixture canonicalization deduped. Parity tests prove byte-identical hashes + findings for
round-trip-clean definitions; lockfile hashes unchanged by the refactor.

**§2 (Pyodide bundle)** — reviewer: ready. Fixed: commit scoping (history rewritten before
push), drift guard now inspects the built zip manifest. Bundle proven to run the full
pipeline with mcp/anyio/pydantic/HTTP blocked and imports resolving from the bundle (P9).

**§3 (site paste mode)** — reviewer: ready, 0 warnings. textContent-only rendering verified
by grep + attribute-flow audit; zero-backend audit clean; INFO polish applied (benign
get_weather twin, reduced-motion beam).

**§4 (direct-connect)** — reviewer: ready. 1 WARNING fixed: CRLF SSE framing (tested LF+CRLF
with leading notification events). Token audit clean: one sink (Authorization header to the
typed URL), no storage/logging. Verified against a real streamable-HTTP FastMCP server.

**§6 (browser E2E, Playwright)** — boot→ready; poisoned example FAIL 100/100 with
D1,D2,D3,D4,D7 (identical to scan.py/CLI pipeline on same input); benign PASS + clean note;
malformed paste → loud IngestError banner; XSS probe (`<img onerror>`/`<script>` in
name/description) rendered inert, zero injected elements; direct-connect to non-CORS URL →
specific error + paste guidance; request origins = same-origin + pinned jsdelivr only.
Screenshot review caught a real bug ([hidden] beaten by author display) — fixed + lesson.
Script committed as scripts/e2e_playground.mjs.

**Final gate** — pytest 178/178 (unpiped exit 0), ruff clean. Spec coverage: R20 ✅ R21 ✅
R22 ✅ (MAY implemented; SHALL subclauses verified) R23 ✅. SPEC M2 checked off.
