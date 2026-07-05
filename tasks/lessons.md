# Lessons — frisk


- **Evidence anchors need unique field paths.** Any `(field_path, offset)` evidence scheme
  requires every path to resolve to exactly ONE string. Dict keys vs. values collided on the
  same path in the leaf walker (§2 review); key leaves now get a `#key` suffix. When adding
  new leaf sources, add them to `test_leaf_walker_field_paths_are_unique`.
- **Schema keywords are leaf noise.** `_walk` yields JSON Schema structural keys (`type`,
  `properties`, `description`) as `#key` leaves. Detectors matching generic words must not
  anchor on schema-keyword leaves (D3/D4: match property names by position, not any leaf).
- **Scan everything the model sees, not just the documented fields.** Limiting prose rules
  to `description` left a trivial relocation bypass via schema `title`/`examples`/`default`
  and `serverInfo.instructions`. For a scanner, coverage filter = "model-visible", not
  "field named in the spec example".
- **Every detection rule needs the reviewer's breaking-string treatment.** The benign twins
  passed while realistic strings (`conversation_id`, enum `environment`, ZWJ emoji, `μs`,
  "Pass your API key as the api_key parameter") false-positived. When adding a rule, write
  the most ordinary sentence that could trip it and test it (Pattern 2, but adversarial).
- **Two ingestion channels = two serialization layers; hashes can diverge where findings
  don't.** Connector hashes pydantic `model_dump`; paste mode hashes the pasted dict verbatim
  (`_meta`, URL normalization, nulls). Findings agree; cross-channel hash comparison is only
  valid for round-trip-clean definitions. Documented in `ingest.py` — deliberate.
- **Assert visibility, not attributes; look at the pixels.** An author `display:flex` on
  `.error-banner` silently defeated the `[hidden]` attribute; the E2E's `:not([hidden])`
  selector passed anyway. Use `isVisible()`-style checks and review an actual screenshot —
  the bug was only caught by looking at one.
- **One live server validates one dialect, not the wire format.** connect.js's SSE parser
  passed against FastMCP (LF framing) but would break on sse-starlette's CRLF. Where a spec
  says "CRLF or LF", test both framings — grep the spec for optional/either constructs.
- **A capability probe must validate its own setup step, not just the end-to-end effect.**
  `_probe_atime` checked "atime advanced after read" but never checked the pin-to-zero took;
  on utime-ignoring mounts setup failure masqueraded as capability success (§1 review).
- **"File missing" has two errnos.** ENOENT (`FileNotFoundError`) and ENOTDIR
  (`NotADirectoryError`) both mean the path is gone; catching only the former let
  parent-dir tampering masquerade as an INFO inspection error (§2 review).
- **Offsets have units; use the existing conversion helper.** Evidence.offset is a BYTE
  offset (UTF-8) by contract, but a new `str.find` call site shipped char offsets (§3
  review). When constructing Evidence outside `make_evidence`, grep for `.find(` feeding
  `offset=` and test with a non-ASCII prefix.
- **Every new ad-hoc print site for Finding fields bypasses R15.** C0-escaping lives in the
  core renderers; a new `print` of item_ref/message must route through `c0_escape`. "This
  value is a frisk constant" must be checked per BRANCH constructing the Finding, not per
  detector — the canary branch's item_ref is a server-controlled tool name (§4 review).
- **`evidence.snippet` is the only sink that echoes raw definition text — enforce S3 there.**
  Tool descriptions are attacker-controlled and can carry secrets; any new detector that
  copies matched text into `snippet` reopens the leak vector. Regression-guard snippet output
  against the per-run canary, not just literal template strings (§5 review). Today only D2
  emits snippets.
- **Invisible chars in source must be `\uXXXX` escapes** — corpus, detector regexes, and
  tests alike; literal ZWJ/bidi in source breaks reviewability AND exact-match editing.
