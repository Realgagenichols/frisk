# frisk

**Vet a third-party MCP server before you trust it.**

`frisk` connects to an MCP server (sandboxed), pulls the real tool/resource/prompt
definitions the model would see, runs deterministic security detectors on them, and emits a
risk-scored report — plus a `frisk.lock` baseline so a later re-scan catches rug-pulls.

Status: **M1 (CLI core) in progress.** See `SPEC.md` for requirements.
