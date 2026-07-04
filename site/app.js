// frisk playground — UI + Pyodide orchestration (R20, R21).
//
// Rendering rule (R15's browser analog): every dynamic value — names, fields, messages,
// snippets — comes from an untrusted server definition and is inserted with textContent
// via el()/text helpers. innerHTML is never used anywhere in this file.
"use strict";

// Pinned Pyodide release (cross-cutting Pattern 5): the one CDN request this page makes.
const PYODIDE_VERSION = "0.26.4";
const PYODIDE_BASE = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;

const DETECTOR_LABELS = {
  D1: "instruction-injection",
  D2: "hidden-content",
  D3: "sensitive-params",
  D4: "scope-mismatch",
  D5: "shadowing",
  D6: "rug-pull",
  D7: "metadata-hygiene",
};

const SEVERITY_VARS = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  INFO: "var(--sev-info)",
};

const $ = (id) => document.getElementById(id);

// DOM builder: children land as text nodes unless they are already Nodes — the single
// choke point that keeps untrusted strings inert.
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "style") node.setAttribute("style", value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// ── boot ────────────────────────────────────────────────────────────────────

let scanJsonPy = null;

function setBoot(state, message) {
  const status = $("boot-status");
  status.classList.remove("ready", "failed");
  if (state) status.classList.add(state);
  $("boot-status-text").textContent = message;
}

async function boot() {
  try {
    setBoot(null, `loading Python runtime (Pyodide v${PYODIDE_VERSION})…`);
    await new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = PYODIDE_BASE + "pyodide.js";
      script.onload = resolve;
      script.onerror = () => reject(new Error("could not load the Pyodide runtime from the CDN"));
      document.head.append(script);
    });
    const pyodide = await loadPyodide({ indexURL: PYODIDE_BASE });

    setBoot(null, "loading frisk detector core…");
    const zipResponse = await fetch("dist/frisk_core.zip");
    if (!zipResponse.ok) {
      throw new Error(
        `detector core bundle missing (HTTP ${zipResponse.status}) — ` +
        "run scripts/build_site.py if serving locally"
      );
    }
    pyodide.unpackArchive(await zipResponse.arrayBuffer(), "zip");

    const glueResponse = await fetch("scan.py");
    if (!glueResponse.ok) throw new Error(`could not load scan.py (HTTP ${glueResponse.status})`);
    pyodide.runPython(await glueResponse.text());
    scanJsonPy = pyodide.globals.get("scan_json");

    setBoot("ready", "detector core ready — same code the CLI runs");
    $("scan-btn").disabled = false;
  } catch (err) {
    setBoot("failed", "boot failed");
    showError(`${err.message}. The playground needs the Pyodide CDN once; ` +
      "your definitions still never leave the browser.");
  }
}

// ── scanning ────────────────────────────────────────────────────────────────

function showError(message) {
  $("error-text").textContent = message;
  $("error-banner").hidden = false;
}

function clearError() {
  $("error-banner").hidden = true;
  $("error-text").textContent = "";
}

function runScan() {
  clearError();
  const text = $("paste-input").value;
  if (!text.trim()) {
    showError("nothing to scan — paste tools/list JSON or load an example first");
    return;
  }
  const button = $("scan-btn");
  button.classList.add("scanning");
  // Let the beam paint one frame before the synchronous Python call blocks the thread.
  requestAnimationFrame(() =>
    setTimeout(() => {
      try {
        const envelope = JSON.parse(scanJsonPy(text));
        if (!envelope.ok) {
          showError(envelope.error);
        } else {
          renderReport(envelope);
        }
      } catch (err) {
        showError(`scan failed unexpectedly: ${err.message}`);
      } finally {
        button.classList.remove("scanning");
      }
    }, 20)
  );
}

// ── report rendering (textContent only) ─────────────────────────────────────

function renderReport(envelope) {
  const report = envelope.report;
  const body = $("report-body");
  body.replaceChildren();

  $("report-meta").textContent =
    `${report.items_scanned} item${report.items_scanned === 1 ? "" : "s"} · ` +
    `exit ${envelope.exit_code} · frisk ${report.frisk_version}`;

  const head = el("div", { class: "verdict-head" },
    el("span", { class: `stamp ${report.verdict}` }, report.verdict),
    el("div", { class: "gauge-block" },
      el("span", { class: "gauge-label" },
        "risk score ", el("strong", {}, `${report.risk_score} / 100`),
        report.highest_severity ? ` — highest: ${report.highest_severity}` : ""
      ),
      el("div", { class: "gauge" },
        el("div", { class: "gauge-fill", id: "gauge-fill" })
      )
    )
  );
  body.append(head);

  if (!envelope.server_info_known) {
    body.append(el("p", { class: "paste-note" },
      "paste carried no serverInfo — identity checks that need it were skipped, ",
      "not passed silently"));
  }

  if (report.findings.length === 0) {
    body.append(el("p", { class: "clean-note" }, "✓ no findings — ",
      "definitions look clean to D1–D7. A clean scan is a lower bound, not a guarantee."));
  } else {
    const list = el("ol", { class: "findings" });
    report.findings.forEach((finding, index) => {
      const sevVar = SEVERITY_VARS[finding.severity] || "var(--dim)";
      let where = `${finding.item} · ${finding.field}`;
      if (finding.evidence.offset !== null && finding.evidence.offset !== undefined) {
        where += ` @ byte ${finding.evidence.offset}`;
      }
      const evidence = el("p", { class: "finding-evidence" }, `(${finding.evidence.category}) `);
      if (finding.evidence.snippet) {
        evidence.append(el("span", { class: "snippet" }, finding.evidence.snippet));
      }
      list.append(
        el("li", { class: "finding", style: `--sev:${sevVar}; --i:${index}` },
          el("div", { class: "finding-head" },
            el("span", { class: "sev-chip", style: `--sev:${sevVar}` }, finding.severity),
            el("span", { class: "detector-tag" }, finding.detector),
            el("span", { class: "detector-label" },
              DETECTOR_LABELS[finding.detector] || ""),
            el("span", { class: "finding-where" }, where)
          ),
          el("p", { class: "finding-message" }, finding.message),
          evidence
        )
      );
    });
    body.append(list);
  }

  body.append(
    el("details", { class: "raw-report" },
      el("summary", {}, "RAW REPORT — exactly what `frisk scan` prints"),
      el("pre", {}, envelope.human)
    )
  );

  requestAnimationFrame(() => {
    const fill = $("gauge-fill");
    if (fill) fill.style.width = `${Math.min(100, report.risk_score)}%`;
  });
}

// ── wiring ──────────────────────────────────────────────────────────────────

function loadExample(which) {
  clearError();
  $("paste-input").value = JSON.stringify(FRISK_EXAMPLES[which], null, 2);
}

$("scan-btn").addEventListener("click", runScan);
$("load-poisoned").addEventListener("click", () => loadExample("poisoned"));
$("load-benign").addEventListener("click", () => loadExample("benign"));
$("clear-input").addEventListener("click", () => { clearError(); $("paste-input").value = ""; });
$("paste-input").addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter" && !$("scan-btn").disabled) {
    runScan();
  }
});

boot();
