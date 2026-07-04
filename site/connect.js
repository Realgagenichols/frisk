// frisk playground — best-effort CORS direct-connect (R22).
//
// A minimal MCP streamable-HTTP client: JSON-RPC initialize → notifications/initialized →
// tools/resources/prompts list (with cursor pagination), then the fetched inventory goes
// through the EXACT same path as a paste: into the textarea, then runScan() (R23 — this
// file is transport only; zero detector logic, zero scan logic).
//
// Token hygiene (S3): read from the password input at click time, held in local variables
// only, sent solely as an Authorization header to the user-typed URL. Never persisted
// (no localStorage/cookies/URL params), never logged, never sent anywhere else.
"use strict";

const MCP_PROTOCOL_VERSION = "2025-06-18";
const CONNECT_TIMEOUT_MS = 20000;

const PASTE_FALLBACK =
  " Fall back to paste mode: run tools/list with any MCP client or inspector and paste the " +
  "JSON on the left.";

let rpcId = 0;

function mcpHeaders(token, session, afterInit) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (session) headers["mcp-session-id"] = session;
  if (afterInit) headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION;
  return headers;
}

// Parse a text/event-stream body: return the first `data:` JSON whose id matches.
function sseExtract(body, id) {
  // SSE permits CRLF or LF framing (sse-starlette emits CRLF) — accept both.
  for (const event of body.split(/\r?\n\r?\n/)) {
    const data = event
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .join("\n");
    if (!data) continue;
    try {
      const message = JSON.parse(data);
      if (message.id === id) return message;
    } catch {
      // keep scanning: other stream events (notifications, pings) are not ours
    }
  }
  throw new Error("server streamed a response but it contained no reply to our request");
}

async function mcpCall(url, token, session, method, params, afterInit) {
  const id = ++rpcId;
  const response = await fetch(url, {
    method: "POST",
    headers: mcpHeaders(token, session, afterInit),
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    signal: AbortSignal.timeout(CONNECT_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`server answered HTTP ${response.status} to ${method}`);
  }
  const contentType = (response.headers.get("content-type") || "").split(";")[0].trim();
  let message;
  if (contentType === "text/event-stream") {
    message = sseExtract(await response.text(), id);
  } else {
    message = await response.json();
  }
  if (message.error) {
    const code = message.error.code;
    throw new Error(`server rejected ${method} (JSON-RPC error ${code})`);
  }
  return { result: message.result, session: response.headers.get("mcp-session-id") || session };
}

async function mcpNotify(url, token, session, method) {
  // Fire the required initialized notification; tolerate servers that answer oddly.
  try {
    await fetch(url, {
      method: "POST",
      headers: mcpHeaders(token, session, true),
      body: JSON.stringify({ jsonrpc: "2.0", method }),
      signal: AbortSignal.timeout(CONNECT_TIMEOUT_MS),
    });
  } catch {
    /* best-effort */
  }
}

async function listAll(url, token, session, method, key) {
  const collected = [];
  let cursor;
  do {
    const { result } = await mcpCall(
      url, token, session, method, cursor ? { cursor } : {}, true
    );
    collected.push(...(result?.[key] ?? []));
    cursor = result?.nextCursor;
  } while (cursor && collected.length < 10000);
  return collected;
}

async function directConnect(url, token) {
  const init = await mcpCall(url, token, null, "initialize", {
    protocolVersion: MCP_PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "frisk-playground", version: "0.1.0" },
  }, false);
  const session = init.session;
  const capabilities = init.result?.capabilities ?? {};
  await mcpNotify(url, token, session, "notifications/initialized");

  const fetched = {};
  if (capabilities.tools) {
    fetched.tools = await listAll(url, token, session, "tools/list", "tools");
  }
  if (capabilities.resources) {
    fetched.resources = await listAll(url, token, session, "resources/list", "resources");
  }
  if (capabilities.prompts) {
    fetched.prompts = await listAll(url, token, session, "prompts/list", "prompts");
  }
  if (!("tools" in fetched) && !("resources" in fetched) && !("prompts" in fetched)) {
    throw new Error("server advertises no tools, resources, or prompts capabilities");
  }
  if (init.result?.serverInfo) fetched.serverInfo = init.result.serverInfo;
  if (init.result?.instructions) fetched.instructions = init.result.instructions;
  return fetched;
}

// ── wiring ──────────────────────────────────────────────────────────────────

function setConnectStatus(message) {
  document.getElementById("connect-status").textContent = message;
}

async function runDirectConnect() {
  clearError();
  const url = document.getElementById("connect-url").value.trim();
  const token = document.getElementById("connect-token").value;
  if (!url) {
    showError("direct connect needs a server URL");
    return;
  }
  if (!/^https?:\/\//i.test(url)) {
    showError("direct connect needs an http(s):// URL (stdio servers need the CLI's sandbox)");
    return;
  }
  const button = document.getElementById("connect-btn");
  button.disabled = true;
  setConnectStatus("connecting…");
  try {
    const fetched = await directConnect(url, token);
    // Same path as a paste (R23): show exactly what was fetched, then scan it. The scan
    // settles asynchronously — its own report/error is the terminal status, not us.
    document.getElementById("paste-input").value = JSON.stringify(fetched, null, 2);
    runScan();
    setConnectStatus("fetched — scanning; fetched JSON is in the paste box");
  } catch (err) {
    setConnectStatus("");
    if (err instanceof TypeError) {
      // fetch() network/CORS failures surface as TypeError with no detail by design.
      showError(
        "could not reach the server from the browser — almost always missing CORS " +
        "headers (the server must send Access-Control-Allow-Origin), or the host is down." +
        PASTE_FALLBACK
      );
    } else if (err.name === "TimeoutError" || err.name === "AbortError") {
      showError(`server did not answer within ${CONNECT_TIMEOUT_MS / 1000}s.` + PASTE_FALLBACK);
    } else {
      showError(`direct connect failed: ${err.message}.` + PASTE_FALLBACK);
    }
  } finally {
    button.disabled = document.getElementById("scan-btn").disabled;
  }
}

document.getElementById("connect-btn").addEventListener("click", runDirectConnect);

// The connect button follows the boot lifecycle: enabled once the scanner is ready.
new MutationObserver(() => {
  document.getElementById("connect-btn").disabled =
    document.getElementById("scan-btn").disabled;
}).observe(document.getElementById("scan-btn"), { attributes: true, attributeFilter: ["disabled"] });
