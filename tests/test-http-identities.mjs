#!/usr/bin/env node
/**
 * Per-caller HTTP identities (AFFINE_MCP_IDENTITIES).
 *
 * - config parsing and validation
 * - bearer middleware resolves identity tokens and the shared token
 * - a live HTTP server binds each MCP session to the identity that opened it
 */
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

import { createHttpAuthState } from "../src/httpAuth.ts";
import {
  loadHttpIdentities,
  matchHttpIdentity,
  parseHttpIdentities,
} from "../src/httpIdentities.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_DIR = path.resolve(__dirname, "..");
const SERVER_PATH = path.join(PROJECT_DIR, "dist", "index.js");

const TOKEN_A = "identity-token-alpha-0123456789";
const TOKEN_B = "identity-token-bravo-0123456789";
const SHARED = "shared-service-token-0123456789";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertThrows(fn, expectedMessage, message) {
  try {
    fn();
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    assert(detail.includes(expectedMessage), `${message}: unexpected error: ${detail}`);
    return;
  }
  throw new Error(`${message}: expected an error`);
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

function testParsing() {
  const fromArray = parseHttpIdentities(JSON.stringify([
    { name: "alice", token: TOKEN_A, email: "alice@example.com", password: "pw" },
    { name: "bob", token: TOKEN_B, apiToken: "affine-api-token", workspaceId: "ws-bob" },
  ]));
  assertEqual(fromArray.length, 2, "array form parses two identities");
  assertEqual(fromArray[1].workspaceId, "ws-bob", "workspaceId is preserved");

  const fromObject = parseHttpIdentities(JSON.stringify({
    carol: { token: TOKEN_A, cookie: "affine_session=abc" },
  }));
  assertEqual(fromObject[0].name, "carol", "object form uses keys as names");

  assertThrows(
    () => parseHttpIdentities("not json"),
    "not valid JSON",
    "invalid JSON is rejected",
  );
  assertThrows(
    () => parseHttpIdentities(JSON.stringify([{ name: "x", token: "short", apiToken: "t" }])),
    "at least 16 characters",
    "short tokens are rejected",
  );
  assertThrows(
    () => parseHttpIdentities(JSON.stringify([{ name: "x", token: TOKEN_A }])),
    "needs AFFiNE credentials",
    "identity without AFFiNE credentials is rejected",
  );
  assertThrows(
    () => parseHttpIdentities(JSON.stringify([{ name: "x", token: TOKEN_A, email: "a@b.c" }])),
    "together",
    "email without password is rejected",
  );
  assertThrows(
    () => parseHttpIdentities(JSON.stringify([
      { name: "x", token: TOKEN_A, apiToken: "t" },
      { name: "X", token: TOKEN_B, apiToken: "t" },
    ])),
    "duplicate identity name",
    "names are unique case-insensitively",
  );
  assertThrows(
    () => parseHttpIdentities(JSON.stringify([
      { name: "x", token: TOKEN_A, apiToken: "t" },
      { name: "y", token: TOKEN_A, apiToken: "t" },
    ])),
    "reuses another identity's token",
    "tokens are unique",
  );
  assertThrows(
    () => parseHttpIdentities(JSON.stringify([{ name: "bad name", token: TOKEN_A, apiToken: "t" }])),
    'needs a "name"',
    "names are restricted to safe characters",
  );

  assertEqual(loadHttpIdentities({}).length, 0, "no variables yields no identities");
  assertThrows(
    () => loadHttpIdentities({ AFFINE_MCP_IDENTITIES: "[]", AFFINE_MCP_IDENTITIES_FILE: "/x" }),
    "Set only one of",
    "inline and file sources are mutually exclusive",
  );
  const fromFile = loadHttpIdentities(
    { AFFINE_MCP_IDENTITIES_FILE: "/identities.json" },
    (p) => {
      assertEqual(p, "/identities.json", "file path is passed through");
      return JSON.stringify([{ name: "dave", token: TOKEN_A, apiToken: "t" }]);
    },
  );
  assertEqual(fromFile[0].name, "dave", "file source parses");

  const matched = matchHttpIdentity(TOKEN_B, fromArray);
  assertEqual(matched?.name, "bob", "matching token resolves its identity");
  assertEqual(matchHttpIdentity("nope", fromArray), undefined, "unknown token resolves nothing");
  console.log("✓ identity parsing");
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

function fakeResponse() {
  const res = { statusCode: 200, locals: {}, headers: {}, body: undefined };
  res.status = (code) => { res.statusCode = code; return res; };
  res.send = (body) => { res.body = body; return res; };
  res.json = (body) => { res.body = body; return res; };
  res.set = (name, value) => { res.headers[name] = value; return res; };
  return res;
}

function runMiddleware(state, authorization) {
  const req = { method: "POST", headers: authorization ? { authorization } : {}, query: {} };
  const res = fakeResponse();
  let nextCalled = false;
  state.authMiddleware(req, res, () => { nextCalled = true; });
  return { res, nextCalled };
}

function testMiddleware() {
  const config = { authMode: "bearer" };
  const identities = parseHttpIdentities(JSON.stringify([
    { name: "alice", token: TOKEN_A, apiToken: "t" },
  ]));

  const withShared = createHttpAuthState(config, {
    allowAnyOrigin: false,
    httpAuthToken: SHARED,
    identities,
  });
  let result = runMiddleware(withShared, `Bearer ${TOKEN_A}`);
  assert(result.nextCalled, "identity token passes");
  assertEqual(result.res.locals.identity, "alice", "identity name is attached to the request");

  result = runMiddleware(withShared, `Bearer ${SHARED}`);
  assert(result.nextCalled, "shared token still passes");
  assertEqual(result.res.locals.identity, undefined, "shared token has no identity");

  result = runMiddleware(withShared, "Bearer wrong-token-0123456789");
  assert(!result.nextCalled, "unknown token is rejected");
  assertEqual(result.res.statusCode, 401, "unknown token returns 401");

  const identitiesOnly = createHttpAuthState(config, { allowAnyOrigin: false, identities });
  result = runMiddleware(identitiesOnly, undefined);
  assertEqual(result.res.statusCode, 401, "identities alone still require a token");
  result = runMiddleware(identitiesOnly, `Bearer ${SHARED}`);
  assertEqual(result.res.statusCode, 401, "no shared token means the old secret is useless");
  result = runMiddleware(identitiesOnly, `Bearer ${TOKEN_A}`);
  assert(result.nextCalled, "identity token passes without a shared token");

  const open = createHttpAuthState(config, { allowAnyOrigin: false });
  result = runMiddleware(open, undefined);
  assert(result.nextCalled, "no tokens configured keeps the unauthenticated path");
  console.log("✓ identity middleware");
}

// ---------------------------------------------------------------------------
// Live server: sessions are bound to identities
// ---------------------------------------------------------------------------

async function findFreePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function spawnServer(port, overrides) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("AFFINE_") || key === "MCP_TRANSPORT" || key === "PORT") delete env[key];
  }
  const child = spawn("node", [SERVER_PATH], {
    cwd: PROJECT_DIR,
    env: {
      ...env,
      MCP_TRANSPORT: "http",
      PORT: String(port),
      AFFINE_BASE_URL: "http://127.0.0.1:3010",
      AFFINE_MCP_AUTH_MODE: "bearer",
      AFFINE_MCP_HTTP_HOST: "127.0.0.1",
      XDG_CONFIG_HOME: mkdtempSync(path.join(os.tmpdir(), "affine-mcp-identities-")),
      ...overrides,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  child.stdout.on("data", () => {});
  return { child, logs: () => stderr };
}

async function waitForHealth(child, url, logs) {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Server exited early: ${logs()}`);
    try {
      const response = await fetch(url);
      const body = await response.json();
      if (response.ok) return body;
    } catch {}
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${url}: ${logs()}`);
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  const exited = await Promise.race([
    new Promise((resolve) => child.once("exit", () => resolve(true))),
    delay(4_000).then(() => false),
  ]);
  if (!exited) child.kill("SIGKILL");
}

const INITIALIZE = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "identities-test", version: "1.0.0" },
  },
};

async function mcpPost(baseUrl, token, body, sessionId) {
  const response = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${token}`,
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, sessionId: response.headers.get("mcp-session-id"), text };
}

async function testLiveServer() {
  const identitiesFile = path.join(mkdtempSync(path.join(os.tmpdir(), "affine-mcp-idfile-")), "identities.json");
  writeFileSync(identitiesFile, JSON.stringify([
    { name: "alice", token: TOKEN_A, apiToken: "alice-affine-token" },
    { name: "bob", token: TOKEN_B, apiToken: "bob-affine-token" },
  ]));

  const port = await findFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  // No AFFINE_MCP_HTTP_TOKEN: identities alone must satisfy the auth requirement.
  const { child, logs } = spawnServer(port, { AFFINE_MCP_IDENTITIES_FILE: identitiesFile });
  try {
    const health = await waitForHealth(child, `${baseUrl}/healthz`, logs);
    assertEqual(health.protected, true, "healthz reports the listener as protected");
    assertEqual(health.identities, 2, "healthz reports the identity count");

    const init = await mcpPost(baseUrl, TOKEN_A, INITIALIZE);
    assertEqual(init.status, 200, `alice initializes (${init.text})`);
    assert(init.sessionId, "initialize returns a session id");
    assert(logs().includes("(identity: alice)"), "session log names the identity");

    const ping = { jsonrpc: "2.0", id: 2, method: "ping" };
    const own = await mcpPost(baseUrl, TOKEN_A, ping, init.sessionId);
    assertEqual(own.status, 200, `alice reuses her session (${own.text})`);

    const hijack = await mcpPost(baseUrl, TOKEN_B, ping, init.sessionId);
    assertEqual(hijack.status, 403, `bob cannot reuse alice's session (${hijack.text})`);

    const stranger = await mcpPost(baseUrl, "unknown-token-0123456789", ping, init.sessionId);
    assertEqual(stranger.status, 401, "unknown token is rejected");

    const bobInit = await mcpPost(baseUrl, TOKEN_B, INITIALIZE);
    assertEqual(bobInit.status, 200, `bob initializes his own session (${bobInit.text})`);
    assert(bobInit.sessionId !== init.sessionId, "sessions are distinct");

    const tools = await mcpPost(baseUrl, TOKEN_B, { jsonrpc: "2.0", id: 3, method: "tools/list" }, bobInit.sessionId);
    assertEqual(tools.status, 200, "identity session lists tools");
    assert(!tools.text.includes('"name":"sign_in"'), "identity sessions do not expose sign_in");
    console.log("✓ identity-bound HTTP sessions");
  } finally {
    await stopServer(child);
    rmSync(path.dirname(identitiesFile), { recursive: true, force: true });
  }
}

async function testStartupRejections() {
  const cases = [
    [
      {
        AFFINE_MCP_IDENTITIES: JSON.stringify([{ name: "x", token: TOKEN_A, apiToken: "t" }]),
        AFFINE_MCP_AUTH_MODE: "oauth",
        AFFINE_API_TOKEN: "service-token",
      },
      "requires AFFINE_MCP_AUTH_MODE=bearer",
    ],
    [{ AFFINE_MCP_IDENTITIES: JSON.stringify([{ name: "x", token: "short", apiToken: "t" }]) }, "at least 16 characters"],
  ];
  for (const [overrides, expected] of cases) {
    const port = await findFreePort();
    const { child, logs } = spawnServer(port, overrides);
    const code = await Promise.race([
      new Promise((resolve) => child.once("exit", resolve)),
      delay(8_000).then(() => { child.kill("SIGKILL"); return "timeout"; }),
    ]);
    assert(code !== 0 && code !== "timeout", `server must refuse to start: ${JSON.stringify(overrides)}`);
    assert(logs().includes(expected), `startup error mentions "${expected}": ${logs()}`);
  }
  console.log("✓ startup rejects invalid identity configuration");
}

async function main() {
  testParsing();
  testMiddleware();
  if (!existsSync(SERVER_PATH)) {
    throw new Error("dist/index.js not found. Run `npm run build` first.");
  }
  await testLiveServer();
  await testStartupRejections();
  console.log("\nAll HTTP identity tests passed.");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : error);
  process.exit(1);
});
