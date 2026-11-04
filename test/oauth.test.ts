import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, test } from "node:test";

import { createApp } from "../src/app.ts";
import { hashPassphrase } from "../src/oauth.ts";
import type { BridgeState } from "../src/state.ts";
import { parsePairingToken } from "../src/t3client.ts";

const PASSPHRASE = "correct horse battery staple";
const CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const JSON_HEADERS = { "content-type": "application/json", accept: "application/json, text/event-stream" };

let t3: Server;
let bridge: Server;
let base: string;
let state: BridgeState;
let seenT3Auth: string | undefined;

const listen = (server: Server) =>
  new Promise<number>((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));

before(async () => {
  t3 = createServer((req, res) => {
    seenT3Auth = req.headers.authorization;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ projects: [{ id: "p1", title: "Demo", workspaceRoot: "/demo", defaultModelSelection: null }], threads: [] }));
  });
  const t3Port = await listen(t3);
  state = {
    publicUrl: "",
    port: 0,
    t3Url: `http://127.0.0.1:${t3Port}`,
    t3Token: "t3-secret",
    t3TokenExpiresAt: Date.now() + 1000,
    maxRuntimeMode: "approval-required",
    passphrase: await hashPassphrase(PASSPHRASE),
    clients: {},
    accessTokens: {},
    refreshTokens: {},
    signInFailures: [],
    signInLockedUntil: 0,
  };
  // The issuer has to be known before listening, and the SDK allows http only on loopback.
  const probe = createServer();
  const port = await listen(probe);
  await new Promise((resolve) => probe.close(resolve));
  base = `http://127.0.0.1:${port}`;
  state.publicUrl = base;
  bridge = createServer(createApp(state, () => {}));
  await new Promise<void>((resolve) => bridge.listen(port, "127.0.0.1", resolve));
});

after(() => {
  bridge.close();
  t3.close();
});

beforeEach(() => {
  state.signInFailures = [];
  state.signInLockedUntil = 0;
});

async function register(redirect = CALLBACK) {
  return fetch(`${base}/register`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ client_name: "<b>Claude</b>", redirect_uris: [redirect], token_endpoint_auth_method: "none" }),
  });
}

async function beginAuthorize(clientId: string, resource = `${base}/mcp`) {
  const verifier = randomBytes(32).toString("base64url");
  const url = new URL(`${base}/authorize`);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: CALLBACK,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state: "xyz",
    resource,
  }).toString();
  const response = await fetch(url, { redirect: "manual" });
  const html = await response.text();
  return { verifier, html, status: response.status, pending: /name="pending" value="([^"]+)"/.exec(html)?.[1] ?? "", headers: response.headers };
}

const approve = (pending: string, passphrase: string) =>
  fetch(`${base}/authorize/approve`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ pending, passphrase }),
  });

async function signIn() {
  const client = (await (await register()).json()) as { client_id: string };
  const { pending, verifier } = await beginAuthorize(client.client_id);
  const redirect = await approve(pending, PASSPHRASE);
  assert.equal(redirect.status, 302);
  const location = new URL(redirect.headers.get("location")!);
  assert.equal(location.origin + location.pathname, CALLBACK);
  assert.equal(location.searchParams.get("state"), "xyz");
  const code = location.searchParams.get("code")!;
  const exchange = (v = verifier) =>
    fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: v, client_id: client.client_id, redirect_uri: CALLBACK, resource: `${base}/mcp` }),
    });
  return { client, exchange };
}

const mcp = (token: string | undefined, method: string, params: object = {}) =>
  fetch(`${base}/mcp`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(token ? { authorization: `Bearer ${token}` } : {}), "mcp-protocol-version": "2025-06-18" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });

test("advertises the metadata claude.ai needs for discovery", async () => {
  const unauth = await mcp(undefined, "tools/list");
  assert.equal(unauth.status, 401);
  assert.match(unauth.headers.get("www-authenticate") ?? "", /resource_metadata=.*oauth-protected-resource\/mcp/);
  const resource = (await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json()) as { resource: string; authorization_servers: string[] };
  assert.equal(resource.resource, `${base}/mcp`);
  const server = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as { registration_endpoint: string; code_challenge_methods_supported: string[] };
  assert.equal(server.registration_endpoint, `${base}/register`);
  assert.deepEqual(server.code_challenge_methods_supported, ["S256"]);
});

test("refuses to register a callback other than Claude's", async () => {
  const response = await register("https://evil.example/callback");
  assert.equal(response.status, 400);
  assert.equal(((await response.json()) as { error: string }).error, "invalid_client_metadata");
});

test("escapes the client name and locks down the sign-in page", async () => {
  const client = (await (await register()).json()) as { client_id: string };
  const { html, headers } = await beginAuthorize(client.client_id);
  assert.ok(html.includes("&lt;b&gt;Claude&lt;/b&gt;"));
  assert.ok(!html.includes("<b>Claude</b>"));
  assert.match(headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
});

test("the full sign-in reaches T3 Code without exposing its token", async () => {
  const { exchange } = await signIn();
  const tokens = (await (await exchange()).json()) as { access_token: string; refresh_token: string };
  const init = await mcp(tokens.access_token, "tools/list");
  assert.equal(init.status, 200);
  const names = ((await init.json()) as { result: { tools: { name: string }[] } }).result.tools.map((t) => t.name);
  assert.deepEqual(names.sort(), ["list_models", "list_projects", "list_threads", "read_thread", "send_message", "start_thread", "stop_thread"]);

  const call = await mcp(tokens.access_token, "tools/call", { name: "list_projects", arguments: {} });
  const body = await call.text();
  assert.match(body, /Demo/);
  assert.equal(seenT3Auth, "Bearer t3-secret");
  assert.ok(!body.includes("t3-secret"));
  assert.ok(!JSON.stringify(state.accessTokens).includes(tokens.access_token), "tokens are stored hashed");
});

test("rejects a wrong PKCE verifier and a reused code", async () => {
  const first = await signIn();
  assert.equal((await first.exchange("x".repeat(43))).status, 400);
  const second = await signIn();
  assert.equal((await second.exchange()).status, 200);
  assert.equal((await second.exchange()).status, 400);
});

test("rotates refresh tokens", async () => {
  const { client, exchange } = await signIn();
  const tokens = (await (await exchange()).json()) as { refresh_token: string };
  const refresh = () =>
    fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id }),
    });
  assert.equal((await refresh()).status, 200);
  assert.equal((await refresh()).status, 400);
});

test("refuses tokens for another resource", async () => {
  const client = (await (await register()).json()) as { client_id: string };
  const { status, pending } = await beginAuthorize(client.client_id, "https://other.example/mcp");
  assert.equal(pending, "");
  assert.ok(status >= 300);
});

test("locks sign-in after five wrong passphrases, even for the right one", async () => {
  const client = (await (await register()).json()) as { client_id: string };
  const { pending } = await beginAuthorize(client.client_id);
  for (let attempt = 0; attempt < 5; attempt += 1) assert.equal((await approve(pending, "wrong")).status, 401);
  const locked = await approve(pending, PASSPHRASE);
  assert.equal(locked.status, 401);
  assert.match(await locked.text(), /locked/);
});

test("rejects a forged pending id and an unknown bearer", async () => {
  assert.equal((await approve("forged", PASSPHRASE)).status, 400);
  assert.equal((await mcp("nope", "tools/list")).status, 401);
});

test("parses pairing links and bare tokens", () => {
  assert.equal(parsePairingToken(" abc123\n"), "abc123");
  assert.equal(parsePairingToken("https://host/pair#token=abc%2F123"), "abc/123");
});
