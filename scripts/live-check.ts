/**
 * End-to-end check against a real T3 Code server: OAuth sign-in, then every tool over MCP.
 * It starts a real agent turn and creates a project, so point it at a throwaway server:
 *
 *   T3_URL=http://127.0.0.1:3999 T3_PAIRING_TOKEN=... LIVE_WORKSPACE=/tmp/x node scripts/live-check.ts
 */
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";

import { createApp } from "../src/app.ts";
import { hashPassphrase } from "../src/oauth.ts";
import type { BridgeState } from "../src/state.ts";
import { exchangePairingToken } from "../src/t3client.ts";

const t3Url = process.env.T3_URL!;
const workspace = process.env.LIVE_WORKSPACE!;
const session = await exchangePairingToken(t3Url, process.env.T3_PAIRING_TOKEN!);
console.log("granted scopes:", session.scope);

const projectId = randomUUID();
const created = await fetch(`${t3Url}/api/projects/mutate`, {
  method: "POST",
  headers: { authorization: `Bearer ${session.token}`, "content-type": "application/json" },
  body: JSON.stringify({ type: "project.create", commandId: randomUUID(), projectId, title: "Live check", workspaceRoot: workspace, createWorkspaceRootIfMissing: true }),
});
assert.equal(created.status, 200, await created.clone().text());

const probe = createServer();
await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
const port = (probe.address() as AddressInfo).port;
await new Promise((r) => probe.close(r));
const base = `http://127.0.0.1:${port}`;
const state: BridgeState = {
  publicUrl: base, port, t3Url, t3Token: session.token, t3TokenExpiresAt: session.expiresAt,
  maxRuntimeMode: "approval-required", passphrase: await hashPassphrase("live"),
  clients: {}, accessTokens: {}, refreshTokens: {}, signInFailures: [], signInLockedUntil: 0,
};
const bridge = createServer(createApp(state, () => {}));
await new Promise<void>((r) => bridge.listen(port, "127.0.0.1", r));

const callback = "https://claude.ai/api/mcp/auth_callback";
const client = (await (await fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "live", redirect_uris: [callback], token_endpoint_auth_method: "none" }) })).json()) as { client_id: string };
const verifier = randomBytes(32).toString("base64url");
const page = await (await fetch(`${base}/authorize?${new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: callback, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", resource: `${base}/mcp` })}`)).text();
const pending = /name="pending" value="([^"]+)"/.exec(page)![1]!;
const approved = await fetch(`${base}/authorize/approve`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ pending, passphrase: "live" }) });
const code = new URL(approved.headers.get("location")!).searchParams.get("code")!;
const tokens = (await (await fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: client.client_id, redirect_uri: callback, resource: `${base}/mcp` }) })).json()) as { access_token: string };

async function tool(name: string, args: object = {}) {
  const response = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tokens.access_token}`, "mcp-protocol-version": "2025-06-18" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  const { result, error } = (await response.json()) as { result?: { isError?: boolean; content: { text: string }[] }; error?: unknown };
  if (error) throw new Error(`${name}: ${JSON.stringify(error)}`);
  const body = result!.content[0]!.text;
  if (result!.isError) return { isError: true as const, message: body };
  return JSON.parse(body);
}

const models = await tool("list_models");
console.log("list_models:", JSON.stringify(models));
const claude = models.find((p: { provider: string }) => p.provider === "claudeAgent");
const model = claude.models.find((m: string) => m.includes("haiku")) ?? claude.models.at(-1);

const projects = await tool("list_projects");
assert.ok(projects.some((p: { id: string }) => p.id === projectId));
console.log("list_projects: ok");

const refused = await tool("start_thread", { project_id: projectId, message: "x", runtime_mode: "full-access", wait_seconds: 0 });
assert.equal(refused.isError, true);
console.log("runtime cap:", refused.message);
assert.equal((await tool("list_threads", { project_id: projectId })).threads.length, 0, "refused call must not create a thread");

const started = await tool("start_thread", { project_id: projectId, provider: "claudeAgent", model, title: "Live check", message: "Reply with exactly the word PONG. Do not use any tools.", wait_seconds: 45 });
console.log("start_thread:", JSON.stringify(started));
assert.equal(started.run_status, "completed");
assert.match(started.reply, /PONG/);

const sent = await tool("send_message", { thread_id: started.thread_id, message: "Reply with exactly the word PING. Do not use any tools.", wait_seconds: 45 });
console.log("send_message:", JSON.stringify(sent));
assert.equal(sent.run_status, "completed");
assert.match(sent.reply, /PING/);
assert.ok(!sent.reply.includes("PONG"), "reply must come only from the new run");

const thread = await tool("read_thread", { thread_id: started.thread_id });
console.log("read_thread:", thread.status, thread.messages.map((m: { role: string; text: string }) => `${m.role}:${m.text}`));
assert.equal(thread.messages.length, 4);

console.log("list_threads:", JSON.stringify((await tool("list_threads")).threads.map((t: { id: string; status: string }) => t.status)));
console.log("stop_thread idle:", JSON.stringify(await tool("stop_thread", { thread_id: started.thread_id })));

const busy = await tool("send_message", { thread_id: started.thread_id, message: "Write a 2000 word essay about rivers. Do not use any tools.", wait_seconds: 3 });
console.log("send_message short wait:", JSON.stringify({ ...busy, reply: busy.reply?.slice(0, 40) }));
const stopped = await tool("stop_thread", { thread_id: started.thread_id });
console.log("stop_thread busy:", JSON.stringify(stopped));
assert.equal(stopped.stopped, true);

const marker = join(workspace, `approval-${randomUUID()}.txt`);
const gated = await tool("start_thread", { project_id: projectId, provider: "claudeAgent", model, title: "Approval check", message: `Use your file writing tool to create ${marker} containing the word hi.`, wait_seconds: 45 });
console.log("approval gate:", JSON.stringify({ status: gated.run_status, waiting: gated.waiting_for_owner }));
assert.ok(gated.waiting_for_owner, "agent should be waiting for the owner");
assert.equal(existsSync(marker), false, "nothing may be written before approval");
await tool("stop_thread", { thread_id: gated.thread_id });

const initialize = await fetch(`${base}/mcp`, {
  method: "POST",
  headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tokens.access_token}` },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "live", version: "1" } } }),
});
assert.equal(initialize.status, 200);
console.log("initialize:", JSON.stringify(((await initialize.json()) as { result: { protocolVersion: string; serverInfo: unknown } }).result.serverInfo));

console.log("LIVE CHECK PASSED");
bridge.close();
process.exit(0);
