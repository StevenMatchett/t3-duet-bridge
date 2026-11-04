#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";

import { createApp } from "./app.ts";
import { hashPassphrase } from "./oauth.ts";
import { defaultStatePath, loadState, RUNTIME_MODES, saveState, type BridgeState, type RuntimeMode } from "./state.ts";
import { exchangePairingToken, parsePairingToken, T3Client } from "./t3client.ts";

const USAGE = `t3-duet-bridge: connect Claude Duet to T3 Code through a claude.ai custom connector.

  setup   --public-url https://host [--port 3774] [--t3-url URL]
          [--max-runtime-mode approval-required|auto-accept-edits|auto|full-access]
          [--default-model instance:model] [--rotate-passphrase] [--skip-pairing]
          Reads the pairing token from T3_PAIRING_TOKEN, or prompts for it.
  serve   Run the MCP server on 127.0.0.1.
  doctor  Check the T3 Code session and the public URL.
  revoke  Sign out every connector client.
`;

function discoverT3Url(): string {
  try {
    const home = process.env.T3CODE_HOME ?? join(homedir(), ".t3");
    const runtime = JSON.parse(readFileSync(join(home, "userdata", "server-runtime.json"), "utf8")) as { port: number };
    return `http://127.0.0.1:${runtime.port}`;
  } catch {
    return "http://127.0.0.1:3773";
  }
}

async function prompt(question: string): Promise<string> {
  const reader = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await reader.question(question);
  } finally {
    reader.close();
  }
}

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

async function setup(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      "public-url": { type: "string" },
      port: { type: "string" },
      "t3-url": { type: "string" },
      "max-runtime-mode": { type: "string" },
      "default-model": { type: "string" },
      "rotate-passphrase": { type: "boolean", default: false },
      "skip-pairing": { type: "boolean", default: false },
    },
  });
  const path = defaultStatePath();
  const existing = loadState(path);

  const publicUrl = (values["public-url"] ?? existing?.publicUrl)?.replace(/\/+$/, "");
  if (!publicUrl) fail("Pass --public-url with the HTTPS address your tunnel gives you.");
  const parsed = new URL(publicUrl);
  if (parsed.protocol !== "https:" || parsed.pathname !== "/") {
    fail("--public-url must be an https:// origin with no path. claude.ai and OAuth both require HTTPS.");
  }

  const maxRuntimeMode = (values["max-runtime-mode"] ?? existing?.maxRuntimeMode ?? "approval-required") as RuntimeMode;
  if (!RUNTIME_MODES.includes(maxRuntimeMode)) fail(`--max-runtime-mode must be one of: ${RUNTIME_MODES.join(", ")}`);

  const t3Url = values["t3-url"] ?? existing?.t3Url ?? discoverT3Url();
  let t3Token = existing?.t3Token ?? "";
  let t3TokenExpiresAt = existing?.t3TokenExpiresAt ?? 0;
  if (!values["skip-pairing"] || !existing) {
    const raw = process.env.T3_PAIRING_TOKEN ?? (await prompt("T3 Code pairing link or token: "));
    const session = await exchangePairingToken(t3Url, parsePairingToken(raw));
    t3Token = session.token;
    t3TokenExpiresAt = session.expiresAt;
    console.log(`T3 Code session granted: ${session.scope}`);
  }

  let passphrase: string | undefined;
  if (!existing || values["rotate-passphrase"]) passphrase = randomBytes(18).toString("base64url");

  let defaultModel = existing?.defaultModel;
  if (values["default-model"]) {
    const [instanceId, model] = values["default-model"].split(":");
    if (!instanceId || !model) fail("--default-model must look like claudeAgent:claude-opus-5-5");
    defaultModel = { instanceId, model };
  }

  const state: BridgeState = {
    publicUrl,
    port: values.port ? Number(values.port) : (existing?.port ?? 3774),
    t3Url,
    t3Token,
    t3TokenExpiresAt,
    maxRuntimeMode,
    ...(defaultModel ? { defaultModel } : {}),
    passphrase: passphrase ? await hashPassphrase(passphrase) : existing!.passphrase,
    clients: existing?.clients ?? {},
    accessTokens: existing?.accessTokens ?? {},
    refreshTokens: existing?.refreshTokens ?? {},
    signInFailures: [],
    signInLockedUntil: 0,
  };
  saveState(path, state);

  console.log(`Saved ${path}`);
  console.log(`Connector URL: ${publicUrl}/mcp`);
  console.log(`Agent runtime limit: ${maxRuntimeMode}`);
  if (passphrase) console.log(`\nSign-in passphrase, shown once. Store it in a password manager:\n\n  ${passphrase}\n`);
}

function requireState(): { state: BridgeState; save: () => void } {
  const path = defaultStatePath();
  if (!existsSync(path)) fail(`No state at ${path}. Run \`t3-duet-bridge setup\` first.`);
  const state = loadState(path)!;
  return { state, save: () => saveState(path, state) };
}

function serve(): void {
  const { state, save } = requireState();
  const server = createApp(state, save).listen(state.port, "127.0.0.1", () => {
    console.log(`t3-duet-bridge on http://127.0.0.1:${state.port}, public at ${state.publicUrl}/mcp`);
  });
  for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => server.close(() => process.exit(0)));
}

async function doctor(): Promise<void> {
  const { state } = requireState();
  let ok = true;
  const check = async (label: string, run: () => Promise<string>) => {
    try {
      console.log(`ok    ${label}: ${await run()}`);
    } catch (error) {
      ok = false;
      console.log(`FAIL  ${label}: ${(error as Error).message}`);
    }
  };
  await check("T3 Code session", async () => {
    const t3 = new T3Client(state.t3Url, () => state.t3Token);
    const shell = await t3.get<{ projects: unknown[] }>("/api/orchestration/shell");
    await t3.rpc("server.getConfig", {});
    const days = Math.floor((state.t3TokenExpiresAt - Date.now()) / 86_400_000);
    return `${shell.projects.length} projects, session expires in ${days} days`;
  });
  await check("local bridge", async () => {
    const response = await fetch(`http://127.0.0.1:${state.port}/healthz`, { signal: AbortSignal.timeout(3000) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return "running";
  });
  await check("public URL", async () => {
    const url = new URL("/.well-known/oauth-authorization-server", state.publicUrl);
    const response = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!response.ok) throw new Error(`HTTP ${response.status} from ${url.href}`);
    const metadata = (await response.json()) as { issuer: string };
    if (metadata.issuer.replace(/\/$/, "") !== state.publicUrl) throw new Error(`issuer mismatch: ${metadata.issuer}`);
    return "OAuth metadata reachable";
  });
  process.exit(ok ? 0 : 1);
}

function revoke(): void {
  const { state, save } = requireState();
  state.clients = {};
  state.accessTokens = {};
  state.refreshTokens = {};
  save();
  console.log("Signed out every connector client. Start the bridge, then reconnect in claude.ai.");
}

const [command, ...rest] = process.argv.slice(2);
if (command === "setup") await setup(rest);
else if (command === "serve") serve();
else if (command === "doctor") await doctor();
else if (command === "revoke") revoke();
else {
  console.log(USAGE);
  process.exit(command ? 1 : 0);
}
