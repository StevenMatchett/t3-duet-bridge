import { createHash, randomBytes, randomUUID, scrypt, timingSafeEqual } from "node:crypto";

import type { Response } from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { InvalidClientMetadataError, InvalidGrantError, InvalidTargetError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";

import type { BridgeState, StoredToken } from "./state.ts";

export const OAUTH_SCOPE = "t3";

/**
 * Sign-in codes only ever go to Claude. Registration is public, so without this
 * anyone could register their own callback and phish a code out of the owner.
 */
export const ALLOWED_REDIRECT_URIS: ReadonlySet<string> = new Set([
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
]);

const ACCESS_TTL_MS = 60 * 60 * 1000;
const REFRESH_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const PENDING_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
const MAX_CLIENTS = 100;
const MAX_PENDING = 50;
const MAX_FAILURES = 5;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;

export async function hashPassphrase(passphrase: string, salt = randomBytes(16).toString("hex")) {
  return { salt, hash: await derive(passphrase, salt) };
}

function derive(passphrase: string, salt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    scrypt(passphrase, salt, 64, (error, key) => (error ? reject(error) : resolve(key.toString("hex"))));
  });
}

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

interface PendingAuthorization {
  clientId: string;
  params: AuthorizationParams;
  resource: string;
  expiresAt: number;
}

interface AuthorizationCode {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  resource: string;
  expiresAt: number;
}

export type ApprovalResult =
  | { kind: "redirect"; location: string }
  | { kind: "retry"; message: string; pendingId: string }
  | { kind: "expired" };

export class BridgeOAuthProvider implements OAuthServerProvider {
  readonly #state: BridgeState;
  readonly #save: () => void;
  readonly #resource: string;
  readonly #pending = new Map<string, PendingAuthorization>();
  readonly #codes = new Map<string, AuthorizationCode>();

  constructor(state: BridgeState, save: () => void, resource: string) {
    this.#state = state;
    this.#save = save;
    this.#resource = resource;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (clientId) => this.#state.clients[clientId],
      registerClient: (client) => {
        const bad = client.redirect_uris.find((uri) => !ALLOWED_REDIRECT_URIS.has(String(uri)));
        if (bad !== undefined) {
          throw new InvalidClientMetadataError(`redirect_uri is not allowed: ${String(bad)}`);
        }
        const registered = {
          ...client,
          client_id: randomUUID(),
          client_id_issued_at: Math.floor(Date.now() / 1000),
        } as OAuthClientInformationFull;
        this.#state.clients[registered.client_id] = registered;
        this.#evictClients();
        this.#save();
        return registered;
      },
    };
  }

  /** Claude registers a new client on each fresh connection, and the endpoint is public. */
  #evictClients(): void {
    const ids = Object.keys(this.#state.clients);
    if (ids.length <= MAX_CLIENTS) return;
    const inUse = new Set(
      [...Object.values(this.#state.accessTokens), ...Object.values(this.#state.refreshTokens)].map((t) => t.clientId),
    );
    const removable = ids
      .filter((id) => !inUse.has(id))
      .sort((a, b) => (this.#state.clients[a]?.client_id_issued_at ?? 0) - (this.#state.clients[b]?.client_id_issued_at ?? 0));
    for (const id of removable.slice(0, ids.length - MAX_CLIENTS)) delete this.#state.clients[id];
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (params.resource !== undefined && !this.#matchesResource(params.resource)) {
      throw new InvalidTargetError("This server only issues tokens for its own /mcp resource.");
    }
    this.#prunePending();
    const pendingId = randomBytes(32).toString("base64url");
    this.#pending.set(pendingId, {
      clientId: client.client_id,
      params,
      resource: this.#resource,
      expiresAt: Date.now() + PENDING_TTL_MS,
    });
    sendSignInPage(res, {
      pendingId,
      clientName: client.client_name ?? "An MCP client",
      redirectHost: new URL(params.redirectUri).host,
    });
  }

  describePending(pendingId: string): { clientName: string; redirectHost: string } | undefined {
    const pending = this.#pending.get(pendingId);
    if (!pending || pending.expiresAt < Date.now()) return undefined;
    return {
      clientName: this.#state.clients[pending.clientId]?.client_name ?? "An MCP client",
      redirectHost: new URL(pending.params.redirectUri).host,
    };
  }

  #prunePending(): void {
    const now = Date.now();
    for (const [id, pending] of this.#pending) if (pending.expiresAt < now) this.#pending.delete(id);
    for (const [code, entry] of this.#codes) if (entry.expiresAt < now) this.#codes.delete(code);
    while (this.#pending.size >= MAX_PENDING) {
      const oldest = this.#pending.keys().next().value;
      if (oldest === undefined) break;
      this.#pending.delete(oldest);
    }
  }

  async approve(pendingId: string, passphrase: string): Promise<ApprovalResult> {
    const pending = this.#pending.get(pendingId);
    if (!pending || pending.expiresAt < Date.now()) return { kind: "expired" };

    const now = Date.now();
    if (this.#state.signInLockedUntil > now) {
      return { kind: "retry", pendingId, message: "Too many wrong passphrases. Sign-in is locked for 15 minutes." };
    }
    const actual = Buffer.from(await derive(passphrase, this.#state.passphrase.salt), "hex");
    const expected = Buffer.from(this.#state.passphrase.hash, "hex");
    if (!timingSafeEqual(actual, expected)) {
      this.#state.signInFailures = [...this.#state.signInFailures.filter((at) => at > now - FAILURE_WINDOW_MS), now];
      if (this.#state.signInFailures.length >= MAX_FAILURES) {
        this.#state.signInLockedUntil = now + FAILURE_WINDOW_MS;
        this.#state.signInFailures = [];
      }
      this.#save();
      return { kind: "retry", pendingId, message: "That passphrase is not correct." };
    }

    this.#state.signInFailures = [];
    this.#save();
    this.#pending.delete(pendingId);
    const code = randomBytes(32).toString("base64url");
    this.#codes.set(code, {
      clientId: pending.clientId,
      codeChallenge: pending.params.codeChallenge,
      redirectUri: pending.params.redirectUri,
      scopes: [OAUTH_SCOPE],
      resource: pending.resource,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    const location = new URL(pending.params.redirectUri);
    location.searchParams.set("code", code);
    if (pending.params.state !== undefined) location.searchParams.set("state", pending.params.state);
    return { kind: "redirect", location: location.toString() };
  }

  #liveCode(client: OAuthClientInformationFull, code: string): AuthorizationCode {
    const entry = this.#codes.get(code);
    if (!entry || entry.clientId !== client.client_id || entry.expiresAt < Date.now()) {
      throw new InvalidGrantError("Invalid or expired authorization code.");
    }
    return entry;
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    return this.#liveCode(client, code).codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    code: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const entry = this.#liveCode(client, code);
    this.#codes.delete(code);
    if (redirectUri !== undefined && redirectUri !== entry.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request.");
    }
    if (resource !== undefined && !this.#matchesResource(resource)) {
      throw new InvalidTargetError("This server only issues tokens for its own /mcp resource.");
    }
    return this.#issue(client.client_id, entry.scopes);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const key = sha256(refreshToken);
    const stored = this.#state.refreshTokens[key];
    if (!stored || stored.clientId !== client.client_id || stored.expiresAt < Date.now()) {
      throw new InvalidGrantError("Invalid or expired refresh token.");
    }
    if (scopes?.some((scope) => !stored.scopes.includes(scope))) {
      throw new InvalidGrantError("Requested scope exceeds the original grant.");
    }
    if (resource !== undefined && !this.#matchesResource(resource)) {
      throw new InvalidTargetError("This server only issues tokens for its own /mcp resource.");
    }
    delete this.#state.refreshTokens[key];
    return this.#issue(client.client_id, scopes ?? stored.scopes);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const stored = this.#state.accessTokens[sha256(token)];
    if (!stored || stored.expiresAt < Date.now()) {
      // The SDK maps this error to 401 invalid_token, which starts Claude's refresh.
      throw new InvalidTokenError("Invalid or expired access token.");
    }
    return {
      token,
      clientId: stored.clientId,
      scopes: stored.scopes,
      expiresAt: Math.floor(stored.expiresAt / 1000),
      resource: new URL(stored.resource),
    };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const key = sha256(request.token);
    for (const table of [this.#state.accessTokens, this.#state.refreshTokens]) {
      if (table[key]?.clientId === client.client_id) delete table[key];
    }
    this.#save();
  }

  #matchesResource(resource: URL): boolean {
    const normalize = (value: string) => value.replace(/#.*$/, "").replace(/\/$/, "");
    return normalize(resource.href) === normalize(this.#resource);
  }

  #issue(clientId: string, scopes: string[]): OAuthTokens {
    const now = Date.now();
    for (const table of [this.#state.accessTokens, this.#state.refreshTokens]) {
      for (const [key, token] of Object.entries(table)) if (token.expiresAt < now) delete table[key];
    }
    const accessToken = randomBytes(32).toString("base64url");
    const refreshToken = randomBytes(32).toString("base64url");
    const record = (ttl: number): StoredToken => ({ clientId, scopes, resource: this.#resource, expiresAt: now + ttl });
    this.#state.accessTokens[sha256(accessToken)] = record(ACCESS_TTL_MS);
    this.#state.refreshTokens[sha256(refreshToken)] = record(REFRESH_TTL_MS);
    this.#save();
    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TTL_MS / 1000,
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    };
  }
}

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);

export function sendSignInPage(
  res: Response,
  input: { pendingId: string; clientName: string; redirectHost: string; error?: string },
): void {
  // form-action must list Claude: browsers apply it to the redirect after the form posts.
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://claude.ai https://claude.com; frame-ancestors 'none'; base-uri 'none'",
  );
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  res.status(input.error ? 401 : 200).type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect T3 Code</title>
<style>
:root{color-scheme:light dark}
body{font:16px/1.5 system-ui,sans-serif;max-width:26rem;margin:15vh auto;padding:0 16px}
input,button{font:inherit;width:100%;box-sizing:border-box;padding:.6rem;margin-top:.5rem}
.error{color:#c62828}
</style></head><body>
<h1>Connect T3 Code</h1>
<p><strong>${escapeHtml(input.clientName)}</strong> wants to start and read agent threads on this machine. The sign-in code goes to <strong>${escapeHtml(input.redirectHost)}</strong>.</p>
${input.error ? `<p class="error" role="alert">${escapeHtml(input.error)}</p>` : ""}
<form method="post" action="/authorize/approve">
<input type="hidden" name="pending" value="${escapeHtml(input.pendingId)}">
<label for="passphrase">Bridge passphrase</label>
<input id="passphrase" name="passphrase" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Allow</button>
</form></body></html>`);
}
