import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export const RUNTIME_MODES = ["approval-required", "auto-accept-edits", "auto", "full-access"] as const;
export type RuntimeMode = (typeof RUNTIME_MODES)[number];

export interface StoredToken {
  clientId: string;
  scopes: string[];
  resource: string;
  expiresAt: number;
}

export interface BridgeState {
  publicUrl: string;
  port: number;
  t3Url: string;
  t3Token: string;
  t3TokenExpiresAt: number;
  maxRuntimeMode: RuntimeMode;
  defaultModel?: { instanceId: string; model: string };
  passphrase: { salt: string; hash: string };
  clients: Record<string, OAuthClientInformationFull>;
  /** Keyed by SHA-256 of the token, so a leaked state file cannot replay connector sessions. */
  accessTokens: Record<string, StoredToken>;
  refreshTokens: Record<string, StoredToken>;
  signInFailures: number[];
  signInLockedUntil: number;
}

export function defaultStatePath(): string {
  const base = process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
  return process.env.T3_DUET_BRIDGE_STATE ?? join(base, "t3-duet-bridge", "state.json");
}

export function loadState(path: string): BridgeState | undefined {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as BridgeState;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

/** Atomic and owner-only, because the file holds the T3 bearer token. */
export function saveState(path: string, state: BridgeState): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, JSON.stringify(state, null, 2), { mode: 0o600 });
  renameSync(temporary, path);
}
