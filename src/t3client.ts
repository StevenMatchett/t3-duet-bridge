/** Minimal client for a T3 Code environment: bearer HTTP for reads, one-shot WebSocket RPC for commands. */

const PROTOCOL_VERSION = "2";
const RPC_TIMEOUT_MS = 20_000;
const BOOTSTRAP_TOKEN_TYPE = "urn:t3:params:oauth:token-type:environment-bootstrap";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

/** Enough to run threads. Deliberately excludes terminal, filesystem, settings, and access scopes. */
export const BRIDGE_T3_SCOPES = "orchestration:read orchestration:operate";

export class T3Error extends Error {}

/** Accepts a bare token or the whole /pair#token=... link that T3 Code shows. */
export function parsePairingToken(input: string): string {
  const trimmed = input.trim();
  const match = /[#?&]token=([^&\s]+)/.exec(trimmed);
  return match?.[1] ? decodeURIComponent(match[1]) : trimmed;
}

export async function exchangePairingToken(
  t3Url: string,
  credential: string,
): Promise<{ token: string; expiresAt: number; scope: string }> {
  const response = await fetch(new URL("/oauth/token", t3Url), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: TOKEN_EXCHANGE_GRANT,
      subject_token: credential,
      subject_token_type: BOOTSTRAP_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TYPE,
      scope: BRIDGE_T3_SCOPES,
      client_label: "Claude Duet bridge",
    }),
  });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok || typeof body.access_token !== "string") {
    throw new T3Error(
      `T3 Code rejected the pairing token (HTTP ${response.status}). Pairing tokens are single use and short lived, so create a fresh one.`,
    );
  }
  return {
    token: body.access_token,
    expiresAt: Date.now() + Number(body.expires_in) * 1000,
    scope: String(body.scope),
  };
}

export class T3Client {
  readonly #baseUrl: string;
  readonly #token: () => string;

  constructor(baseUrl: string, token: () => string) {
    this.#baseUrl = baseUrl;
    this.#token = token;
  }

  async get<T>(path: string): Promise<T> {
    return this.#parse<T>(
      await this.#fetch(new URL(path, this.#baseUrl), { headers: this.#headers() }),
      path,
    );
  }

  async #fetch(url: URL, init: RequestInit): Promise<Response> {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(RPC_TIMEOUT_MS) });
    } catch (error) {
      throw new T3Error(`T3 Code is not reachable at ${this.#baseUrl}: ${(error as Error).message}`);
    }
  }

  #headers(): Record<string, string> {
    return {
      authorization: `Bearer ${this.#token()}`,
      "x-t3-orchestration-protocol": PROTOCOL_VERSION,
    };
  }

  async #parse<T>(response: Response, label: string): Promise<T> {
    if (response.status === 401) {
      throw new T3Error(
        "T3 Code rejected the bridge's session. It may have expired or been revoked, so re-run `t3-duet-bridge setup` with a new pairing token.",
      );
    }
    if (!response.ok) {
      const detail = (await response.text().catch(() => "")).slice(0, 300);
      throw new T3Error(`T3 Code returned HTTP ${response.status} for ${label}: ${detail}`);
    }
    return (await response.json()) as T;
  }

  async rpc<T>(method: string, payload: unknown): Promise<T> {
    const ticketResponse = await this.#fetch(new URL("/api/auth/websocket-ticket", this.#baseUrl), {
      method: "POST",
      headers: this.#headers(),
    });
    const { ticket } = await this.#parse<{ ticket: string }>(ticketResponse, "websocket ticket");

    const url = new URL("/ws", this.#baseUrl);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.searchParams.set("wsTicket", ticket);
    url.searchParams.set("orchestrationProtocol", PROTOCOL_VERSION);

    return new Promise<T>((resolve, reject) => {
      const socket = new WebSocket(url);
      const finish = (settle: () => void) => {
        clearTimeout(timer);
        socket.onclose = null;
        socket.close();
        settle();
      };
      const timer = setTimeout(
        () => finish(() => reject(new T3Error(`T3 Code did not answer ${method} in time.`))),
        RPC_TIMEOUT_MS,
      );
      socket.onopen = () => {
        socket.send(JSON.stringify({ _tag: "Request", id: "1", tag: method, payload, headers: [] }));
      };
      socket.onerror = () =>
        finish(() => reject(new T3Error(`Could not open a T3 Code connection for ${method}.`)));
      socket.onclose = () =>
        finish(() => reject(new T3Error(`T3 Code closed the connection during ${method}.`)));
      socket.onmessage = (event) => {
        const message = JSON.parse(String(event.data)) as {
          _tag: string;
          requestId?: string;
          exit?: { _tag: "Success"; value: T } | { _tag: "Failure"; cause: unknown };
        };
        if (message._tag !== "Exit" || message.requestId !== "1" || !message.exit) return;
        const { exit } = message;
        if (exit._tag === "Success") finish(() => resolve(exit.value));
        else finish(() => reject(new T3Error(`T3 Code refused ${method}: ${describeCause(exit.cause)}`)));
      };
    });
  }
}

function describeCause(cause: unknown): string {
  const failures = Array.isArray(cause) ? cause : [cause];
  return failures
    .map((failure) => {
      const { error, defect } = (failure ?? {}) as { error?: { message?: string; _tag?: string }; defect?: unknown };
      return error?.message ?? error?._tag ?? (defect ? "internal server error" : "unknown error");
    })
    .join("; ");
}
