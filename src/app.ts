import express from "express";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { BridgeOAuthProvider, OAUTH_SCOPE, sendSignInPage } from "./oauth.ts";
import type { BridgeState } from "./state.ts";
import { T3Client } from "./t3client.ts";
import { createMcpServer } from "./tools.ts";

export function createApp(state: BridgeState, save: () => void): express.Express {
  const base = new URL(state.publicUrl);
  const resource = new URL("/mcp", base);
  const provider = new BridgeOAuthProvider(state, save, resource.href);
  const t3 = new T3Client(state.t3Url, () => state.t3Token);

  const app = express();
  app.disable("x-powered-by");
  // The bridge binds to loopback, so the only proxy in front of it is the local tunnel.
  app.set("trust proxy", "loopback");

  app.get("/healthz", (_req, res) => void res.json({ ok: true }));

  app.post("/authorize/approve", express.urlencoded({ extended: false, limit: "8kb" }), async (req, res, next) => {
    try {
      const pendingId = String(req.body?.pending ?? "");
      const details = provider.describePending(pendingId);
      const result = await provider.approve(pendingId, String(req.body?.passphrase ?? ""));
      if (result.kind === "redirect") {
        res.setHeader("Cache-Control", "no-store");
        res.redirect(302, result.location);
      } else if (result.kind === "expired" || !details) {
        res.status(400).type("text").send("This sign-in request has expired. Start again from Claude.");
      } else {
        sendSignInPage(res, { pendingId, ...details, error: result.message });
      }
    } catch (error) {
      next(error);
    }
  });

  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: base,
      resourceServerUrl: resource,
      scopesSupported: [OAUTH_SCOPE],
      resourceName: "T3 Code",
    }),
  );

  const bearer = requireBearerAuth({
    verifier: provider,
    requiredScopes: [OAUTH_SCOPE],
    expectedResource: resource,
    resourceMetadataUrl: new URL("/.well-known/oauth-protected-resource/mcp", base).href,
  });

  app.post("/mcp", bearer, express.json({ limit: "1mb" }), async (req, res, next) => {
    try {
      // Stateless: nothing here needs a session, so a bridge restart never strands Claude.
      const server = createMcpServer(t3, state);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      next(error);
    }
  });

  const methodNotAllowed: express.RequestHandler = (_req, res) => {
    res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
  };
  app.get("/mcp", bearer, methodNotAllowed);
  app.delete("/mcp", bearer, methodNotAllowed);

  const onError: express.ErrorRequestHandler = (error, _req, res, _next) => {
    console.error("request failed:", (error as Error).message);
    if (!res.headersSent) res.status(500).json({ error: "server_error" });
  };
  app.use(onError);
  return app;
}
