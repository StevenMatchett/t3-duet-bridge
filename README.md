# t3-duet-bridge

A remote MCP server that lets Claude Duet start and read T3 Code threads, added to claude.ai as a custom connector.

This is an unofficial community project, not affiliated with Anthropic or T3 Code.

T3 Connect cannot do this itself. Its OAuth only supports DPoP token exchange for T3's own clients, and T3's `/mcp` endpoint only accepts tokens minted for its own agent threads. This bridge provides the OAuth flow claude.ai expects and calls your T3 Code server locally.

```
Claude Duet -> claude.ai -> your HTTPS tunnel -> bridge (127.0.0.1:3774) -> T3 Code (127.0.0.1:3773)
```

## Tools

| Tool | Effect |
| --- | --- |
| `list_projects`, `list_models`, `list_threads`, `read_thread` | Read only |
| `start_thread`, `send_message` | Run an agent on your machine |
| `stop_thread` | Interrupt the active run |

The tools wait up to 45 seconds for an answer. Longer runs report `still_working`, and Duet checks back with `read_thread`.

## Setup

Requires Node 24 or newer and a claude.ai plan with Duet and custom connectors.

1. **Install.**

   ```bash
   git clone https://github.com/StevenMatchett/t3-duet-bridge.git
   cd t3-duet-bridge
   pnpm install
   ```

2. **Start a tunnel to port 3774.** Note the HTTPS origin. A stable hostname matters, because the connector and its OAuth issuer are tied to it. Tailscale Funnel gives you one, while a Cloudflare quick tunnel changes on every restart.

   ```bash
   tailscale funnel --bg 3774
   ```

3. **Create a T3 pairing link.** In T3 Code, open Settings, then Connections, and create a pairing link. Copy it. Links are single use and short lived.

4. **Run setup and paste the link when asked.** Save the passphrase it prints, because it is shown once.

   ```bash
   node src/cli.ts setup --public-url https://your-host.example
   ```

5. **Run the bridge.** To keep it running as a service:

   ```bash
   cp deploy/t3-duet-bridge.service ~/.config/systemd/user/
   systemctl --user daemon-reload
   systemctl --user enable --now t3-duet-bridge
   loginctl enable-linger "$USER"
   ```

   Or run it in the foreground with `node src/cli.ts serve`. The unit file assumes the repo is at `~/code/t3-duet-bridge` and that systemd can find `node`, so edit `ExecStart` if either is not true.

6. **Check it.**

   ```bash
   node src/cli.ts doctor
   ```

7. **Add the connector.** In claude.ai, open Settings, then Connectors, then Add custom connector. Enter `https://your-host.example/mcp`, leave the client ID and secret empty, and sign in with the passphrase.

8. **Set approvals.** In the connector's tool permissions, set `start_thread` and `send_message` to need approval. See the security section for why.

### Keep the `t3` CLI in step with the app

Use the T3 Code app for pairing if your `t3` command is older than the desktop app. Check with `t3 --version`. An older CLI should not touch the running app's data directory. The desktop build's own CLI is always in step. On a Linux package install it looks like this, and other installs use a different path:

```bash
ELECTRON_RUN_AS_NODE=1 /usr/lib/t3code/t3code \
  /usr/lib/t3code/resources/app.asar/apps/server/dist/bin.mjs auth pairing create --json
```

## Maintenance

Stop the bridge before running `setup` or `revoke`, and start it again afterwards. A running bridge keeps its settings in memory and can overwrite your change. Restarting also cancels any sign-in page that is open.

- **Renewal:** the T3 session lasts 30 days and cannot be refreshed. `doctor` shows the time left. To renew, create a new pairing link and run `node src/cli.ts setup`.
- **Sign everyone out:** run `node src/cli.ts revoke`.
- **Revoke the bridge's T3 access:** remove the "Claude Duet bridge" client in T3 Code under Settings, then Connections.
- **Change the passphrase:** run `node src/cli.ts setup --skip-pairing --rotate-passphrase`.

## Security

This connector lets a remote caller run coding agents on your computer. Read this before exposing it.

- **Prompt injection is the main risk.** Duet reads things other people write, such as email. A crafted message could try to make Duet start a thread. Requiring approval for `start_thread` and `send_message` in claude.ai is your check on that.
- **Agents ask before acting.** New threads use `approval-required`, and decisions can only be made in T3 Code. The bridge has no tool for answering them. The limit also blocks `send_message` to any thread running above it.
- **Raising the limit removes that protection.** `--max-runtime-mode full-access` lets a prompt-injected message run commands with no human check. It is not recommended.
- **Read tools see every thread.** Anyone signed in can read all thread text in T3 Code, including any secrets pasted there.
- **Sign-in is one passphrase.** Five failures lock sign-in for 15 minutes for everyone, so someone with your URL can repeatedly lock you out, but cannot sign in without the passphrase.
- **Scopes are narrow.** The T3 session holds only `orchestration:read` and `orchestration:operate`. It has no terminal, filesystem, settings, or access management scope, though agents themselves can still use those through their own tools once approved.
- **Codes only go to Claude.** Registration refuses any callback other than Claude's.
- **Local state is sensitive.** `~/.config/t3-duet-bridge/state.json` is owner-only and holds the T3 bearer token in plain text. Connector tokens are stored hashed.

## Known limits

- T3 Code cannot wake Duet. Duet learns about results when it next checks.
- Approvals cannot be answered from Duet, by design.
- Attachments are not supported.
- The bridge must run on the same machine as T3 Code, because `setup` assumes a loopback T3 address unless you pass `--t3-url`.
- The bridge uses T3 Code's internal protocol (version 2), which has no stability promise, so a T3 update may break it. Run `doctor` after updating.

## Development

```bash
pnpm test
pnpm typecheck
```

`scripts/live-check.ts` runs the OAuth flow and every tool against a real server, including real agent turns. Use a throwaway server, because it creates projects and threads:

```bash
ELECTRON_RUN_AS_NODE=1 /usr/lib/t3code/t3code \
  /usr/lib/t3code/resources/app.asar/apps/server/dist/bin.mjs \
  serve --base-dir /tmp/t3-live --port 3999 --host 127.0.0.1
# Create a pairing token with `auth pairing create --base-dir /tmp/t3-live --json`, then:
T3_URL=http://127.0.0.1:3999 T3_PAIRING_TOKEN=... LIVE_WORKSPACE=/tmp/t3-live-project \
  node scripts/live-check.ts
```
