# NordStellar MCP

Connect any MCP-compatible AI assistant to NordStellar so you can query your platform data directly from chat.

## What you get

- Use natural language to ask about NordStellar data
- No need to switch to the NordStellar UI or write GraphQL by hand
- Secure login via your NordStellar account

## Setup

### 1. Add to your MCP client

Add the NordStellar MCP server to your AI assistant’s MCP configuration (e.g. `mcp.json` or the equivalent in your client):

```json
{
  "nordstellar-mcp": {
    "command": "uvx",
    "args": [
      "nordstellar-mcp",
      "https://platform-mcp.nordstellar.com/mcp"
    ]
  }
}
```

`uvx` pulls the [`nordstellar-mcp`](https://pypi.org/project/nordstellar-mcp/) package from PyPI. To pin a version, use e.g. `"--from", "nordstellar-mcp==0.1.3"` before the tool name in `args`.

To run the same from a shell:

```bash
uvx nordstellar-mcp https://platform-mcp.nordstellar.com/mcp
```

The default endpoint is `https://platform-mcp.nordstellar.com/mcp`. Contact your NordStellar administrator if you need a different URL.

### 2. First-time login

When you first use NordStellar, a browser window will open. Sign in with your NordStellar credentials. After that, you’re set—the connection stays authenticated until you sign out or the session expires.

### 3. Start using it

Ask your AI assistant things like “What projects do I have?” or “Show me recent activity” and it will use your NordStellar data to answer.

### 4. Install agent skills (optional)

You can install bundled skills the same way as other `npx skills add` workflows (for example the [Google Workspace CLI](https://github.com/googleworkspace/cli) repo):

```bash
# Install all skills at once
npx skills add https://github.com/NordStellar/nordstellar-mcp

# Or pick only what you need
npx skills add https://github.com/NordStellar/nordstellar-mcp/tree/main/skills/nordstellar-general
npx skills add https://github.com/NordStellar/nordstellar-mcp/tree/main/skills/attack-surface-management
npx skills add https://github.com/NordStellar/nordstellar-mcp/tree/main/skills/dark-web-search
npx skills add https://github.com/NordStellar/nordstellar-mcp/tree/main/skills/domain-squatting
npx skills add https://github.com/NordStellar/nordstellar-mcp/tree/main/skills/malware-infection-analysis
```

## Credential storage

Session cookies are saved in your OS credential store under the service name `NordStellar MCP`:

- **macOS** — Keychain
- **Windows** — Credential Locker
- **Linux** — Freedesktop Secret Service (for example GNOME Keyring or KWallet)

If no secure credential store is available, the proxy keeps credentials in memory only. In that mode, credentials are lost when the process exits.

Any application running as your user account may be able to read stored credentials through the OS credential APIs. This is the standard behavior for desktop credential stores.

### Clear stored credentials

To remove stored session cookies, use one of the following:

- Any platform: run `nordstellar-mcp --logout`
- macOS: run `security delete-generic-password -s "NordStellar MCP"`
- Windows: remove the Generic Credential named `NordStellar MCP` from Credential Manager
- Linux: remove the `NordStellar MCP` secret from your Secret Service keyring (for example with Seahorse or KWallet Manager)

## Token lifetime and refresh behavior

This proxy stores whatever authentication cookies the NordStellar backend sets and refreshes the session through `POST /auth/refresh-token` when it needs a fresh `AccessToken`.

The repository does not define backend token lifetimes or refresh-token rotation policy. The `AccessToken` cookie payload includes an `expires_in` field, but the exact TTLs and whether refresh cookies rotate are backend-controlled and should be confirmed with NordStellar platform operators.

## Requirements

- [uv](https://docs.astral.sh/uv/) installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Python 3.10 or newer (uv handles this automatically)
- [keyring](https://pypi.org/project/keyring/) — installed automatically as a dependency. Provides persistent, secure credential storage using each platform's native backend:
  - **macOS** — Keychain
  - **Windows** — Credential Locker
  - **Linux** — Freedesktop Secret Service (GNOME Keyring / KWallet). Requires `gnome-keyring` or `kwallet` to be available; on headless systems, see the [keyring docs](https://pypi.org/project/keyring/) for setup instructions.

## Community

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Need help?

Contact your NordStellar administrator for the correct MCP endpoint URL and any access questions.
