# MCP Server — Connect Your Agents to Hakuna

Hakuna exposes a [Model Context Protocol](https://modelcontextprotocol.io/) server so you can connect Claude Desktop, Cursor, custom Claude SDK agents, or any MCP-compatible client and query findings, assets, and campaigns through tools.

- **Endpoint:** `POST {your-hakuna-host}/api/mcp`
- **Transport:** Streamable HTTP (JSON-RPC 2.0)
- **Auth:** `Authorization: Bearer hak_…` (long-lived API token) + `X-Org-Context: <org_id>` header

## 1. Mint an API token

1. Sign in to Hakuna → **Settings → API Tokens** (under "Platform").
2. Click **New token**.
3. Name it for the client (e.g. `claude-desktop`, `cursor`, `ci-runner`).
4. Pick scopes — for MCP read access, leave the default `mcp:read`.
5. Optionally set an expiry. No expiry = lives until revoked.
6. Click **Create token**. The plaintext is shown **once**. Copy it immediately, along with the prepared MCP config snippet, then close the dialog.

> Tokens inherit your role and your current `X-Org-Context`. Revoke any time from the same page.

## 2. Configure your MCP client

### Claude Desktop / Claude Code

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "hakuna": {
      "url": "https://your-hakuna-host/api/mcp",
      "headers": {
        "Authorization": "Bearer hak_YOUR_TOKEN_HERE",
        "X-Org-Context": "1"
      }
    }
  }
}
```

Restart Claude Desktop. The Hakuna tools appear in the tools menu.

### Cursor

Settings → MCP → Add Server → `Streamable HTTP`. Same URL + headers as above.

### Custom (Claude Agent SDK)

```python
from anthropic import Anthropic
from anthropic.types.beta import BetaMessageParam

client = Anthropic()
response = client.beta.messages.create(
    model="claude-opus-4-7",
    mcp_servers=[{
        "type": "url",
        "url": "https://your-hakuna-host/api/mcp",
        "name": "hakuna",
        "authorization_token": "hak_YOUR_TOKEN_HERE",
    }],
    messages=[{"role": "user", "content": "Show me the top 5 KEV-listed findings."}],
    max_tokens=1024,
)
```

(Plus an `X-Org-Context` header where your transport allows custom headers.)

### Verifying with curl

```bash
curl -s -X POST https://your-hakuna-host/api/mcp \
  -H "Authorization: Bearer hak_YOUR_TOKEN_HERE" \
  -H "X-Org-Context: 1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
```

You should see five tools listed.

## 3. Available tools

All read-only. All scoped to orgs your user can access.

| Tool | Purpose | Key arguments |
|---|---|---|
| `list_findings` | List findings ordered by priority score | `severity`, `kev_only`, `exploit_available`, `search`, `limit` |
| `get_finding` | Full detail for one finding | `finding_id` |
| `list_assets` | List assets ordered by risk score | `asset_type`, `criticality_min`, `internet_facing_only`, `search`, `limit` |
| `get_asset` | Full detail for one asset | `asset_id` |
| `list_campaigns` | List remediation campaigns | `status`, `limit` |

For the full input schema, run `tools/list`.

## 4. Example prompts

Once connected, your agent can answer:

- *"What KEV-listed findings do we have on internet-facing assets?"*
- *"Show me the top 10 critical findings on our PCI-tagged hosts."*
- *"List active remediation campaigns and how many findings each has."*
- *"What's the asset with the highest risk score, and what are its top three findings?"*

## 5. Security notes

- Tokens are stored hashed (sha256). The plaintext is irrecoverable; if lost, revoke and mint a new one.
- A token's `last_used_at` updates on every successful auth — surface stale tokens from the listing page.
- API tokens use the `hak_` prefix so the auth layer can route them away from the JWT decoder. Don't include them in URLs or commit them to git.
- Recommend rotation: set `expires_in_days` to 90 for production agents.

## 6. Known limitations

- All tools are read-only today. `mcp:write` scope exists but no write tools are wired up yet.
- The transport responds with JSON; SSE streaming is not used (the current tools all return promptly).
- No rate limiting beyond the default backend slowapi config — open an issue if you need stricter quotas per token.
