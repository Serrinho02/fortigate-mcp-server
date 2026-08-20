# Installation

## Requirements

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`
- A supported OS credential store for `fortinet-mcp-cred`:
  - **Windows** -- Windows Credential Manager (built in, no setup needed)
  - **macOS** -- Keychain (built in, no setup needed)
  - **Linux desktop** -- a running Secret Service daemon (GNOME Keyring, KWallet); most desktop distros have one by default
  - **Linux headless / Docker** -- see [Docker](#docker) below, this needs extra setup

## 1. Clone and install dependencies

```bash
git clone https://github.com/Serrinho02/fortigate-mcp-server.git
cd fortigate-mcp-server
uv sync
```

This creates `.venv/` with every dependency, including `keyring`, `sqlalchemy`, `aiosqlite`, and `mcp`.

## 2. Create a config file

The server still reads a `config/config.json` on startup (a legacy artifact of the original single-file device list). If you're only using the newer inventory system (recommended -- see [Usage](USAGE.md)), an empty device list is enough:

```json
{ "fortigate": { "devices": {} } }
```

Copy [`config/config.example.json`](../config/config.example.json) instead if you want to also pre-register devices the old, config-file way (not recommended for anything beyond quick local testing -- credentials in that file are **not** encrypted).

`config/config.json` and `config/inventory.db` are already gitignored -- never commit either.

## 3. First run / health check

```bash
FORTIGATE_MCP_CONFIG=$(pwd)/config/config.json uv run python -m src.fortigate_mcp.server
```

On Windows PowerShell:

```powershell
$env:FORTIGATE_MCP_CONFIG = "$PWD\config\config.json"
uv run python -m src.fortigate_mcp.server
```

The server communicates over stdio -- it won't print much and will just sit there waiting for an MCP client. That's expected; skip straight to wiring it into a client (step 5) rather than trying to interact with it directly in a terminal.

## 4. Register a device and provision its credential

This is the two-channel flow the security model is built around (see the main [README](../README.md#security-model)):

1. From your MCP client, call `inventory_register_device_pending` with the device's host/name/customer/site. It returns a `credential_id` (e.g. `cred_a83653612dc2`) and marks the credential as not-yet-provisioned.
2. **Locally, outside of any AI/MCP interaction**, run:

   ```bash
   .venv/Scripts/fortinet-mcp-cred.exe set cred_a83653612dc2 --auth-type token   # Windows
   .venv/bin/fortinet-mcp-cred set cred_a83653612dc2 --auth-type token           # macOS/Linux
   ```

   It prompts for the API token (or `--auth-type basic` for username/password) and stores it in your OS credential store. The secret is typed once, here, and nowhere else.

   > If `fortinet-mcp-cred` isn't found when you run it plainly, it's because it's only on `PATH` inside the activated venv -- either activate the venv first (`source .venv/bin/activate` / `.venv\Scripts\activate`) or call the full path shown above.

3. Call `connection_connect` with the device's name (or site/customer/IP) from your MCP client. It resolves the target, opens a session, and runs a health probe.

## 5. Wire it into an MCP client

### Claude Desktop

Edit your `claude_desktop_config.json` (`%APPDATA%\Claude\claude_desktop_config.json` on Windows, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "C:\\path\\to\\fortigate-mcp-server\\.venv\\Scripts\\python.exe",
      "args": ["-m", "src.fortigate_mcp.server"],
      "env": {
        "FORTIGATE_MCP_CONFIG": "C:\\path\\to\\fortigate-mcp-server\\config\\config.json",
        "FORTINET_MCP_DB_URL": "sqlite+aiosqlite:///C:/path/to/fortigate-mcp-server/config/inventory.db",
        "FORTINET_MCP_MODE": "full"
      }
    }
  }
}
```

On macOS/Linux, use the venv's `bin/python` and forward-slash paths instead. `FORTINET_MCP_DB_URL` is optional (defaults to `config/inventory.db` relative to the working directory) but setting it explicitly avoids surprises about which directory the server was launched from. Restart Claude Desktop after editing.

### Claude Code / other stdio clients

Same `command`/`args`/`env` shape as above, per that client's MCP server configuration format.

### HTTP transport

For network-accessible deployments (multiple clients, a shared server), use `src.fortigate_mcp.server_http` instead:

```bash
uv run python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 --path /fortigate-mcp --config config/config.json
```

Point an HTTP-capable MCP client at `http://<host>:8814/fortigate-mcp/`. There is no built-in authentication on this transport beyond what's configured in `config.json`'s `auth` section -- put it behind a reverse proxy (see [`nginx/`](../nginx/)) with TLS and real access control if it's reachable beyond localhost.

## Docker

```bash
docker compose up --build
```

This builds the image and mounts `config/config.json`. **Before relying on this in production, be aware of one real gap:** `CredentialManager` uses the OS `keyring` library, and a bare Linux container has no Secret Service daemon for it to talk to. `fortinet-mcp-cred` (and anything that provisions a credential) will fail inside the container as shipped.

To fix this, add the [`keyrings.cryptfile`](https://pypi.org/project/keyrings.cryptfile/) backend to the image and configure it with a master passphrase supplied via an environment variable or mounted secret file -- this isn't wired up in this repo yet (tracked as a known limitation, see the main README). Until then, either:
- provision credentials on a host with a working keyring backend and don't run the credential CLI inside the container, or
- run the server natively (not in Docker) if you need `fortinet-mcp-cred` to work.

Also mount `config/inventory.db` as a volume (add it next to the `config.json` mount in `docker-compose.yml`) so the inventory survives container restarts -- it's SQLite, so a bind-mounted file is enough, no separate database service needed.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `FORTIGATE_MCP_CONFIG` | *(required)* | Path to the legacy `config.json`. |
| `FORTINET_MCP_DB_URL` | `sqlite+aiosqlite:///config/inventory.db` | SQLAlchemy URL for the inventory/change-history store. |
| `FORTINET_MCP_MODE` | `full` | `read_only` \| `safe` \| `full` -- see the main README's Operating Modes section. |

## Troubleshooting

- **`fortinet-mcp-cred: command not found`** -- it's a console script installed only inside `.venv`. Activate the venv or call it by full path (see step 4 above).
- **`Resource not found` on a device you just registered** -- make sure you ran `fortinet-mcp-cred set` for its `credential_id`; `connection_connect`/any device tool will otherwise fail with a credential-not-provisioned error, not a silent success.
- **`Server is in READ_ONLY mode` on every mutation** -- check `FORTINET_MCP_MODE` in your client's server config; it's not something a tool call can override at runtime.
- **Changed `config.json` but nothing changed** -- the server reads it once at startup; restart your MCP client (which restarts the server process) after editing it.
