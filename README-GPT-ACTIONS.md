# BugScout GPT Actions REST API (adapter package)

This adapter keeps the existing `bugscout_mcp.py` analysis engine as the source of truth and exposes it over ordinary HTTPS REST endpoints. GPT Actions call REST/OpenAPI; they do not speak MCP.

## Files added
- `api_main.py`
- `requirements-api.txt`
- `render.yaml`
- `openapi.yaml`

Keep the existing `bugscout_mcp.py` and its analysis rules unchanged.

## Deploy
1. Deploy this repository as a Render Web Service.
2. Render detects `render.yaml`; deploy.
3. Ensure `BUGSCOUT_API_TOKEN` is a long random secret (32+ characters). Never put it in GitHub or GPT instructions.
4. Open `https://YOUR-SERVICE.onrender.com/openapi.json` to inspect the generated OpenAPI 3.1 document.
5. Test `/health`, then authenticated `/gate/check`.

The free Render service may sleep when idle; the first request can be slow.

## Local development with .env

1. Copy `.env.example` to a file named `.env`.
2. Replace `BUGSCOUT_API_TOKEN` with a random secret of at least 32 characters.
3. Install the API dependencies: `pip install -r requirements-api.txt`.
4. Start the API: `uvicorn api_main:app --reload`.

The API loads `.env` automatically for local development. The real `.env` file is ignored by Git; only the placeholder `.env.example` is committed. Never paste a real token into GitHub, chat, or the OpenAPI schema.

For Render, set `BUGSCOUT_API_TOKEN` and other settings in the service's Environment dashboard. Do not upload the local `.env` file to Render.

## GPT Actions setup
In the GPT editor, add an Action and import:
`https://YOUR-SERVICE.onrender.com/openapi.json`

Configure Authentication as API Key, auth type Bearer, and paste the same `BUGSCOUT_API_TOKEN` value.

## REST operations
- `POST /gate/check` — quick SEND / SEND_WITH_NOTE / DO_NOT_SEND verdict
- `POST /analyze/code` — full code report
- `POST /gate/check-file` — upload one source file and gate-check it
- `POST /analyze/file` — upload one source file and get the full report
- `POST /analyze/archive` — inspect up to 50 supported source files in a ZIP
- `GET /languages` — checker availability
- `GET /guide` — BugScout usage guide
- `POST /prompts/send-script` — prompt helper
- `GET /health` — health check (no authentication)

## Safety and limitations
- BugScout is a heuristic bug checker, not a security scanner. SEND is not a security approval.
- Uploaded files are read in memory; ZIP entries are never extracted to disk. ZIP traversal paths and oversized files are rejected.
- Compiler checks remain opt-in. Enable only when the host has the required compiler tools.
- The existing engine imports FastMCP, so `mcp` remains a dependency for now even though the deployed interface is REST.
- Never commit API tokens. Rotate a token if exposed.
