# Sentinel Brief — web console

A single-screen **SOC Detection-to-Decision console** that renders the
`IncidentBrief` the agents produce: a fired Splunk alert, an animated multi-agent
war room (supervisor + 4 subagents), then the adjudicated brief — verdict,
MITRE ATT&CK, multi-index kill-chain timeline, ranked blast radius, human-approval
actions, the SPL detection-fix diff, and the hero: the **backtested 75%
false-positive reduction** (true positive retained).

Stack: **Vite + React + Tailwind + Framer Motion**.

## Run (frontend only — instant, offline, demo-safe)

```bash
cd sentinel_brief/web
npm install
npm run dev          # http://localhost:5173
```

The UI bundles `sample_brief.json` (a real captured run), so it renders instantly
and never depends on a backend or live Splunk during a demo.

## Optional: serve through the backend

```bash
npm run build                                    # builds dist/
pip install fastapi uvicorn
cd sentinel_brief/web
uvicorn backend.app:app --port 8000              # serves UI + /api/brief
```

- `GET /api/brief` — the cached brief (default data source).
- `POST /api/run` — runs the real `run_sentinel_brief` pipeline. Disabled unless
  `SENTINEL_ALLOW_LIVE=1`; any failure degrades to the cached brief, so the demo
  never breaks.

The console is a **view layer** over the typed `IncidentBrief` — the agents,
Splunk integration, MCP calls, and backtest all live in the Python package.
