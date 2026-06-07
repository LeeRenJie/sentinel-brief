# Sentinel Brief

**A multi-agent Detection-to-Decision war room for the SOC, built on Splunk
`splunklib.ai`.** When a detection fires, Sentinel Brief turns it into one typed,
auditable incident brief — verdict, MITRE ATT&CK mapping, attack timeline, blast
radius, human-approved containment, and **the SPL rule fix that stops the alert
from over-firing next time, backtested on real data to prove the false-positive
reduction** — in under three minutes.

> Splunk Agentic Ops Hackathon · Security track · Grand Prize entry.

---

## The problem: alert fatigue *and* detection drift

A fired Splunk detection lands on an analyst's queue and the clock starts. The
analyst manually pivots across indexes to answer four different questions:

1. **Is this real?** (true positive, or noise?)
2. **How far did it spread?** (which hosts and accounts are in the blast radius?)
3. **What do we do?** (which SOP-grounded containment action, approved by a human?)
4. **Why did our detection miss or over-fire?** — *and nobody ever gets to #4.*

That last question is **detection drift**: the rule that keeps paging the SOC at
2am on a legitimate backup service account never gets fixed, so the false
positives recur forever and real signal drowns. Splunk's own first-party Triage
Agent answers question #1. **Nothing ships that closes the loop on #4.**

## The solution: one war room, one auditable brief

Sentinel Brief is a **supervisor agent** that orchestrates **four specialist
subagents**, each on its own model tier, and collapses the whole investigation
into a single typed `IncidentBrief` — not a chat transcript:

| Subagent | Tier | Job |
|---|---|---|
| **Correlator** | flash | Multi-index event **timeline** + ranked **blast-radius** entities via SPL tools |
| **Adjudicator** | pro | **Verdict + confidence + severity** and **MITRE ATT&CK** technique mapping |
| **Responder** | flash | **SOP-grounded containment actions** — every one dry-run, human-approved |
| **Detection Engineer** | flash | **The self-improving loop** — proposes the SPL rule fix that removes the false-positive class |

This is **human-AI collaboration — augmented, not replaced**: the agents
reconstruct the kill chain and stage the decision, the analyst approves every
action, and the brief is a deterministic object an AI/ML or security reviewer can
audit line by line.

## The novel hook: a self-improving detection-engineering loop

The **Detection Engineer** is what no first-party triage agent ships. On the
seeded scenario, the current correlation search over-fires because it counts
distinct admin-share destinations per account and alerts on a flat threshold — it
cannot tell a legitimate backup service account apart from a compromised one. The
Detection Engineer rewrites the rule to **correlate against the EDR attack-tool
signal** (the discriminator that the real compromise carries and the benign
baseline does not), and emits the change as a **unified SPL diff**:

- it **keeps** the admin-share fan-out logic that catches the true positive, and
- it **adds** an `index=edr` correlation that removes the *entire* service-account
  false-positive class.

### …and then it *proves* it (the measured backtest)

A suggested rule change is a claim. Sentinel Brief turns it into a **measured
result**. When running live, a deterministic backtest step replays **both** the
old rule and the proposed new rule over the historical data window and computes,
from real query results (not model prose):

| metric | seeded run |
|---|---|
| `old_alert_count` | **4** (1 real attack + 3 benign service accounts) |
| `new_alert_count` | **1** (the real attack only) |
| `false_positives_eliminated` | **3** — `svc_monitor`, `svc_patch`, `svc_vuln` |
| `true_positive_retained` | **true** — `svc_backup` / `WKS-014` still fires |
| `alert_reduction_pct` | **75%** |

The discriminator is honest and explicit: we make **no claim of an external
ground-truth oracle**. The eliminated accounts are exactly the ones that fan out
across admin shares but carry **no correlated attack-tool EDR signal**
(`suspicious_download` / `remote_exec_tool`) on their origin host — that
correlation is the ground-truth signal the new rule keys on. The number is
computed by a pure function over real Splunk results and surfaced as the typed
`detection_backtest` field on the brief; the OLD-rule query is routed through the
**Splunk MCP Server's `splunk_run_query`** tool. The step is **live-gated and
fail-safe**: in mock mode, or if the queries fail, `detection_backtest` is null
and the brief still renders everything else.

"Agentic operations that make your detections better every time they fire" —
reactive → agentic → **self-improving** → **measurably** self-improving.

## Why it wins (the four judging axes)

- **Technological Implementation** — real `splunklib.ai` depth: a supervisor +
  four subagents with per-agent model tiering (the framework's own context-bloat
  mitigation), local SPL tools and remote MCP tools, and Pydantic
  `output_schema` so the agent run resolves to a typed, auditable object. Not a
  chat wrapper.
- **Design** — the output is **one scannable brief** that reads in 10 seconds:
  verdict banner → timeline → blast radius → approve-gated actions → SPL diff. No
  login, no settings, no dashboard theater.
- **Potential Impact** — it attacks MTTR across **investigation + response +
  tuning**, and the self-improving loop cuts false-positive volume *at the
  source* — a board-level SOC pain that static triage cannot fix.
- **Quality of the Idea** — deliberately the superset Splunk's Agentic SOC does
  *not* ship: cross-signal blast radius + human-approved response + detection
  authoring as part of triage.

---

## Architecture

See **[`ARCHITECTURE.md`](./ARCHITECTURE.md)** for the full diagram (rendered
Mermaid) and data flow. In one line: `demo.py` fires a detection → the supervisor
(`gemini-2.5-pro`) fans out to four subagents over Google Vertex AI → the
Correlator/Responder reach Splunk through local SPL tools (`ctx.service.jobs
.oneshot`, mgmt `:8089`) and remote MCP tools → the supervisor assembles a typed
`IncidentBrief` → `render.py` prints the brief with the SPL diff as the climax.

```
sentinel_brief/
├── demo.py                     # scripted detection -> brief E2E (the <3-min path)
├── requirements.txt            # pinned deps (develop-branch splunk-sdk[google])
└── sentinel_brief/
    ├── agents.py               # F1 — supervisor + 4 subagents on splunklib.ai
    ├── schemas.py              # F2 — the typed IncidentBrief + DetectionBacktest
    ├── render.py               # F2 — one scannable brief view (backtest = climax)
    ├── config.py               # Vertex GoogleModel factory (ADC)
    ├── mock_service.py         # seeded scenario + drop-in MockService
    ├── service_factory.py      # backend selector (live Splunk | mock)
    ├── live_context.py         # builds the detection context from live SPL
    ├── mcp_wiring.py           # remote Splunk MCP Server tool wiring (fail-safe)
    ├── backtest.py             # measured old-vs-new-rule FP-reduction loop
    └── spl_tools.py            # local SPL tools (@registry.tool + ToolContext)
seed_data/                      # auth.csv / edr.csv for the real-Splunk path
tests/                          # 40 offline tests (zero API burn)
```

## What you need

- **Python ≥ 3.13** (verified on **3.14.3**). `splunklib.ai` requires 3.13+.
- A **Google Cloud project with Vertex AI enabled** and **Application Default
  Credentials** (ADC) on the machine. The spine routes the agents through Vertex
  `gemini-2.5-pro` / `gemini-2.5-flash`.
- The Splunk SDK with the `[google]` extra, installed **from the `develop`
  branch** — `splunklib.ai` is not in the PyPI `splunk-sdk` 2.1.1 release:

  ```
  splunk-sdk[google] @ git+https://github.com/splunk/splunk-sdk-python.git@develop
  ```

- A live Splunk instance is **not required to run the demo** — it ships mock-backed
  (see below).

## Setup

```bash
# from the repo root
cd sentinel_brief

# Python 3.14 (3.13+ required by splunklib.ai)
py -3.14 -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip
.venv/Scripts/python -m pip install -r requirements.txt
```

Authenticate to Vertex with ADC (one-time on the machine):

```bash
gcloud auth application-default login
# or point GOOGLE_APPLICATION_CREDENTIALS at a service-account JSON
```

Set your project/location (defaults shown; override for your own project):

```bash
# bash
export GOOGLE_CLOUD_PROJECT=your-gcp-project
export GOOGLE_CLOUD_LOCATION=us-central1
```
```powershell
# PowerShell
$env:GOOGLE_CLOUD_PROJECT = "your-gcp-project"
$env:GOOGLE_CLOUD_LOCATION = "us-central1"
```

## Run the demo (mock-backed — no Splunk needed)

`SENTINEL_BACKEND` defaults to `live` (real Splunk). For the no-Splunk path, set it
to `mock` — the full agent spine still runs (it needs Vertex ADC + a Gemini model),
only the data source is the seeded `MockService` instead of a live instance:

```bash
cd sentinel_brief
# Windows PowerShell:  $env:SENTINEL_BACKEND="mock"; .venv\Scripts\python demo.py
SENTINEL_BACKEND=mock .venv/Scripts/python demo.py
```

You'll see the supervisor fan out to the four subagents and then the rendered
**IncidentBrief**: `TRUE POSITIVE` verdict with confidence, MITRE techniques, the
multi-index timeline, the ranked blast radius (origin host emphasized), the
human-approval action list, and the **SPL detection-fix diff** as the climax.

The seeded scenario: a compromised `svc_backup` service account pivots from
`WKS-014` across five admin$ shares, preceded by a suspicious PowerShell download
and a PsExec remote-exec signal on the origin host.

### Run the offline tests (zero API burn)

```bash
cd sentinel_brief
.venv/Scripts/python -m pytest tests/ -q
```

40 tests cover schema bounds, the brief render (including the SPL-diff gutters and
the no-color/ANSI paths), the Detection-Engineer fix shape (keeps the TP, removes
the FP class), the **backtest metric** (the 4→1 / 75% math, the eliminated-account
logic, TP-lost detection, and the live-gated/fail-safe `run_backtest` contract),
mock-service determinism, and seed-CSV no-drift. They import the package only and
**never call Vertex or Splunk**.

## Swap to a real Splunk instance

The demo runs on `mock_service.MockService`, a drop-in stand-in for a
`splunklib.client.Service` that serves the seeded `auth`/`edr` rows through the
same `jobs.oneshot(...)` API the real service exposes. To run against live data:

1. Ingest the seed data: follow **[`seed_data/README.md`](./seed_data/README.md)**
   to create the `auth` and `edr` indexes and load `auth.csv` / `edr.csv`. These
   CSVs are generated from the *same* scenario constants as the mock, so the live
   brief matches the mock brief with **zero drift**.
2. In `demo.py`, replace `MockService()` with:

   ```python
   from splunklib.client import connect
   service = connect(host="localhost", port=8089, token="<your-splunk-token>")
   ```

**Nothing in `agents.py`, `spl_tools.py`, or `schemas.py` changes** — the local
SPL tools already call `ctx.service.jobs.oneshot(...)`. Once the Splunk MCP Server
App and a token are in place, the Responder's remote MCP tools auto-discover for
live (still human-approved) containment.

## Seeded example scenario

| Index | Rows | Malicious chain | Benign baseline |
|---|---|---|---|
| `auth` | 20 | 5 — `svc_backup` admin$ pivot from `WKS-014` | 15 — incl. **3 legit service accounts that fan out >3 dests** (`svc_monitor`, `svc_patch`, `svc_vuln`) + normal logons |
| `edr` | 6 | 2 — PowerShell download + PsExec | 4 — chrome, robocopy, wuauclt, nessusd (no attack signal) |

The benign rows are not decoration: the three fan-out service accounts
(`svc_monitor`, `svc_patch`, `svc_vuln`) **trip the old flat-threshold rule** —
they are the genuine false-positive class. Each runs real admin tooling (patch
deployment, vuln scanning, log archival) but emits **no attack-tool EDR signal**,
so the EDR-correlated new rule correctly drops all three while still firing on
`svc_backup`. This is what makes the backtest's 75% reduction real rather than
zero. All events are timestamped **2026-05-31**, so search with the time picker on
**All time** (see `seed_data/README.md`).

## Splunk AI capabilities used

- **`splunklib.ai`** (Developer Tools) — supervisor + subagents, local SPL tools
  via `@registry.tool()` + `ToolContext.service`, structured `output_schema`.
- **Splunk MCP Server** — remote tools (`splunk_run_query`, `splunk_get_indexes`,
  `splunk_get_metadata`) allowlisted and auto-discovered, with the encrypted token
  auto-minted by `splunklib.ai`. The **backtest routes its OLD-rule query through
  MCP deterministically**; the Correlator is also wired and prompted to call
  `splunk_run_query` (a captured live run shows it invoked — see `MCP-EVIDENCE.md`),
  though, as with any LLM tool use, that particular call is model-decided, not
  guaranteed every run. Fail-safe: if MCP is unavailable the agent falls back to
  local SPL and the brief is unchanged.
- **Splunk Hosted Models** — documented bonus lane. The spine runs on Vertex, so
  Hosted-Models availability on the Enterprise trial is never load-bearing; the
  `| ai` path is designed and documented rather than required.

## License

MIT — see [`LICENSE`](./LICENSE).
