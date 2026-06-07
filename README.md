# Sentinel Brief

**A multi-agent Detection-to-Decision war room for the SOC, built on Splunk
`splunklib.ai`.** When a detection fires, Sentinel Brief turns it into one typed,
auditable incident brief — verdict, MITRE ATT&CK mapping, attack timeline, blast
radius, human-approved containment, and **the SPL rule fix that stops the alert
from over-firing next time** — in under three minutes.

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

"Agentic operations that make your detections better every time they fire" —
reactive → agentic → **self-improving**.

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
    ├── schemas.py              # F2 — the typed IncidentBrief (Pydantic)
    ├── render.py               # F2 — one scannable brief view
    ├── config.py               # Vertex GoogleModel factory (ADC)
    ├── mock_service.py         # seeded scenario + drop-in MockService
    └── spl_tools.py            # local SPL tools (@registry.tool + ToolContext)
seed_data/                      # auth.csv / edr.csv for the real-Splunk path
tests/                          # 24 offline tests (zero API burn)
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

```bash
cd sentinel_brief
.venv/Scripts/python demo.py
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

24 tests cover schema bounds, the brief render (including the SPL-diff gutters and
the no-color/ANSI paths), the Detection-Engineer fix shape (keeps the TP, removes
the FP class), mock-service determinism, and seed-CSV no-drift. They import the
package only and **never call Vertex**.

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
| `auth` | 10 | 5 — `svc_backup` admin$ pivot from `WKS-014` | 5 — normal logons, incl. a benign `svc_monitor` |
| `edr` | 4 | 2 — PowerShell download + PsExec | 2 — chrome, robocopy |

The benign rows make the index realistic and intentionally include a *legitimate*
service account (`svc_monitor`) so the detection fix has a real false-positive
class to remove. All events are timestamped **2026-05-31**, so search with the
time picker on **All time** (see `seed_data/README.md`).

## Splunk AI capabilities used

- **`splunklib.ai`** (Developer Tools) — supervisor + subagents, local SPL tools
  via `@registry.tool()` + `ToolContext.service`, structured `output_schema`.
- **Splunk MCP Server** — remote tools, allowlisted and auto-discovered (token
  auth), on the Correlator and Responder paths.
- **Splunk Hosted Models** — documented bonus lane. The spine runs on Vertex, so
  Hosted-Models availability on the Enterprise trial is never load-bearing; the
  `| ai` path is designed and documented rather than required.

## License

MIT — see [`LICENSE`](./LICENSE).
