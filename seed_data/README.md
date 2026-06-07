# Seed data — `auth` + `edr` indexes (Lane A step A3)

Copy-paste-runnable ingest for the **exact** seeded lateral-movement scenario the
Sentinel Brief demo uses. These CSVs are generated **from the same constants** the
mock service uses (`SEED_AUTH_EVENTS` / `SEED_EDR_EVENTS` in
`sentinel_brief/sentinel_brief/mock_service.py`), so the live-Splunk demo matches
the mock demo with **zero scenario drift**.

| File | Rows | Malicious chain | Benign noise |
|---|---|---|---|
| `auth.csv` | 10 | 5 (`svc_backup` admin$ pivot from WKS-014) | 5 (normal logons) |
| `edr.csv`  | 4  | 2 (powershell download + PsExec) | 2 (chrome, robocopy) |

The malicious rows (`scenario=lateral-movement`) ARE the seeded scenario. The
benign rows (`scenario=benign-noise`) only make the index realistic; they do not
touch `svc_backup` / `WKS-014` / `jdoe` and do not change the detection's behaviour.

Regenerate at any time (single source of truth, deterministic):

```
sentinel_brief/.venv/Scripts/python.exe seed_data/generate_seed_csvs.py
```

---

## ⚠️ #1 ingest gotcha — TIME RANGE

All events are timestamped **2026-05-31** (the seeded scenario date). When you
search, set the time picker to **All time** (or a window covering 2026-05-31),
otherwise the rows are outside the default "Last 24 hours" and **you will see zero
results** and think ingest failed. It didn't — widen the time range.

---

## Step 1 — Create the two indexes

### Option A — Splunk Web (UI)
Settings → Indexes → **New Index**. Name: `auth`. Save.
Repeat with Name: `edr`. Save.

### Option B — CLI (headless, faster)
From the Splunk install `bin/` directory (you'll be prompted for admin creds):

```
splunk add index auth
splunk add index edr
```

### Option C — REST (if you only have the management port + a token)
```
curl -k -u admin:<password> https://localhost:8089/services/data/indexes \
  -d name=auth
curl -k -u admin:<password> https://localhost:8089/services/data/indexes \
  -d name=edr
```

---

## Step 2 — Ingest the CSVs

### Option A — Splunk Web "Add Data → Upload"
1. Settings → **Add Data** → **Upload**.
2. Select `seed_data/auth.csv`.
3. Set Source type: **csv** (Splunk auto-detects header + comma delimiter).
4. On the "Input Settings" page set **Index: `auth`**.
   - Timestamp: Splunk reads the `_time` column automatically for the `csv`
     sourcetype. If it doesn't, set Timestamp → Advanced → `TIME_FORMAT` to
     `%Y-%m-%dT%H:%M:%SZ` and `TIMESTAMP_FIELDS = _time`.
5. Review → Submit.
6. Repeat for `seed_data/edr.csv` with **Index: `edr`**.

### Option B — CLI `oneshot` (one command per file)
From the Splunk install `bin/` directory, using **absolute paths**:

```
splunk add oneshot "C:\Users\RenJieLee\Desktop\Personal\splunk-hackathon\seed_data\auth.csv" -index auth -sourcetype csv
splunk add oneshot "C:\Users\RenJieLee\Desktop\Personal\splunk-hackathon\seed_data\edr.csv"  -index edr  -sourcetype csv
```

(You'll be prompted for admin credentials if not already authenticated.)

> If `_time` is not picked up as the event time with the stock `csv` sourcetype,
> add this stanza to `$SPLUNK_HOME/etc/system/local/props.conf` and re-ingest:
> ```
> [csv]
> INDEXED_EXTRACTIONS = csv
> TIMESTAMP_FIELDS = _time
> TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
> KV_MODE = none
> ```

---

## Step 3 — Verify (set time range to **All time** first)

```
index=auth | head 5
index=edr  | head 5
```

Expect 5 auth rows and (≤)5 edr rows. Then confirm the **scenario** is intact:

```
# The malicious lateral-movement chain (should return the 5 svc_backup pivots):
index=auth user=svc_backup action=logon logon_type=3 share="admin$"
| table _time host user src dest share

# The over-firing detection that the Detection Engineer improves
# (svc_backup hits >3 distinct dests → fires):
index=auth action=logon logon_type=3
| stats dc(dest) as distinct_dests by user
| where distinct_dests > 3

# The EDR signal that distinguishes a REAL compromise from the benign baseline:
index=edr signal IN ("suspicious_download","remote_exec_tool")
| table _time host user process cmdline signal
```

If all three return the expected rows, ingest is good →
tell the orchestrator **"auth + edr indexes have data"** to unblock **B5**
(swap `MockService` → real `splunklib.client.connect`) and **spike check 6**.

---

## What this unblocks

- **B5** — the same agents/tools run against real index data instead of the mock
  (no code change to `agents.py` / `spl_tools.py`; only the `Service` source swaps).
- **Spike check 6** — `ctx.service.jobs.oneshot(...)` over real SPL.
- The live demo path renders the **same** IncidentBrief as the mock demo.
