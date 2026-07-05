# Purple Loop — Startup Guide

## Architecture

```
┌─────────────────────────────────┐
│ threat-intel-arbiter            │  ingests CISA KEV + MISP → scores SSVC
│ (separate repo)                 │  exports priority-ordered plan
└──────────────┬──────────────────┘
               │ arbiter-live.json
               ▼
┌──────────────────────────────────┐
│ Purple Loop                      │
│ ┌──────┐ ┌──────┐ ┌──────┐      │
│ │ Feed │→│Exec  │→│Collect│      │  go run ./cmd/purpleloop run
│ └──────┘ └──────┘ └──────┘      │
│               ↓                  │
│ ┌──────┐ ┌──────┐               │
│ │Eval  │→│Report│               │
│ └──────┘ └──────┘               │
└──────────────┬───────────────────┘
               │ docker exec / SSH
               ▼
┌──────────────────────────────────┐
│ Wazuh 4.9.2 SIEM                 │
│ ┌────────┐ ┌────────┐           │
│ │Manager │ │Indexer │           │  Docker Compose (purpleloop-lab)
│ └────────┘ └────────┘           │
│ ┌──────────────┐                │
│ │Dashboard :443│                │
│ └──────────────┘                │
│                                  │
│ Agent 001: victim01 (Docker)     │
│ Agent 002: windows-vm (VMware)   │
└──────────────────────────────────┘
```

## 1. First-Time Setup

```bash
git clone https://github.com/jayelbotvibe-web/purple-loop.git
cd purple-loop
```

### 1.1 Host Prep (one-time)
```bash
# Wazuh indexer requires elevated mmap count
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-purpleloop.conf
```

### 1.2 Build
```bash
make build && make vet
go test ./internal/...  # all must PASS
```

## 2. Starting the Lab

### 2.1 Automated
```bash
bash scripts/startup.sh
```
This runs: host prep → `make lab-up` → `make verify` → `make canary`

### 2.2 Manual (step by step)
```bash
make lab-up                     # start Wazuh + Linux victim (~30s)
make verify                     # indexer health + API auth + agents enrolled
make canary                     # pipeline positive control — must say DETECTED
```

**Expected output:**
```
Canary marker: purpleloop-canary-a1b2c3d4
Canary: DETECTED on windows (evidence: 4 events)
```

If the canary fails: check WazuhSvc and Sysmon64 are running on Windows VM, and that
the Wazuh agent is connected (agent_control -l shows agent 002 Active).

## 3. Windows VM

### 3.1 Starting
1. Power on the VM in VMware
2. Confirm bridged IP: run `ipconfig` on the VM → should be `192.168.88.13`
3. Test SSH: `ssh windows-vm@192.168.88.13 hostname`
4. Confirm services:
   ```powershell
   Get-Service WazuhSvc, Sysmon64 | Format-Table Name, Status
   ```

### 3.2 First-Time Windows Setup
If re-provisioning the VM:
1. Copy `lab/windows/provision.ps1` to the VM
2. Run as Admin: `powershell -ExecutionPolicy Bypass -File provision.ps1`
3. Enable SSH key auth (see lab/README.md)

## 4. Connecting the Arbiter

The threat-intel-arbiter is a separate repo. To generate a priority-ordered export:

```bash
# Query the arbiter database and export the top 10 alerts
```

**What this does:**
1. Queries the arbiter's SQLite database (1,147 alerts from CISA KEV + MISP)
2. Extracts CVEs and SSVC actions from alert explanations
3. Exports the top 10 as JSON to `testdata/arbiter-live.json`
4. Purple Loop reads this file via `--arbiter`

**Manual alternative:**
```bash
python3 << 'EOF'
import sqlite3, json, re
db = sqlite3.connect('/home/niel/projects/threat-intel-arbiter/data/arbiter.db')
rows = db.execute("SELECT id, severity, explanation, matched_apps FROM alerts WHERE explanation LIKE '%Action:%' ORDER BY created_at DESC LIMIT 10").fetchall()
alerts = []
for r in rows:
    cves = re.findall(r'CVE-\d{4}-\d{4,}', r[2] or '')
    alerts.append({"id":r[0],"action":"Track","severity":r[1] or "medium",
      "matched_apps":json.loads(r[3]) if r[3] else [],"cves":cves,"techniques":["T1059"]})
with open('testdata/arbiter-live.json','w') as f: json.dump({"alerts":alerts},f,indent=2)
print(f"Exported {len(alerts)} alerts")
EOF
```

## 5. Running Campaigns

### 5.1 Discovery Plan (10 techniques)
```bash
go run ./cmd/purpleloop run \
  --plan plans/discovery.yml \
  --victim-container purpleloop-victim \
  --manager-container single-node-wazuh.manager-1 \
  --output reports/coverage.html
```

### 5.2 Arbiter-Prioritized Campaign
```bash
go run ./cmd/purpleloop run \
  --arbiter testdata/arbiter-live.json \
  --victim-container purpleloop-victim \
  --manager-container single-node-wazuh.manager-1 \
  --output reports/arbiter-coverage.html
```

### 5.3 Single Technique
```bash
go run ./cmd/purpleloop run \
  --technique T1059.004 \
  --victim-container purpleloop-victim \
  --manager-container single-node-wazuh.manager-1
```

### 5.4 Dry-Run (no lab required)
```bash
go run ./cmd/purpleloop run --technique T1059.004 --dry-run
# Expected: verdict=DETECTED, rule_matched=proc_creation_susp_shell.yml
```

### 5.5 Emulation Plans
```bash
go run ./cmd/purpleloop run --emulation emulation/discovery-chain.yml --dry-run
go run ./cmd/purpleloop run --emulation emulation/apt29-subset.yml --dry-run
```

## 6. Verifying Results

### 6.1 Check Coverage Report
Open `reports/coverage.html` in a browser. Shows per-technique verdicts, events collected,
rule matched, and CVE priority.

### 6.2 Check Wazuh Events
```bash
# View raw Sysmon events from Windows
docker exec single-node-wazuh.manager-1 \
  grep "Microsoft-Windows-Sysmon" /var/ossec/logs/archives/archives.json | tail -1

# Count events per agent
docker exec single-node-wazuh.manager-1 \
  grep -c '"001"' /var/ossec/logs/archives/archives.json  # Linux
docker exec single-node-wazuh.manager-1 \
  grep -c '"002"' /var/ossec/logs/archives/archives.json  # Windows
```

### 6.3 Agent Status
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

## 7. Shutdown

```bash
make lab-down           # stop Docker containers (data preserved)
make no-boot            # stop + reminder to disable Docker auto-start
```
On Windows VM: shut down normally via VMware.

**Note on RAM:** The Wazuh indexer (OpenSearch, a Java process) uses ~4 GB RAM (`-Xms4g -Xmx4g`). If
you're on a 16 GB machine, this may be tight with the Windows VM running. The containers do NOT
auto-start at boot unless `restart: always` is set in docker-compose.yml and Docker itself starts
at boot. To prevent boot auto-start: `sudo systemctl disable docker`.

## 8. Troubleshooting

| Symptom | Check |
|---------|-------|
| Canary fails | `ssh windows-vm@192.168.88.13 "sc query WazuhSvc Sysmon64"` |
| Agent not Active | `docker logs single-node-wazuh.manager-1 \| grep -i "auth\|enroll" \| tail -5` |
| No Sysmon events | `ssh windows-vm@192.168.88.13 "wevtutil qe Microsoft-Windows-Sysmon/Operational /c:2"` |
| Dashboard 502 | `docker logs single-node-wazuh.indexer-1 \| tail -5` |
| Build fails | `go mod tidy && make build` |
| Port conflicts | `docker ps --format '{{.Names}} {{.Ports}}'` |
| vm.max_map_count reset | `sysctl vm.max_map_count` (must be ≥262144) |

## 9. Quick Reference

```bash
make lab-up       # start lab
make verify       # health check
make canary       # pipeline control
make lab-down     # stop lab
make build        # compile
make test         # run tests
```
