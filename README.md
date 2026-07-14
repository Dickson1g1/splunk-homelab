
     ███████╗██████╗ ██╗     ██╗   ██╗███╗   ██╗██╗  ██╗
     ██╔════╝██╔══██╗██║     ██║   ██║████╗  ██║██║ ██╔╝
     ███████╗██████╔╝██║     ██║   ██║██╔██╗ ██║█████╔╝
     ╚════██║██╔═══╝ ██║     ██║   ██║██║╚██╗██║██╔═██╗
     ███████║██║     ███████╗╚██████╔╝██║ ╚████║██║  ██╗
     ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
     ███████╗ ██████╗  ██████╗    ██╗      █████╗ ██████╗
     ██╔════╝██╔═══██╗██╔════╝    ██║     ██╔══██╗██╔══██╗
     ███████╗██║   ██║██║         ██║     ███████║██████╔╝
     ╚════██║██║   ██║██║         ██║     ██╔══██║██╔══██╗
     ███████║╚██████╔╝╚██████╗    ███████╗██║  ██║██████╔╝
     ╚══════╝ ╚═════╝  ╚═════╝    ╚══════╝╚═╝  ╚═╝╚═════╝

                    Built by Dickson Boakye | github.com/Dickson1g1
    

A fully functional Security Operations Center (SOC) home lab built on Splunk Free. Ingests Windows event logs and web server logs, runs 5 detection rules mapped to the NIST framework, and visualizes threats on a live security dashboard.

**Built by:** Dickson Boakye  
**Stack:** Splunk Free · Python · Windows Event Logs · Apache/Nginx logs  
**Skills demonstrated:** SIEM configuration · SPL query writing · Alert triage · Threat detection · Dashboard engineering

---

## What this lab detects

| # | Detection | MITRE Tactic | Severity |
|---|-----------|-------------|----------|
| 1 | Brute force login attempts | Credential Access (T1110) | High |
| 2 | Account lockout events | Credential Access (T1110) | High |
| 3 | Off-hours login activity | Initial Access (T1078) | Medium |
| 4 | Port scan detection | Discovery (T1046) | Medium |
| 5 | Privilege escalation attempts | Privilege Escalation (T1078) | Critical |

---

## Architecture

```
[Windows VM / Log Generator]
        |
        | (Windows Event Logs + web logs)
        v
[Splunk Universal Forwarder]
        |
        | (port 9997)
        v
[Splunk Free - Indexer + Search Head]
        |
        +-- Indexes: windows_events, web_logs
        +-- 5 Detection Alerts (saved searches)
        +-- SOC Dashboard (XML)
        +-- Notable Events panel
```

---

## Quick start (30 minutes)

### Step 1 — Install Splunk Free

1. Go to [splunk.com/en_us/download/splunk-enterprise.html](https://www.splunk.com/en_us/download/splunk-enterprise.html)
2. Create a free account and download Splunk Enterprise (free license = 500MB/day, unlimited time)
3. Install:
   - **Windows:** Run the `.msi` installer → accept defaults → set admin password
   - **Linux:** `tar -xzvf splunk*.tgz -C /opt` then `/opt/splunk/bin/splunk start --accept-license`
4. Open browser → `http://localhost:8000` → log in with your admin credentials

### Step 2 — Ingest sample logs

Two options:

**Option A — Use the included log generator (recommended for beginners):**
```bash
cd scripts/
python generate_logs.py
# Generates: ../sample-logs/windows_events.log + ../sample-logs/web_access.log
```

**Option B — Use your own Windows machine logs:**
- Install Splunk Universal Forwarder on your Windows machine
- Point it at `C:\Windows\System32\winevt\Logs\Security.evtx`

### Step 3 — Create indexes in Splunk

In Splunk Web (`http://localhost:8000`):
1. Go to **Settings → Indexes → New Index**
2. Create index: `windows_events`
3. Create index: `web_logs`

### Step 4 — Upload sample logs

1. Go to **Settings → Add Data → Upload**
2. Upload `sample-logs/windows_events.log` → set source type: `WinEventLog:Security` → index: `windows_events`
3. Upload `sample-logs/web_access.log` → set source type: `access_combined` → index: `web_logs`

### Step 5 — Load the detection rules

In Splunk Web, go to **Search & Reporting** and run each SPL query from the `detection-rules/` folder.  
Save each as an **Alert** (Saved Search → Alert) with the recommended schedule.

### Step 6 — Import the dashboard

1. Go to **Dashboards → Create New Dashboard → Classic Dashboard**
2. Click the **Source** button (top right `< >` icon)
3. Paste the full contents of `dashboard/soc_dashboard.xml`
4. Click **Save**

---

## Folder structure

```
splunk-homelab/
├── README.md                    ← you are here
├── detection-rules/
│   ├── 01_brute_force.spl       ← SPL query + alert config
│   ├── 02_account_lockout.spl
│   ├── 03_off_hours_login.spl
│   ├── 04_port_scan.spl
│   └── 05_privilege_escalation.spl
├── dashboard/
│   └── soc_dashboard.xml        ← paste into Splunk dashboard source
├── sample-logs/
│   └── .gitkeep                 ← run generate_logs.py to populate
├── scripts/
│   ├── generate_logs.py         ← creates realistic sample log data
│   └── ingest_check.py          ← verifies logs are indexed correctly
└── docs/
    ├── setup_guide.md           ← detailed setup with screenshots guide
    └── alert_tuning.md          ← how to tune thresholds to reduce false positives
```

---

## Screenshots

> Add screenshots of your running dashboard here after setup.  
> Recommended: dashboard overview, a triggered alert, and the brute force detection panel.

---

## What I learned

- Configured a SIEM from scratch including index creation, sourcetype mapping, and forwarder setup
- Wrote SPL detection logic for 5 real-world attack patterns used in professional SOC environments
- Mapped each detection to NIST IR framework phases (Detect → Respond) and MITRE ATT&CK techniques
- Built a real-time dashboard that mirrors what Tier 1 SOC analysts monitor daily

---

## Resources

- [Splunk Free Download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [SPL Quick Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/QuickReferenceGuide)
- [MITRE ATT&CK Matrix](https://attack.mitre.org/)
- [NIST IR Framework](https://www.nist.gov/cyberframework)
