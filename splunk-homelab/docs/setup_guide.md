# Detailed Setup Guide

Step-by-step instructions to get your Splunk SOC home lab running from zero.  
**Estimated time: 30–45 minutes**

---

## Prerequisites

- Computer with 4GB+ RAM free (Splunk uses ~1GB)
- Admin rights on your machine
- Free Splunk account (sign up at splunk.com — no credit card required)
- Python 3.8+ (for the log generator)

---

## Part 1 — Install Splunk Free (15 min)

### Windows

1. Go to: https://www.splunk.com/en_us/download/splunk-enterprise.html
2. Select **Windows** → download the `.msi` file (~450MB)
3. Run the installer as Administrator
4. Accept the license → keep default install path (`C:\Program Files\Splunk`)
5. Set a password for the `admin` account — **write this down**
6. Click **Finish** — Splunk starts automatically
7. Open browser → `http://localhost:8000`
8. Log in with `admin` / [your password]

### Linux (Ubuntu/Debian)

```bash
# Download
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-linux-2.6-x86_64.tgz'

# Install
sudo tar -xzvf splunk.tgz -C /opt

# Start Splunk and accept license
sudo /opt/splunk/bin/splunk start --accept-license

# Enable on boot
sudo /opt/splunk/bin/splunk enable boot-start

# Access via browser
# http://localhost:8000
```

### Mac

```bash
# Download the .dmg from splunk.com
# Drag to Applications
# Open Splunk from Applications
# Or run: /Applications/Splunk/bin/splunk start
```

---

## Part 2 — Generate Sample Logs (5 min)

```bash
cd scripts/
python generate_logs.py
```

Output:
```
[*] Generating 3 days of log data...
[+] Windows events : 2,847 lines → ../sample-logs/windows_events.log
[+] Web access logs: 1,203 lines → ../sample-logs/web_access.log
```

Want more data?
```bash
python generate_logs.py --days 7 --events 10000
```

---

## Part 3 — Create Indexes in Splunk (3 min)

1. In Splunk Web: **Settings** (top nav) → **Indexes**
2. Click **New Index** (top right)
3. Create first index:
   - Index Name: `windows_events`
   - Max Size: 500 MB (leave default)
   - Click **Save**
4. Create second index:
   - Index Name: `web_logs`
   - Click **Save**

---

## Part 4 — Upload Logs (5 min)

### Upload Windows events

1. **Settings** → **Add Data** → **Upload**
2. Click **Select File** → choose `sample-logs/windows_events.log`
3. Click **Next**
4. Source type: type `WinEventLog:Security` in the box and select it
   - If not found, select **Structured** → **Log4j** → then manually type `WinEventLog:Security`
5. Click **Next**
6. Index: select `windows_events` (the one you just created)
7. Click **Review** → **Submit**
8. Click **Start Searching** to verify

Verify it worked:
```spl
index=windows_events | stats count BY EventCode | sort -count
```
You should see EventCodes 4624, 4625, 4740, 4728, 1102 in the results.

### Upload web logs

1. **Settings** → **Add Data** → **Upload**
2. Select `sample-logs/web_access.log`
3. Source type: `access_combined`
4. Index: `web_logs`
5. Submit

Verify:
```spl
index=web_logs | stats count BY status
```
You should see 200, 301, 404 status codes.

---

## Part 5 — Load Detection Rules (5 min)

For each file in `detection-rules/`:

1. Open the `.spl` file in a text editor
2. Copy everything between the first `--` block and the `HOW TO SAVE` comment
3. Paste into **Search & Reporting** in Splunk
4. Click the **magnifying glass** to run it
5. If results appear: click **Save As** → **Alert**
6. Configure the alert (settings are in the comment at the bottom of each file)
7. Repeat for all 5 rules

**Quick test** — run each base query first:

```spl
index=windows_events EventCode=4625 | stats count
index=windows_events EventCode=4740 | stats count
index=windows_events EventCode=4624 | stats count
index=windows_events (EventCode=4728 OR EventCode=1102) | stats count
```

All should return `count > 0`.

---

## Part 6 — Import the Dashboard (3 min)

1. In Splunk Web: **Apps** → **Search & Reporting** → **Dashboards**
2. Click **Create New Dashboard**
3. Title: `SOC Security Monitoring Dashboard`
4. Click **Classic Dashboard** → **Create**
5. In the editor that opens, click the **`< >`** (Source) button in the top right
6. **Select all** text in the editor and **delete** it
7. Open `dashboard/soc_dashboard.xml` from this repo
8. **Copy all** the XML content
9. **Paste** it into the Splunk dashboard source editor
10. Click **Save** → **Back**

Your dashboard is now live. Set the time range picker to **Last 7 days** to see all your sample data.

---

## Part 7 — Verify Everything Works

Run this final check:
```spl
index=windows_events
| stats count BY EventCode
| eval event_name=case(
    EventCode="4624","Successful Logon",
    EventCode="4625","Failed Logon",
    EventCode="4740","Account Lockout",
    EventCode="4728","Group Membership Change",
    EventCode="1102","Log Cleared",
    true(), "Other"
  )
| table EventCode, event_name, count
| sort -count
```

Expected output should include all 5 event types.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard shows no data | Change time picker to "Last 7 days" or "All time" |
| EventCode field missing | Re-upload with source type `WinEventLog:Security` (not auto) |
| Port 8000 not accessible | Check Windows Firewall or run `splunk status` |
| Timestamp wrong (all same time) | Re-upload, set timestamp extraction manually |
| Detection rules return 0 results | Run base queries first to confirm data exists |

---

## Next steps after setup

1. Add screenshots of your running dashboard to the README
2. Try modifying the detection thresholds (e.g., lower brute force from 5 to 3 attempts)
3. Write a 6th detection rule for something new (try: multiple failed logins across multiple usernames from one IP)
4. Connect this to the MITRE ATT&CK mapper project
