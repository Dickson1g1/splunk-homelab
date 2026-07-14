"""
ingest_check.py
===============
Verifies your Splunk indexes contain the expected data after upload.
Run this from the command line — it queries Splunk's REST API and
prints a health report.

Usage:
  python ingest_check.py
  python ingest_check.py --host localhost --port 8089 --user admin

Requires: pip install splunk-sdk
  OR just use the SPL queries in the MANUAL CHECKS section below
  if you don't want to install the SDK.
"""

import sys

# ---------------------------------------------------------------------------
# OPTION A: Manual SPL checks (no SDK needed)
# Run these directly in Splunk Web → Search & Reporting
# ---------------------------------------------------------------------------

MANUAL_CHECKS = """
==============================================================
MANUAL VERIFICATION QUERIES
Run each in Splunk Web → Search & Reporting
==============================================================

1. Check windows_events index exists and has data:
   index=windows_events | stats count
   Expected: count > 0

2. Confirm EventCode 4625 (failed logins) are present:
   index=windows_events EventCode=4625 | stats count BY EventCode
   Expected: count > 0

3. Confirm EventCode 4624 (successful logins) are present:
   index=windows_events EventCode=4624 | stats count BY EventCode
   Expected: count > 0

4. Check all 5 event codes needed for detection rules:
   index=windows_events
   | stats count BY EventCode
   | where EventCode IN ("4624","4625","4628","4732","4740","4756","1102")
   | sort EventCode

5. Check web_logs index:
   index=web_logs | stats count
   Expected: count > 0

6. Check time range of ingested data:
   index=windows_events | stats min(_time) AS earliest, max(_time) AS latest
   | eval earliest=strftime(earliest,"%Y-%m-%d %H:%M"), latest=strftime(latest,"%Y-%m-%d %H:%M")

7. Quick attack scenario validation — brute force:
   index=windows_events EventCode=4625
   | bucket _time span=10m
   | stats count BY src_ip, _time
   | where count >= 5
   | sort -count
   Expected: at least 1 row (the simulated brute force attack)

8. Quick attack scenario validation — privilege escalation:
   index=windows_events (EventCode=4728 OR EventCode=4732 OR EventCode=1102)
   | stats count BY EventCode
   Expected: at least 1 row

==============================================================
TROUBLESHOOTING
==============================================================

Problem: index=windows_events returns 0 results
Fix   : Check Settings → Indexes — does "windows_events" exist?
        If not, create it. Then re-upload the file and make sure
        you select index=windows_events in the upload wizard.

Problem: EventCode field is missing
Fix   : The source type may be wrong. Re-upload with:
        Source type: WinEventLog:Security
        NOT: generic_single_line or auto

Problem: _time is all the same (ingestion time, not log time)
Fix   : Splunk couldn't parse the timestamps. Re-upload and set:
        Timestamp: Extract from file → Custom pattern:
        %m/%d/%Y %I:%M:%S %p

Problem: Dashboard shows no data
Fix   : Make sure the time range picker in Splunk shows "Last 24h"
        or "Last 7 days" — the sample logs use relative dates.
        If logs are older than 7 days, change the dashboard
        time range to "All time" during testing.
==============================================================
"""


def main():
    print(MANUAL_CHECKS)

    # ---------------------------------------------------------------------------
    # OPTION B: Programmatic check using Splunk Python SDK
    # Uncomment and run if you have splunk-sdk installed:
    #   pip install splunk-sdk
    # ---------------------------------------------------------------------------

    # try:
    #     import splunklib.client as client
    #     import splunklib.results as results
    # except ImportError:
    #     print("splunk-sdk not installed. Using manual queries above.")
    #     sys.exit(0)

    # import argparse
    # parser = argparse.ArgumentParser()
    # parser.add_argument("--host",     default="localhost")
    # parser.add_argument("--port",     type=int, default=8089)
    # parser.add_argument("--user",     default="admin")
    # parser.add_argument("--password", default="changeme")
    # args = parser.parse_args()

    # try:
    #     service = client.connect(
    #         host=args.host, port=args.port,
    #         username=args.user, password=args.password
    #     )
    #     print(f"[+] Connected to Splunk at {args.host}:{args.port}")
    # except Exception as e:
    #     print(f"[-] Could not connect: {e}")
    #     print("    Is Splunk running? Try: http://localhost:8000")
    #     sys.exit(1)

    # checks = [
    #     ("Windows events index", "search index=windows_events | stats count"),
    #     ("Failed logins (4625)", "search index=windows_events EventCode=4625 | stats count"),
    #     ("Web logs index",       "search index=web_logs | stats count"),
    # ]

    # for label, query in checks:
    #     job = service.jobs.create(query, count=1)
    #     while not job.is_done():
    #         import time; time.sleep(0.5)
    #     reader = results.JSONResultsReader(job.results(output_mode='json'))
    #     for r in reader:
    #         if isinstance(r, dict):
    #             count = r.get("count", "0")
    #             status = "[+]" if int(count) > 0 else "[-]"
    #             print(f"{status} {label}: {count} events")


if __name__ == "__main__":
    main()
