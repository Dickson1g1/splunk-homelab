"""
generate_logs.py
================
Generates realistic Windows Security Event logs and Apache web access logs
for the Splunk SOC Home Lab.

Simulates real attack scenarios:
  - Brute force attempts (EventCode 4625)
  - Account lockouts (EventCode 4740)
  - Successful logins including off-hours (EventCode 4624)
  - Privilege escalation / group changes (EventCode 4728, 4732)
  - Log clearing event (EventCode 1102)
  - Port scan traffic in web logs
  - Normal background traffic

Usage:
  python generate_logs.py
  python generate_logs.py --days 7 --events 5000

Output:
  ../sample-logs/windows_events.log
  ../sample-logs/web_access.log
"""

import argparse
import os
import random
import sys
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

USERNAMES = [
    "jsmith", "adavis", "mwilson", "rlee", "kthomas",
    "admin", "svc_backup", "svc_sql", "SYSTEM", "administrator"
]

HOSTNAMES = [
    "DESKTOP-A1B2C3", "WORKSTATION-04", "SRV-DC01",
    "LAPTOP-HR01", "SRV-FILE01", "WORKSTATION-09"
]

INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.22", "192.168.1.45",
    "192.168.1.100", "10.0.0.5", "10.0.0.18"
]

ATTACKER_IPS = [
    "185.220.101.45",   # Known Tor exit node range
    "194.165.16.72",
    "45.33.32.156",
    "104.21.67.23",
    "198.199.125.140"
]

GROUPS = [
    "Administrators", "Domain Admins", "Backup Operators",
    "Remote Desktop Users", "Account Operators"
]

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    7: "Unlock",
    10: "RemoteInteractive",
    11: "CachedInteractive"
}

WEB_PATHS_NORMAL = [
    "/", "/index.html", "/about", "/contact", "/products",
    "/api/v1/status", "/static/main.css", "/static/app.js",
    "/favicon.ico", "/robots.txt", "/sitemap.xml"
]

WEB_PATHS_SUSPICIOUS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env",
    "/config.php", "/backup.zip", "/../../../etc/passwd",
    "/shell.php", "/cmd.php", "/.git/config",
    "/api/v1/admin/users", "/wp-login.php"
]

WEB_USER_AGENTS_NORMAL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)',
]

WEB_USER_AGENTS_SUSPICIOUS = [
    'sqlmap/1.7.2',
    'Nikto/2.1.6',
    'nmap scripting engine',
    'python-requests/2.28.0',
    'curl/7.85.0',
    '-'
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rand_time(base: datetime, jitter_minutes: int = 60) -> datetime:
    return base + timedelta(minutes=random.randint(0, jitter_minutes))


def fmt_win_time(dt: datetime) -> str:
    return dt.strftime("%m/%d/%Y %I:%M:%S %p")


def fmt_clf_time(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


# ---------------------------------------------------------------------------
# Windows Event Log generators
# ---------------------------------------------------------------------------

def event_4624(dt: datetime, user: str, src_ip: str, logon_type: int = 3) -> str:
    """Successful logon."""
    return (
        f"{fmt_win_time(dt)} EventCode=4624 "
        f"user={user} src_ip={src_ip} "
        f"ComputerName={random.choice(HOSTNAMES)} "
        f"LogonType={logon_type} "
        f"LogonTypeName={LOGON_TYPES.get(logon_type,'Unknown')} "
        f"Message=An account was successfully logged on."
    )


def event_4625(dt: datetime, user: str, src_ip: str) -> str:
    """Failed logon."""
    return (
        f"{fmt_win_time(dt)} EventCode=4625 "
        f"user={user} src_ip={src_ip} "
        f"ComputerName={random.choice(HOSTNAMES)} "
        f"FailureReason=Unknown user name or bad password "
        f"Message=An account failed to log on."
    )


def event_4740(dt: datetime, user: str, src_ip: str) -> str:
    """Account locked out."""
    return (
        f"{fmt_win_time(dt)} EventCode=4740 "
        f"user={user} src_ip={src_ip} "
        f"ComputerName={random.choice(HOSTNAMES)} "
        f"Message=A user account was locked out."
    )


def event_4728(dt: datetime, actor: str, target_user: str, group: str) -> str:
    """User added to security-enabled global group."""
    return (
        f"{fmt_win_time(dt)} EventCode=4728 "
        f"user={actor} src_user={target_user} "
        f"group_name={group} "
        f"ComputerName=SRV-DC01 "
        f"Message=A member was added to a security-enabled global group."
    )


def event_1102(dt: datetime, actor: str) -> str:
    """Audit log cleared — critical red flag."""
    return (
        f"{fmt_win_time(dt)} EventCode=1102 "
        f"user={actor} "
        f"ComputerName=SRV-DC01 "
        f"Message=The audit log was cleared."
    )


def web_log(dt: datetime, client_ip: str, method: str,
            path: str, status: int, size: int, ua: str) -> str:
    """Apache Combined Log Format."""
    return (
        f'{client_ip} - - [{fmt_clf_time(dt)}] '
        f'"{method} {path} HTTP/1.1" '
        f'{status} {size} "-" "{ua}"'
    )


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------

def scenario_brute_force(base: datetime, lines: list) -> None:
    """Attacker tries 30+ passwords against one account in 10 min."""
    attacker = random.choice(ATTACKER_IPS)
    target   = random.choice(["admin", "administrator", "jsmith"])
    for i in range(random.randint(25, 50)):
        t = base + timedelta(seconds=i * 12)
        lines.append(event_4625(t, target, attacker))
    # After brute force, one successful login (compromise)
    if random.random() < 0.3:
        lines.append(event_4624(base + timedelta(minutes=11), target, attacker, logon_type=10))
    # Then lockout
    lines.append(event_4740(base + timedelta(minutes=12), target, attacker))


def scenario_off_hours_rdp(base: datetime, lines: list) -> None:
    """Admin logs in via RDP at 2am on a Saturday."""
    t = base.replace(hour=2, minute=random.randint(0, 59))
    # Push to Saturday if not already weekend
    days_until_sat = (5 - t.weekday()) % 7
    t = t + timedelta(days=days_until_sat)
    user = random.choice(["admin", "administrator"])
    src  = random.choice(ATTACKER_IPS)
    lines.append(event_4624(t, user, src, logon_type=10))


def scenario_privilege_escalation(base: datetime, lines: list) -> None:
    """Attacker adds a new account to Domain Admins."""
    actor  = random.choice(["admin", "SYSTEM"])
    target = f"hacker_{random.randint(100,999)}"
    group  = "Domain Admins"
    lines.append(event_4728(base, actor, target, group))
    # Optionally clear the log 5 minutes later to cover tracks
    if random.random() < 0.4:
        lines.append(event_1102(base + timedelta(minutes=5), actor))


def scenario_normal_traffic(base: datetime, lines: list, count: int = 50) -> None:
    """Simulate routine logins and logoffs throughout the day."""
    for _ in range(count):
        t    = rand_time(base, jitter_minutes=480)
        user = random.choice(USERNAMES[:6])   # non-admin users
        ip   = random.choice(INTERNAL_IPS)
        lt   = random.choice([2, 3, 7])
        lines.append(event_4624(t, user, ip, logon_type=lt))
        # Occasional failed login (mistyped password)
        if random.random() < 0.1:
            lines.append(event_4625(t + timedelta(seconds=5), user, ip))


def scenario_web_port_scan(base: datetime, lines: list) -> None:
    """Attacker scans many paths looking for admin panels."""
    attacker = random.choice(ATTACKER_IPS)
    ua       = random.choice(WEB_USER_AGENTS_SUSPICIOUS)
    for path in WEB_PATHS_SUSPICIOUS:
        t = base + timedelta(seconds=random.randint(0, 30))
        lines.append(web_log(t, attacker, "GET", path, 404, 0, ua))
    # Also hit normal paths to blend in
    for _ in range(5):
        t    = base + timedelta(seconds=random.randint(31, 120))
        path = random.choice(WEB_PATHS_NORMAL)
        lines.append(web_log(t, attacker, "GET", path, 200, random.randint(500, 8000), ua))


def scenario_normal_web(base: datetime, lines: list, count: int = 100) -> None:
    """Routine web traffic."""
    for _ in range(count):
        t      = rand_time(base, jitter_minutes=480)
        client = random.choice(INTERNAL_IPS + ["203.0.113." + str(random.randint(1,254))])
        path   = random.choice(WEB_PATHS_NORMAL)
        status = random.choices([200, 301, 304, 404], weights=[70, 10, 15, 5])[0]
        size   = random.randint(200, 15000)
        ua     = random.choice(WEB_USER_AGENTS_NORMAL)
        method = random.choices(["GET", "POST"], weights=[85, 15])[0]
        lines.append(web_log(t, client, method, path, status, size, ua))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate Splunk home lab sample logs")
    parser.add_argument("--days",   type=int, default=3,    help="Days of history to generate (default: 3)")
    parser.add_argument("--events", type=int, default=2000, help="Approx total Windows events (default: 2000)")
    args = parser.parse_args()

    out_dir = os.path.join(os.path.dirname(__file__), "..", "sample-logs")
    os.makedirs(out_dir, exist_ok=True)

    win_path = os.path.join(out_dir, "windows_events.log")
    web_path = os.path.join(out_dir, "web_access.log")

    win_lines = []
    web_lines = []

    now  = datetime.now()
    base = now - timedelta(days=args.days)

    print(f"[*] Generating {args.days} days of log data...")
    print(f"[*] Time range: {base.strftime('%Y-%m-%d')} → {now.strftime('%Y-%m-%d')}")

    # Generate one full day at a time
    for day_offset in range(args.days):
        day_base = base + timedelta(days=day_offset)

        # Normal background traffic (bulk of events)
        normal_count = args.events // args.days
        scenario_normal_traffic(day_base, win_lines, count=normal_count)
        scenario_normal_web(day_base, web_lines, count=normal_count // 2)

        # Attack scenarios (1–3 per day, randomised)
        num_attacks = random.randint(1, 3)
        for _ in range(num_attacks):
            attack_time = rand_time(day_base, jitter_minutes=1380)
            choice = random.choice([
                scenario_brute_force,
                scenario_off_hours_rdp,
                scenario_privilege_escalation,
                scenario_web_port_scan,
            ])
            if choice == scenario_web_port_scan:
                choice(attack_time, web_lines)
            else:
                choice(attack_time, win_lines)

    # Sort both log files chronologically
    win_lines.sort()
    web_lines.sort()

    with open(win_path, "w") as f:
        f.write("\n".join(win_lines) + "\n")

    with open(web_path, "w") as f:
        f.write("\n".join(web_lines) + "\n")

    print(f"\n[+] Windows events : {len(win_lines):,} lines → {win_path}")
    print(f"[+] Web access logs: {len(web_lines):,} lines → {web_path}")
    print("\n[*] Next steps:")
    print("    1. Open Splunk → Settings → Add Data → Upload")
    print(f"    2. Upload: {win_path}")
    print("       Source type: WinEventLog:Security | Index: windows_events")
    print(f"    3. Upload: {web_path}")
    print("       Source type: access_combined | Index: web_logs")
    print("    4. Load detection rules from detection-rules/ folder")
    print("    5. Import dashboard/soc_dashboard.xml")


if __name__ == "__main__":
    main()
