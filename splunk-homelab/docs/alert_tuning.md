# Alert Tuning Guide

How to reduce false positives and make your detection rules production-quality.  
This is the skill that separates a good SOC analyst from a great one.

---

## Why tuning matters

Raw detection rules generate noise. In a real SOC, an untuned rule that fires 200 times
a day trains analysts to ignore it — and that's when real attacks slip through.
The goal is: **high fidelity, low noise**.

---

## Rule 1 — Brute Force: Tuning the threshold

**Default:** 5 failed logins in 10 minutes from same IP  
**Problem:** Legitimate users mistype passwords. A mobile app with saved bad credentials
can hit this threshold every time it reconnects.

**Tune it — add exclusions:**

```spl
index=windows_events EventCode=4625
| bucket _time span=10m
| stats count AS failed_attempts, values(user) AS targeted_accounts BY src_ip, _time
| where failed_attempts >= 5
| where NOT src_ip IN ("192.168.1.100", "10.0.0.1")   -- exclude known service IPs
| where NOT user IN ("svc_backup", "svc_monitor")      -- exclude service accounts
```

**Tune it — raise threshold for internal IPs:**

```spl
| eval adjusted_threshold = if(match(src_ip, "^192\.168\.|^10\."), 15, 5)
| where failed_attempts >= adjusted_threshold
```

---

## Rule 3 — Off-Hours Logins: Reducing noise

**Problem:** Sysadmins legitimately work late. On-call engineers log in at 3am.

**Tune it — only alert on admin accounts and RDP (logon type 10):**

```spl
index=windows_events EventCode=4624
| eval login_hour = tonumber(strftime(_time,"%H"))
| eval is_off_hours = if(login_hour < 7 OR login_hour >= 22, "YES", "NO")
| where is_off_hours="YES"
| where match(user, "(?i)admin|domain|svc_") OR LogonType="10"   -- only high-value targets
```

**Tune it — add a whitelist for known on-call staff:**

```spl
| where NOT user IN ("oncall_admin", "backup_svc")
```

---

## Rule 4 — Port Scan: Handling legitimate scanners

**Problem:** Your own vulnerability scanner (Rapid7, Nessus) will trigger this rule daily.

**Tune it — exclude authorized scanner IPs:**

```spl
| where NOT src_ip IN ("10.0.0.50", "192.168.1.200")   -- Rapid7 scanner IPs
```

**Better approach — add a "known scanners" lookup table:**

1. Create a CSV file `authorized_scanners.csv`:
   ```
   ip,description
   10.0.0.50,Rapid7 InsightVM
   192.168.1.200,Nessus scanner
   ```
2. Upload to Splunk: Settings → Lookups → Add new
3. Reference in your SPL:
   ```spl
   | lookup authorized_scanners ip AS src_ip OUTPUT description
   | where isnull(description)   -- only alert if NOT in whitelist
   ```

---

## General tuning principles

| Principle | What it means |
|-----------|--------------|
| Whitelist known good | Exclude authorized IPs, service accounts, scheduled tasks |
| Raise thresholds | Start high, lower gradually as you understand your baseline |
| Add context fields | Include `user`, `src_ip`, `hostname` so analysts can triage fast |
| Set severity tiers | CRITICAL/HIGH/MEDIUM — not everything is high severity |
| Review weekly | Check which alerts fire most. Tune the noisy ones first |
| Document changes | Note WHY you raised a threshold — it matters during audits |

---

## Interview answer: "How do you reduce false positives?"

When asked this in a SOC analyst interview, walk through this framework:

1. **Identify the baseline** — what does normal look like for this environment?
2. **Whitelist known good** — authorized scanners, service accounts, scheduled tasks
3. **Adjust thresholds** — differentiate internal vs external, admin vs standard users
4. **Add context** — more fields means faster triage, fewer unnecessary escalations
5. **Review and iterate** — tune weekly for the first month, monthly after that
6. **Track metrics** — false positive rate, mean time to triage, escalations vs confirmed incidents

This shows operational maturity — the interviewer wants to hear that you think about
signal quality, not just alert quantity.
