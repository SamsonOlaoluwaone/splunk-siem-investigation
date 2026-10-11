# Security Incident Report: SSH Brute Force and Account Compromise

**Report ID:** IR-2026-001
**Classification:** Internal Use
**Prepared by:** [Your Name], SOC Analyst
**Date Prepared:** October 11, 2026
**Environment:** Linux Server (`linux_server`), SSH Authentication Logs
**SIEM Platform:** Splunk Enterprise (Free license tier)
**Data Source:** `index=test sourcetype=linux_secure`

---

## 1. Executive Summary

This report documents a security investigation conducted on SSH authentication logs covering a 30-day period. The investigation identified two distinct security events:

1. A large-scale, automated brute-force campaign against SSH login that **did not succeed**.
2. A separate, successful unauthorized login to a privileged account (`admin`) from an external IP address, followed by privilege escalation to `root` within 34 seconds, assessed as a **high-confidence account compromise**.

A second successful login to the same `admin` account from a different external IP occurred eight days later, with no observed follow-on escalation in the available data.

Four working detection rules were developed and tested against this dataset (persistent brute force, failed-then-success correlation, sudo-to-root baseline, and rare escalation). A fifth, password spraying, was tested and rejected because it could not be distinguished from ordinary brute force in this data.

**Overall severity: High**, due to confirmed privileged account compromise and successful privilege escalation to root.

---

## 2. Scope and Methodology

**Scope:** SSH authentication events (`linux_secure` sourcetype) for a single Linux host, covering all available log history (timestamped May 31 to June 30, 2026).

**Methodology:**
- Parsed raw authentication log lines using Splunk `rex` field extraction to isolate source IP, username, and outcome (success or failure).
- Identified anomalous source IPs by aggregate failed-login volume.
- Cross-referenced suspected attacker IPs against the full list of successful logins to determine whether any brute-force source ultimately succeeded.
- Investigated low-frequency successful logins from external IP ranges, comparing them against the baseline behavior of known internal users.
- Correlated login events with subsequent privilege escalation (`sudo`) events by user and by time.
- Established a legitimate-use baseline (escalation frequency per user) to distinguish routine administrative activity from anomalous one-off escalation events.
- Tuned detection thresholds by measuring how many source IPs each candidate threshold would flag.

---

## 3. Timeline of Findings

| Time (local) | Event | Source IP | User | Assessment |
|---|---|---|---|---|
| Ongoing (multiple dates) | 1,557 failed SSH login attempts across 148 distinct usernames | `87.194.216.51` | root, admin, administrator, mysql, system, etc. | Automated brute-force / dictionary attack, **unsuccessful** |
| 2026-06-22 11:47:43 | Successful SSH login, no failed attempts from this IP | `73.202.92.7` | `admin` | **Unauthorized access, high confidence** |
| 2026-06-22 11:48:17 | Privilege escalation via `sudo` to `root` (`/bin/su`), 34 seconds after login | n/a | `admin` | **Privilege escalation following compromise** |
| 2026-06-29 18:41:10 | Successful SSH login from the same IP, different username | `73.202.92.7` | `allurbase` | Related to the same source; warrants further review |
| 2026-06-30 15:05:16 | Successful SSH login, no failed attempts from this IP | `212.114.31.255` | `admin` | **Second unauthorized access event**; no escalation observed afterward |

---

## 4. Detailed Analysis

### 4.1 Brute-Force Campaign (Unsuccessful)

The source IP `87.194.216.51` generated 1,557 failed login attempts against 148 distinct usernames, heavily weighted toward high-privilege and service accounts (`root`: 251 attempts, `administrator`: 45, `admin`: 44, `mysql`: 28, `system`: 27). This volume and username diversity is inconsistent with human error and consistent with automated dictionary-attack tooling.

A search for this IP among all successful logins returned **zero matches**. A broader check confirmed that no IP in the dataset has both more than 5 failed logins and a successful login. The brute-force campaigns did not result in any successful authentication.

Note that this IP is not the fastest attacker. Its busiest 5-minute window held 25 failures, while another IP reached 32. What distinguishes it is persistence: it exceeded 10 failures in 60 separate 5-minute windows, against 37 for the next IP.

### 4.2 Account Compromise via `admin`

Unlike the brute-force source, the `admin` account was accessed from `73.202.92.7` with **no failed login attempts from that IP**, a first-attempt success. This is inconsistent with password guessing and more consistent with a valid credential obtained outside the observed brute-force activity (credential reuse, a leaked or purchased password, or a prior undetected compromise). The same holds for the second login from `212.114.31.255`. This check is per source IP; it does not exclude failed attempts made from other IPs.

Baseline comparison supports this conclusion. Legitimate internal users (`djohnson`: 2,352 logins, `nsharpe`: 1,147, `myuan`: 409) authenticate from fixed internal IP addresses (`10.x.x.x` range), with routine `sudo` usage (412, 203, and 72 escalation events respectively). The `admin` account has **no history of internal use** and recorded exactly two successful logins in the entire dataset, both from external public IP addresses.

### 4.3 Privilege Escalation

Thirty-four seconds after the `73.202.92.7` login, the session executed `sudo` to `/bin/su`, escalating to `root`. This was the account's **only** recorded escalation event, compared with hundreds from routine users. The short interval between login and escalation, together with the account's lack of legitimate-use history, indicates deliberate privilege escalation rather than routine administrative work.

### 4.4 Second Access Event

A second successful login to `admin` occurred eight days later from a different external IP (`212.114.31.255`). No corresponding escalation was found in the available log window. This may be the same actor returning, credential reuse by a second party, or an incomplete session. It is flagged for continued monitoring rather than confirmed escalation.

---

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Observed Activity |
|---|---|---|
| T1110 | Brute Force | 1,557 failed login attempts from `87.194.216.51` |
| T1078 | Valid Accounts | First-attempt successful logins to `admin` from external IPs |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | `/bin/su` escalation to root, 34 seconds after login |

Password spraying (T1110.003) is not listed. It was tested and could not be distinguished from the brute-force activity above (see section 6).

---

## 6. Detection Rules

| # | Rule | Logic | Result on this dataset |
|---|---|---|---|
| 1 | SSH brute force (persistence) | At least 20 five-minute windows with more than 10 failed logins from one IP | Flags 5 of 184 IPs; `87.194.216.51` first with 60 windows |
| 2 | Password spraying | More than 5 usernames, under 3 attempts per username, in 10 minutes | **Tested, not adopted.** Flagged 182 of 184 IPs |
| 3 | Failed-then-success | More than 5 failures and at least 1 success from one IP | No results (expected: no brute-forcing IP succeeded) |
| 4 | Sudo to root (baseline) | Count of `sudo` events targeting root, by user | 688 events: djohnson 412, nsharpe 203, myuan 72, admin 1 |
| 5 | Rare escalation | Accounts with 1 to 4 escalations to root | One row: `admin` (1) |

### 6.1 Tuning notes

**Rule 1.** A simple threshold did not work, because nearly every IP in this dataset guesses at a similar pace.

| Version | Logic | IPs flagged (of 184) |
|---|---|---|
| v1 | More than 10 failures in 5 minutes | 182 (too noisy) |
| v2 | More than 25 failures in 5 minutes | 11, but **missed** `87.194.216.51` (busiest window was 25) |
| v3 | At least 20 windows over 10 failures | 5, including the main attacker |

The cutoff of 20 sits in a natural gap in this data (the fifth IP has 22 windows, the sixth has 18). It was chosen from this dataset and should be re-measured on new data.

**Rule 2.** 175 of 184 IPs tried 15 or more usernames in a 10-minute window with only 1 to 2 attempts each. Spraying and ordinary dictionary brute force look the same here, so the rule cannot isolate a separate behavior.

**Rule 3.** With the failure threshold removed, the five IPs that ever logged in had 0 to 1 failures each. The logic works, and the threshold is simply never reached.

**Rule 5.** It measures rarity, not timing. The 34-second gap between login and escalation was established from a combined timeline of the `admin` account's events, not by this rule. It also cannot catch a takeover of an account that escalates routinely, because the attacker's activity would blend into that account's normal pattern.

---

## 7. Recommendations

1. **Rotate credentials** for the `admin` account and review whether it should exist as a remotely accessible account at all.
2. **Audit all commands executed** during both compromised sessions (`73.202.92.7` and `212.114.31.255`) for further indicators of compromise (new users, scheduled tasks, modified files).
3. **Enforce key-based SSH authentication** for privileged accounts and disable password authentication where feasible.
4. **Implement account lockout or rate-limiting** on repeated failed authentication to reduce brute-force effectiveness.
5. **Block or geofence** the identified source IPs (`87.194.216.51`, `73.202.92.7`, `212.114.31.255`) at the network perimeter, pending further investigation.
6. **Deploy the rare-escalation rule (Rule 5) as a scheduled alert**, and add an automated check for login-to-escalation timing. That timing (34 seconds here) was established manually and is not yet a rule.
7. **Establish a baseline review process** for privileged account usage, flagging any account whose escalation activity departs from its history.

---

## 8. Limitations

- Alerting could not be configured natively on the Splunk Free license tier, so detections were validated as saved reports, not live scheduled alerts.
- Detection thresholds were tuned against this dataset and need re-measuring on other data.
- Password spraying could not be separated from brute force in this data.
- Log timestamps reflect sample dataset generation dates (2026), not a real-world breach date.
- Only SSH authentication and local privilege escalation logs were analyzed. No endpoint, network, or file-integrity data was available to confirm activity beyond the initial escalation.
- The failed-login check for the two external IPs is per source IP and does not exclude attempts from other IPs.

---

## Appendix: Key SPL Queries

**Brute force, persistence version (Rule 1):**
```spl
index=test sourcetype=linux_secure "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<ssh_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=5m
| stats count by _time, src_ip
| where count > 10
| stats count as windows_over_10, max(count) as busiest_window by src_ip
| where windows_over_10 >= 20
| sort - windows_over_10
```

**Failed-then-success (Rule 3):**
```spl
index=test sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex field=_raw "Failed password for (invalid user )?(?<ssh_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "Accepted password for (?<ssh_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval outcome=case(match(_raw,"Failed password"),"failure", match(_raw,"Accepted password"),"success")
| stats count(eval(outcome="failure")) as failures, count(eval(outcome="success")) as successes by src_ip
| where failures > 5 AND successes > 0
| sort - failures
```

**Rare escalation (Rule 5):**
```spl
index=test sourcetype=linux_secure ("Accepted password" OR ("sudo" "USER=root"))
| rex field=_raw "Accepted password for (?<ssh_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "sudo:\s+(?<sudo_user>\S+)"
| eval event_type=case(isnotnull(ssh_user), "login", isnotnull(sudo_user), "escalation")
| eval user=coalesce(ssh_user, sudo_user)
| where user!="pam_unix(sudo:session):"
| stats count(eval(event_type="escalation")) as escalation_count by user
| where escalation_count > 0 AND escalation_count < 5
```

**`admin` compromise timeline (shows the 34-second gap):**
```spl
index=test sourcetype=linux_secure ("Accepted password" OR "sudo") "admin"
| rex field=_raw "Accepted password for (?<ssh_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "sudo:\s+(?<sudo_user>\S+)"
| eval event_type=case(isnotnull(ssh_user), "Login", isnotnull(sudo_user), "Privilege Escalation")
| eval user=coalesce(ssh_user, sudo_user)
| where user="admin"
| table _time, event_type, user, src_ip
| sort _time
```

---

*End of report.*
