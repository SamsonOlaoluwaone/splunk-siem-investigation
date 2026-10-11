# SIEM Log Analysis: Attack Detection and Incident Investigation (Splunk)

SOC-style investigations built in **Splunk Enterprise**. I ingested Linux SSH logs and the Boss of the SOC v1 dataset (web traffic, IDS alerts, Windows and Sysmon logs), extracted fields, wrote and tuned detection rules, investigated two incidents, and presented the findings in a dashboard and two formal reports.

![Dashboard overview](screenshots/dashboard-full.png)

---

## TL;DR: What I found

### Incident 1: Linux SSH account compromise ([report](report/incident-report.md))

| Finding | Detail |
|---|---|
| Brute force (failed) | `87.194.216.51` made **1,557** failed logins across **148 usernames**. Cross-checked against every successful login: **zero matches**. |
| Account compromise | The `admin` account has no history of internal use, yet was accessed from external IP `73.202.92.7` on the **first attempt**, suggesting valid, likely stolen credentials. |
| Privilege escalation | **34 seconds** later the session ran `sudo /bin/su` to become `root`. That was `admin`'s only escalation, against 412 / 203 / 72 for routine users. |

### Incident 2: Joomla web server compromise ([report](report/incident-report-web.md))

| Finding | Detail |
|---|---|
| Scan | `40.80.148.42` ran an automated vulnerability scan. The IDS identified the tool (Acunetix) and logged **50 distinct alert types**. |
| Password guessing | `23.22.63.114` made **412 guesses** at the Joomla admin login in about 90 seconds. The IDS raised **no alerts** for it. |
| Link | The password `batman` appears once in the guesser's list. About 74 seconds after the guessing ended, the scanner IP submitted `admin` / `batman`. |
| Upload | **2.4 minutes** after that login, an obfuscated PHP package was uploaded through the admin panel. Two independent sources (web logs and IDS) recorded it 2 ms apart. Likely a web shell. |

Caveat: web login success is **inferred** from the admin-only actions that followed, and the two IPs are not proven to be one actor.

---

## Scenario

I played the role of a SOC analyst. The task: review logs from several systems, work out who is attacking, and decide whether anyone got in.

## Tools and data

- **SIEM:** Splunk Enterprise (Free license tier)
- **Linux data:** `linux_secure` SSH authentication logs (`index=test`), about 30 days from one host
- **Web, IDS, and Windows data:** Splunk Boss of the SOC v1, attack-only (`index=botsv1`): `stream:http`, `suricata`, `wineventlog:security`, Sysmon
- **Environment:** Kali Linux

---

## Method

1. **Explore:** count events by source IP, event type, or user to find outliers.
2. **Extract fields:** `rex` to pull IPs, usernames, and passwords out of raw text.
3. **Investigate the loud source:** what did it target, and did it ever succeed?
4. **Investigate the quiet source:** low-volume activity that doesn't fit the baseline.
5. **Correlate across sources:** line up web logs and IDS alerts by timestamp.
6. **Tune:** measure how many IPs each threshold flags, then adjust.
7. **Report and visualize:** formal reports plus a dashboard.

---

## Detections

Seven working rules and one that was tested and rejected. Each is saved as a Splunk report and stored in [`detections/`](detections/).

| # | Detection | Logic | MITRE ATT&CK | Result |
|---|---|---|---|---|
| 1 | SSH brute force (persistence) | At least 20 five-minute windows with more than 10 failed logins from one IP | T1110 | Flags **5 of 184** IPs, top is `87.194.216.51` |
| 2 | Password spraying | More than 5 usernames, under 3 attempts each, in 10 minutes | T1110.003 | **Tested, not adopted:** flagged 182 of 184 IPs |
| 3 | Failed-then-success | More than 5 failures and at least 1 success from one IP | T1110, T1078 | No results, as expected |
| 4 | Sudo to root (baseline) | Count of `sudo` to root by user | T1548.003 | 688 events; `admin` has 1 |
| 5 | Rare escalation | Accounts with 1 to 4 escalations to root | T1078, T1548.003 | One row: `admin` |
| 6 | Web brute force (Joomla) | More than 10 POSTs to the admin login from one IP in 5 minutes | T1110.001 | Flags `23.22.63.114` (412) |
| 7 | Scanner | One IP triggering more than 5 distinct IDS signatures | T1595.002 | Flags only `40.80.148.42` (50) |
| 8 | Login then package upload | Same IP submits a password, then uploads a package within 10 minutes | T1078, T1505.003 | Flags `40.80.148.42` (gap 2.4 min) |

### Tuning story: Rule 1

A simple threshold did not work, because nearly every IP in the dataset guesses at a similar pace.

| Version | Logic | IPs flagged (of 184) |
|---|---|---|
| v1 | More than 10 failures in 5 minutes | 182 (too noisy) |
| v2 | More than 25 failures in 5 minutes | 11, but **missed** the main attacker (its busiest window was 25) |
| v3 | At least 20 windows over 10 failures | 5, including the main attacker |

The main attacker is not the fastest, it is the most **persistent**: 60 windows over the threshold against 37 for the next IP. The cutoff of 20 was chosen from this dataset and should be re-measured on new data.

### Why Rules 2, 3, and 5 are described the way they are

- **Rule 2** was rejected: 175 of 184 IPs tried 15 or more usernames with 1 to 2 attempts each, so spraying cannot be told apart from ordinary dictionary brute force in this data.
- **Rule 3** returns nothing. That is the correct result, and a sanity check (with the threshold removed) showed the logic works: the five IPs that ever logged in had 0 to 1 failures each.
- **Rule 5** measures **rarity**, not timing. The 34-second login-to-escalation gap came from the `admin` timeline, not from this rule. It also can't catch a takeover of an account that escalates routinely.

### Example: login then upload

```spl
index=botsv1 sourcetype=stream:http http_method=POST uri_path="/joomla/administrator/index.php"
| eval action=case(like(form_data,"%passwd=%"),"login", like(form_data,"%task=install.install%"),"upload")
| where isnotnull(action)
| stats min(eval(if(action="login",_time,null()))) as first_login, min(eval(if(action="upload",_time,null()))) as upload_time by src_ip
| where isnotnull(first_login) AND isnotnull(upload_time) AND (upload_time - first_login) < 600
| eval minutes_between=round((upload_time - first_login)/60, 1)
| convert ctime(first_login) ctime(upload_time)
```

It returns one IP (`40.80.148.42`, gap 2.4 minutes). The password guesser, with 412 logins and no upload, is correctly ignored.

---

## Dashboard

Six panels cover the Linux incident: top attacking IPs, usernames targeted, failed logins over time, successful logins by source, the **admin compromise timeline**, and escalation frequency by user.

![Admin compromise timeline](screenshots/admin-timeline.png)

---

## Checked but not present

Hypotheses that the data did not support, documented so reviewers can see what was ruled out:

- Windows EventCodes 4720 (account created), 4732 (group change), 4625 (failed logon): none in the dataset.
- RDP logons (type 10): none. The 9 rare logons were all benign.
- PowerShell in Sysmon: only the Splunk forwarder's own helper process.
- Password spraying as a behavior separate from brute force (see Rule 2).

---

## Lessons learned

- **Verify against the full data.** An early guess from a 20-event preview pointed at the wrong IP. Counting across the whole dataset fixed it.
- **The loud attacker isn't always the real incident.** On Linux, the 1,557-failure IP never got in. On the web, the IDS flagged the scanner 50 ways and missed the password guessing entirely.
- **Tune with measurements, not guesses.** Counting how many IPs each threshold flags showed that a higher threshold missed the main attacker, and that persistence was the signal that mattered.
- **A quiet rule needs proof it can fire.** Rule 3 returns nothing, so I removed its threshold to show the logic counts correctly.
- **Check your own assumptions.** I expected HTTP status 303 to mean a successful web login. All 412 guesses returned 303, so the field couldn't separate success from failure, and I inferred access from later actions instead.
- **Say what you haven't proven.** Both reports separate what the data shows from what it suggests, and Rule 2 is documented as a rejected rule instead of being quietly dropped.

## Limitations

- Splunk Free has no alerting, so detections are saved reports, not scheduled alerts.
- Both datasets are synthetic or training scenarios with generated timestamps.
- Thresholds were tuned on this data and need re-measuring elsewhere.
- The uploaded PHP package was not analyzed, so "web shell" is an assessment.
- Login-to-escalation timing (34 seconds) was established manually, not by a rule.

## Next steps

- Automate the login-to-escalation timing check on the Linux data.
- Test the spraying rule on a dataset that actually contains spraying.
- Review the remaining PHP-tag alerts and admin-page POSTs from the web incident.
- Convert saved searches to scheduled alerts on a licensed instance.

---

## Repository structure

```
splunk-siem-investigation/
├── README.md
├── detections/          # one .spl file per rule (8 files)
├── report/
│   ├── incident-report.md       # Linux SSH incident
│   └── incident-report-web.md   # Joomla web incident
└── screenshots/
    ├── dashboard-full.png
    └── admin-timeline.png
```

## Skills demonstrated

Log parsing and regex field extraction, SPL, threat detection, cross-source event correlation, threshold tuning and false-positive reduction, MITRE ATT&CK mapping, incident investigation, dashboarding, and evidence-based technical reporting.
