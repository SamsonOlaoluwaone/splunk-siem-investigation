# Security Incident Report: Web Server Compromise

**Report ID:** IR-2026-002
**Classification:** Internal Use
**Prepared by:** [Your Name], SOC Analyst
**Date Prepared:** October 9, 2026
**Environment:** Joomla web server `192.168.250.70` (Wayne Corp Inc. network, Boss of the SOC v1 dataset)
**SIEM Platform:** Splunk Enterprise (Free license tier)
**Data Sources:** `index=botsv1`, sourcetypes `stream:http` and `suricata`
**Event Date:** August 10, 2016 (dataset timestamps)

---

## 1. Executive Summary

Web traffic and intrusion-detection logs show a multi-stage attack on a Joomla web server. One external IP ran an automated vulnerability scan. A second external IP guessed passwords against the Joomla administrator login. About a minute after the guessing ended, the scanning IP logged in as `admin` with a password that was on the guesser's list, then uploaded an obfuscated PHP package through the admin panel and browsed the server's file system.

The upload is confirmed by two independent sources. The login is inferred from the activity that followed it. Whether the two IPs are one actor is **not** established.

**Severity: High.** The evidence is consistent with administrator access to the web server and installation of a likely web shell.

---

## 2. Scope and Methodology

- Counted web requests by source and destination to find outliers.
- Broke the two top external IPs down by HTTP method and by the pages they posted to.
- Extracted submitted usernames and passwords from login POSTs with `rex`.
- Checked every IDS (Suricata) alert for the two IPs.
- Matched events across two data sources by timestamp.
- Compared the two IPs' submitted passwords.

**Method note.** HTTP status code 303 could not be used to separate failed from successful logins. All 412 guessing attempts returned 303, including passwords such as `qwerty`, so Joomla evidently redirects on failure as well. Login success is therefore inferred from the actions that followed, not from the status code.

---

## 3. Timeline (2016-08-10)

| Time | Source IP | Event | Evidence |
|---|---|---|---|
| 17:37:16 | `40.80.148.42` | Earliest PHP-tag IDS alert; automated scanning in progress | Suricata |
| 17:45:21 to 17:46:51 | `23.22.63.114` | 412 password guesses against `/joomla/administrator/index.php` (about 90 seconds) | `stream:http` |
| 17:48:05 | `40.80.148.42` | `admin` / `batman` submitted (the only password this IP sent) | `stream:http` |
| 17:50:31 | `40.80.148.42` | Obfuscated PHP package uploaded via `task=install.install`, target `C:\inetpub\wwwroot\joomla/tmp` | `stream:http` at 17:50:31.324, Suricata alert at 17:50:31.326 |
| 17:51 to 18:21 | `40.80.148.42` | File-system browsing through the eXtplorer component (`com_extplorer`) | `stream:http` |

---

## 4. Detailed Analysis

### 4.1 Reconnaissance: vulnerability scan (`40.80.148.42`)

This IP sent about 17,500 requests to the web server, far more than any other source. Suricata raised alerts of **50 distinct types** for it, and one signature named the tool: "ET SCAN Acunetix Version 6 (Free Edition) Scan Detected" (45 alerts). Other alerts covered cross-site scripting, SQL injection, XML external entity, Shellshock (CVE-2014-6271), and attempts to reach `cmd.exe`, `/system32/`, and `global.asa`. The scan also used unusual HTTP methods (`OPTIONS`, `TRACE`, `PROPFIND`, `CONNECT`).

These alerts show attacks were **attempted**. They do not show that any succeeded.

### 4.2 Credential guessing (`23.22.63.114`)

412 POSTs to the administrator login in about 90 seconds, always with `username=admin` and a different password each time (the first five reviewed: `12345678`, `letmein`, `qwerty`, `1234`, `123456`). Those five arrived within 34 milliseconds, which is only possible with automated tooling.

Suricata recorded 3,273 events for this IP (HTTP, flow, and fileinfo records) and raised **no alerts** for any of them. The password guessing was visible to the IDS but not flagged by it.

### 4.3 Link between the two IPs

`batman` appears once in the guesser's 412 attempts. About 74 seconds after the guessing ended, `40.80.148.42` submitted `admin` / `batman`. The shared password and the timing make it likely the credential came from the guessing run.

**This is not proof of a single actor.** The two IPs could be one attacker using two machines, or two parties sharing results. The report states only that the activity is consistent with one actor.

### 4.4 Administrator access, package upload, and file browsing

Within about 2.4 minutes of the `batman` login, the same IP posted an install package through the admin panel. Only an authenticated administrator can do this, which is why access is inferred.

- The package is PHP code padded with junk characters and built to hide its contents. A disguised upload through the admin panel, followed by file-system browsing, matches the usual shape of a **web shell** (a backdoor giving remote control). The code was not analyzed, so "web shell" is an assessment, not a confirmed finding.
- The upload is the only package installation in the dataset.
- Two further PHP-tag POSTs were flagged by the IDS at 17:50:58 and 17:52:47. Their contents were not reviewed.
- Of the 14 POSTs this IP sent to the admin page, 10 were reviewed. They contained no passwords; they were upload and file-browser actions. The remaining 4 were not reviewed.

---

## 5. MITRE ATT&CK Mapping

| Technique | Name | Observed |
|---|---|---|
| T1595.002 | Active Scanning: Vulnerability Scanning | Acunetix scan, 50 distinct IDS signatures |
| T1110.001 | Brute Force: Password Guessing | 412 guesses against the admin login |
| T1078 | Valid Accounts | `admin` / `batman` followed by admin-only actions (inferred) |
| T1505.003 | Server Software Component: Web Shell | Obfuscated PHP package upload (assessed, not confirmed) |
| T1083 | File and Directory Discovery | eXtplorer folder browsing |

---

## 6. Detection Rules Developed

| Rule (saved report) | Logic | Result |
|---|---|---|
| `Detection_WebBruteForce_Joomla` | More than 10 POSTs to the admin login from one IP in 5 minutes | Flags `23.22.63.114` (412). The scanner's 14 POSTs were spread over about 30 minutes and did not trigger it. |
| `Detection_Scanner_MultiSignature` | One source IP triggering more than 5 distinct IDS signatures | Flags only `40.80.148.42` (50 signatures). No false positives. |
| `Detection_Web_LoginThenUpload` | Same IP submits a password, then uploads a package within 10 minutes | Flags only `40.80.148.42` (gap 2.4 minutes). The guesser is not flagged because it never uploaded. |

---

## 7. Recommendations

1. Treat `192.168.250.70` as compromised. Locate and remove the uploaded package (the install target was `joomla/tmp`) and review the server for web shells and added files.
2. Reset the `admin` password and any shared credentials. `batman` is a dictionary password and must not be reused.
3. Restrict the `/administrator` path by IP or VPN, and require multi-factor authentication for admin logins.
4. Rate-limit or lock out repeated login failures on the admin page.
5. Review the two additional PHP-tag POSTs (17:50:58 and 17:52:47) and the 4 unreviewed admin-page POSTs.
6. Block `40.80.148.42` and `23.22.63.114` at the perimeter, pending further investigation.
7. Patch Joomla and its extensions, and review whether the eXtplorer component is needed.
8. Schedule the three detection rules as alerts on a licensed Splunk instance.

---

## 8. Windows Checks That Found No Activity

Hypotheses from the original plan that the BOTS v1 data did not support:

| Check | Result |
|---|---|
| Windows EventCodes 4720 (account created), 4732 (added to a group), 4625 (failed logon) | Not present; only 4624 (3,209 successful logons) exists |
| RDP logons (logon type 10) | None |
| Rare logon types (2, 7, 11, 0) | 9 events, all benign: system startup, Windows display-manager accounts, one user at their own workstation |
| PowerShell in Sysmon | 5 events, all the Splunk Universal Forwarder's own helper process (`splunk-powershell.exe`) loading standard DLLs |

---

## 9. Limitations

- Alerting is unavailable on the Splunk Free license, so the rules are saved reports, not scheduled alerts.
- Login success is inferred, not directly observed (see the method note).
- The uploaded package was not analyzed.
- The two IPs may or may not be one actor.
- Suricata raised no alerts for the guessing IP; other detection tools were not checked.
- The dataset is a public training scenario with 2016 timestamps.

---

## Appendix: Key SPL

**Scanner detection**
```spl
index=botsv1 sourcetype=suricata
| stats count, dc(alert.signature) as distinct_signatures by src_ip
| where distinct_signatures > 5
| sort - count
```

**Web brute force**
```spl
index=botsv1 sourcetype=stream:http http_method=POST uri_path="/joomla/administrator/index.php"
| bin _time span=5m
| stats count by _time, src_ip
| where count > 10
```

**Login followed by upload**
```spl
index=botsv1 sourcetype=stream:http http_method=POST uri_path="/joomla/administrator/index.php"
| eval action=case(like(form_data,"%passwd=%"),"login", like(form_data,"%task=install.install%"),"upload")
| where isnotnull(action)
| stats min(eval(if(action="login",_time,null()))) as first_login, min(eval(if(action="upload",_time,null()))) as upload_time by src_ip
| where isnotnull(first_login) AND isnotnull(upload_time) AND (upload_time - first_login) < 600
| eval minutes_between=round((upload_time - first_login)/60, 1)
| convert ctime(first_login) ctime(upload_time)
```

---

*End of report.*
