# PhishStrike — Spear-Phishing Email Forensics & Malware Triage

[![Category](https://img.shields.io/badge/Category-Threat%20Intel-blue)]()
[![Tactics](https://img.shields.io/badge/Tactics-Initial%20Access%20%7C%20Execution-orange)]()
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)]()

## Overview

This repository documents a full incident-response walkthrough of the **PhishStrike** lab (CyberDefenders CyberRange). The investigation covers email header/authentication analysis, malicious URL triage, malware sample identification, sandbox behavioral analysis, C2 infrastructure mapping, and a MITRE ATT&CK technique mapping for a spear-phishing campaign targeting educational faculty members. It also includes three draft Sigma detection rules as a learning exercise in translating sandbox findings into detection logic.

Full technical write-up: [`report.md`](./report.md)

## Scenario

> As a cybersecurity analyst at an educational institution, an alert is raised for a phishing email targeting faculty members. The email spoofs a trusted contact and claims a **$625,000** purchase, providing a link to download an "invoice." The objective is to analyze the email headers, inspect the linked content for malicious behavior, identify Indicators of Compromise (IOCs), and document findings to prevent fraud and support faculty awareness.

| Attribute | Detail |
|---|---|
| Lab | PhishStrike (CyberDefenders CyberRange) |
| Category | Threat Intel |
| Tactics | Initial Access, Execution |
| Lure | Spoofed "Commercial Purchase Receipt" — fraudulent $625,000 invoice |
| Target | Faculty member, uptc.edu.co (educational institution) |
| Questions | 11/11 solved (100%) |

## Tools Used

- **PhishTool** — email header, authentication (SPF/DKIM/DMARC), and URL extraction
- **URLhaus (abuse.ch)** — malicious URL/host intelligence and payload history
- **VirusTotal** — file/network relations and detection ratio
- **MalwareBazaar (abuse.ch)** — malware sample metadata and sandbox links
- **ANY.RUN** — interactive dynamic malware analysis (behavioral sandbox)
- **CyberChef** — Base64 decoding of the PowerShell loader command
- **tria.ge (Triage)** — secondary sandbox validation, network IOC confirmation

## Key Findings Summary

- **Header/Authentication failure**: Sender IP `18.208.22[.]104` — SPF: **softfail**, DKIM: **fail/neutral**, DMARC: **fail**. Return-Path (`erikajohana.lopez@uptc.edu[.]co`) does not align with the originating IP's rDNS (`inpost.tmes.trendmicro[.]com`), confirming spoofing of the trusted contact.
- **Payload delivery**: Malicious link resolves to `107.175.247[.]199`, a host serving three distinct payloads from the same `/loader/` path — tagged **CoinMiner**, **BitRAT**, and **AsyncRAT** on URLhaus.
- **BitRAT sample** (`bf7628695c2df7a3020034a065397592a1f8850e59f9a448b555bc1c8c639539`): drops to `C:\Users\admin\AppData\Roaming\Ozndzodb\Jzwvix.exe`, establishes persistence via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, and delays execution 50 seconds via `Start-Sleep -Seconds 50` (Base64-encoded PowerShell) — a basic sandbox-evasion technique. C2: `gh9st.mywire[.]org`.
- **AsyncRAT sample** (`5ca468704e7ccb8e1b37c0f7595c54df4e2f4035345b6e442e8bd4e11c58f791`): exfiltrates/receives commands via the **Telegram Bot API** (`bot5610920260`), polling `api.telegram[.]org`.

Full breakdown and defanged IOC matrix: [`report.md`](./report.md#5-ioc-summary).

## Repository Structure

```
├── README.md          # This file — project overview
├── report.md          # Full incident response report (header analysis, malware triage, sandbox findings, ATT&CK mapping, IOC matrix)
├── detections/         # Draft Sigma rules (learning exercise, not production-tested)
│   ├── registry_autorun_appdata_roaming.yml
│   ├── powershell_encoded_sleep_evasion.yml
│   └── telegram_bot_api_c2_pattern.yml
└── screenshots/        # Supporting evidence captured during the investigation
    ├── 01_phishtool_authentication.png
    ├── 02_phishtool_details.png
    ├── 03_phishtool_urls.png
    ├── 04_urlhaus_browse.png
    ├── 05_urlhaus_host_payloads.png
    ├── 06_virustotal_relations.png
    ├── 07_urlhaus_bitrat_payload.png
    ├── 08_malwarebazaar_browse.png
    ├── 09_malwarebazaar_sample.png
    ├── 10_anyrun_registry_persistence.png
    ├── 11_anyrun_process_tree_http.png
    ├── 12_anyrun_dropped_file_hash.png
    ├── 13_cyberchef_base64_decode.png
    ├── 14_anyrun_dns_requests.png
    ├── 15_urlhaus_asyncrat_payload.png
    └── 16_triage_telegram_c2.png
```

## Disclaimer

This repository is for **educational and defensive security research purposes only**, produced as part of a controlled CyberDefenders lab exercise. All indicators of compromise (IOCs) are **defanged** to prevent accidental execution or navigation. Do not interact with any listed domains, IPs, or URLs outside of an isolated analysis environment.
