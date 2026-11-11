<div align="center">

# 🛡️ Sentinel DFIR X

### Windows Endpoint Defense • Threat Detection • Digital Forensics

**Research Preview — v0.2**

[![Version](https://img.shields.io/badge/version-v0.2-2563eb?style=for-the-badge)](https://github.com/Hassan-Jouda/Sentinel-DFIR-X-v0.2)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011-0078D4?style=for-the-badge)
![Framework](https://img.shields.io/badge/.NET-10-512BD4?style=for-the-badge)
![Status](https://img.shields.io/badge/status-research%20preview-orange?style=for-the-badge)

**Monitor. Correlate. Investigate. Understand.**

[Overview](#overview) · [Features](#capabilities-in-v02) · [Quick Start](#quick-start) · [Architecture](#architecture) · [Roadmap](#roadmap) · [العربية](#-نبذة-بالعربية)

</div>

> [!IMPORTANT]
> **Source-code preview, not a production endpoint security product.** v0.2 has **not been compiled or runtime-tested on Windows in the preparation environment**. Build and validate it in a disposable Windows VM before use. It is **not** a certified forensic acquisition tool or a replacement for Microsoft Defender. **Keep Defender enabled.**

## Overview

**Sentinel DFIR X** is a Windows-focused, locally operated endpoint monitoring and digital forensics research project built with **C# / .NET 10** and **WPF**. It combines persistent background telemetry collection, Windows event subscriptions, process/network observations, executable metadata inspection, and explainable, rule-based correlation in a single desktop investigation workflow.

The central design principle is **evidence over assumptions**: an outbound connection, high file entropy, an unfamiliar process, or a missing embedded signer certificate **alone does not prove malicious activity**. Sentinel aggregates observable signals to help an analyst prioritize events, inspect context, and decide what to investigate next.

**Intended use:** authorized defensive research, Windows security education, lab-based incident triage, and experimentation with endpoint telemetry and detection engineering.

## Capabilities in v0.2

The following functionality is described as implemented **in the provided source**, not independently verified by a successful Windows build or end-to-end test.

| Area | Implemented behavior | Important boundary |
|---|---|---|
| **Continuous monitoring** | `SentinelAgent` Windows Worker Service runs independently of the desktop UI | Requires successful installation and adequate permissions |
| **Process observation** | Process, executable path, and new activity polling every **5 seconds** | Short-lived processes can be missed |
| **Network visibility** | IPv4 TCP/UDP endpoint enumeration with owning **PID** via Windows IP Helper API | No packet capture/content inspection; no IPv6 PID attribution |
| **Windows event telemetry** | Optional Sysmon subscription plus selected System, Defender, and Task Scheduler events | Channels, providers, and event IDs must be available/enabled |
| **Executable inspection** | PE magic check, SHA-256 (files up to **100 MiB**), sampled Shannon entropy (first **1 MiB**), embedded signer-certificate presence | Certificate presence is **not** Authenticode trust validation; limited to **8 new paths per iteration** |
| **Explainable detection** | Local heuristics, scored signals, contextual MITRE ATT&CK references where applicable | Scores are **not** malware verdicts |
| **Event correlation** | Recent PID-associated activity across categories (up to **20 minutes**) with alert cooldown | Pure polling may confuse recycled PIDs; Sysmon Process GUID helps when present |
| **Repeated callbacks** | Flags **4 distinct newly observed outbound TCP connections** to one public endpoint within **10 minutes** | A simple repetition heuristic, not proof of beaconing/backdoor/C2 |
| **Persistence monitoring** | Baselines loaded-user and HKLM autoruns plus startup folders; periodic checks and `FileSystemWatcher` notifications | Not exhaustive coverage of persistence mechanisms |
| **Local indicators** | Optional SHA-256, IP, and DNS-domain matches from `indicators.json` | Exact matching only; no external threat-reputation verdict |
| **Evidence store** | JSON Lines (`JSONL`) events, **20 MiB** log rotation, UI `snapshot.json` | Not immutable or cryptographically signed forensic storage |
| **WPF investigation UI** | Events/alerts, processes, IPv4 endpoints/PIDs, autoruns, file inspector, HTML report + SHA-256 | Manual process termination requires confirmation; no automatic remediation |

### Telemetry sources

- **Process/network polling:** baseline collection even without Sysmon.
- **Sysmon (optional):** richer event coverage when separately installed and configured.
- **Windows Event Log subscriptions:** service installation (System **7045**), Defender detection/action (**1116/1117**), and Task Scheduler (**106/140/141**) when the respective channels are active.
- **Registry and startup folders:** change observations for a defined subset of autorun locations.

> [!NOTE]
> The collectors observe **endpoint metadata**, not network packet contents. Sysmon event availability depends on its configuration; newly subscribed events are not automatically backfilled from historical logs.

## Architecture

```text
                    ┌───────────────────────────┐
                    │ Windows telemetry sources │
                    │ Processes / TCP / UDP     │
                    │ Sysmon / Event Logs       │
                    │ Registry / Startup        │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │ Sentinel.Agent            │
                    │ Windows Worker Service    │
                    │ Collection & correlation  │
                    └─────────────┬─────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │ Sentinel.Core             │
                    │ Events / rules / IOCs     │
                    │ File metadata / storage   │
                    └─────────────┬─────────────┘
                                  │
                      Local JSONL + snapshots
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │ Sentinel.Desktop          │
                    │ WPF Investigation UI      │
                    │ Alerts / inspection       │
                    │ HTML export               │
                    └───────────────────────────┘
```

**Project structure**

```text
src/
├── Sentinel.Core/           # Event models, rules, IOCs, hashing, entropy, JSONL
├── Sentinel.Agent/          # Service, collectors, correlation, snapshots
└── Sentinel.Desktop/        # WPF dashboard, inspection, reports
Build.ps1                    # Local build
Publish.ps1                  # Publish agent + desktop separately
Install-Service.ps1          # Register Windows service
Upgrade-Agent.ps1            # Upgrade an existing service installation
Smoke-Test.ps1               # Basic post-install checks
Uninstall-Service.ps1        # Remove service registration
indicators.sample.json       # Local IOC example
```

## Requirements

| Requirement | Details |
|---|---|
| OS | Windows **10 / 11**, **x64** |
| SDK | Official **.NET 10 SDK** for building |
| Shell | PowerShell; elevated for service installation/upgrade |
| Telemetry | Sysmon optional, separately configured |
| Internet | Needed for initial SDK/build dependency downloads; **no runtime cloud telemetry** is described |
| Test environment | **Strongly recommended:** disposable Windows VM and snapshot |

Check the installed SDK:

```powershell
dotnet --list-sdks
dotnet --version
```

Install the official SDK if missing: https://dotnet.microsoft.com/download

## Quick Start

### 1. Build and publish

Open **PowerShell in the project root** (the folder containing `Build.ps1`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\Publish.ps1
```

**Expected output folders:**

```text
dist/agent/
dist/desktop/
```

### 2. Test the desktop

```powershell
.\dist\desktop\Sentinel.Desktop.exe
```

**Keep the entire `dist\desktop` directory together**. Do not copy only the `.exe`: WPF deployment can require adjacent runtime and application DLLs. The multi-file desktop publish is deliberate, especially after the earlier single-file WPF startup failure.

### 3. Fresh service installation

After VM testing, open PowerShell **as Administrator**, in the project root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-Service.ps1
Get-Service SentinelAgent
```

Then launch the desktop application. Closing the desktop does not by itself stop the Windows service.

### 4. Basic smoke test

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Smoke-Test.ps1
Get-Service SentinelAgent
```

These commands are **instructions**, not proof that the build or service passed in your environment. If an operation fails, inspect the full PowerShell/compiler output before proceeding.

## Upgrade from v0.1 / v0.1.1

> [!CAUTION]
> **Preserve existing evidence.** Do **not** delete `C:\ProgramData\SentinelDFIR` and do **not** manually overwrite active service binaries in `Program Files`.

1. Extract v0.2 into a **separate directory**, such as `C:\SentinelDFIR-v0.2`.
2. Take a snapshot of the Windows VM and separately back up any evidence needed for an investigation.
3. Run `Build.ps1` and `Publish.ps1` from the new directory.
4. Confirm the new desktop starts **before** changing the installed service.
5. In an **elevated** PowerShell session, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Upgrade-Agent.ps1
Get-Service SentinelAgent
powershell -NoProfile -ExecutionPolicy Bypass -File .\Smoke-Test.ps1
```

The provided upgrade script is described as backing up previous **service binaries** and attempting rollback if upgrade fails. It is **not** a substitute for a separate verified backup, and this behavior has not been independently runtime-tested here. The existing EventStore should not be deleted by the stated upgrade workflow.

To remove service **registration** using the included script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-Service.ps1
```

Review the script before running it and preserve evidence separately.

## Local Data and Indicators

| Location | Purpose |
|---|---|
| `C:\ProgramData\SentinelDFIR\events.jsonl` | Current append-only JSONL event log (rotation at **20 MiB**) |
| `C:\ProgramData\SentinelDFIR\events-*.jsonl` | Rotated event-log files |
| `C:\ProgramData\SentinelDFIR\snapshot.json` | Desktop-facing summary/snapshot |
| `C:\ProgramData\SentinelDFIR\indicators.json` | Optional, locally maintained IOC list |

Configure example local indicators **after the service has created its data directory**:

```powershell
Copy-Item .\indicators.sample.json 'C:\ProgramData\SentinelDFIR\indicators.json'
```

Inspect recent evidence and snapshot properties:

```powershell
Get-Content 'C:\ProgramData\SentinelDFIR\events.jsonl' -Tail 4
Get-Content 'C:\ProgramData\SentinelDFIR\snapshot.json' -Raw |
  ConvertFrom-Json | Select-Object ProcessCount, SysmonActive, DroppedEvents
```

IOC hits should be investigated and corroborated, not automatically treated as verified compromise. Do not copy real event logs or secrets into public issues or repositories.

## Optional: Microsoft Sysmon

Sysmon can improve visibility into activity missed by periodic polling. It is **not** silently installed or reconfigured by Sentinel DFIR X.

- [Official Sysmon download](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Official Sysmon events reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)

Sysmon network **Event ID 3** commonly requires explicit enablement. Carefully review event volume, privacy implications, and host performance before using a custom configuration.

## Detection & Severity

| Score | Label | Interpretation |
|---:|---|---|
| **0–24** | Info | Observational event or limited suspicious context |
| **25–59** | Medium | One or more weaker indicators |
| **60–84** | High | Strong or combined suspicious signals |
| **85–100** | Critical | Strong correlated signals or an analyst-supplied indicator match |

**These values represent heuristic prioritization, not calibrated probabilities of malware.** Examples of non-conclusive signals include:

- High entropy (legitimate software may be packed/compressed).
- Missing embedded signer certificate (legitimate apps may be unsigned).
- An outbound connection to an unusual port, including `4444` (not proof of a reverse shell).
- Repeated connections to the same endpoint (not by itself a confirmed beacon).
- Certificate presence (does **not** confirm code signature trust).

To independently inspect an executable's Authenticode status on Windows:

```powershell
Get-AuthenticodeSignature 'C:\path\to\program.exe' |
  Select-Object Status, StatusMessage, SignerCertificate
```

## Privacy, Safety & Forensic Integrity

> [!WARNING]
> **Use only on devices you own or are authorized to monitor.** Event data may contain usernames, file paths, command-line arguments, IP addresses, domains, and potentially sensitive material.

- **Local-first:** no built-in cloud upload, remote administration, credential capture, covert command channel, or automatic malware execution is described.
- **No automatic destructive response:** no automatic quarantine, process termination, blocking, or registry modification. Manual process termination in the UI requires an explicit confirmation and may still cause data loss.
- **Keep Microsoft Defender enabled.** This project does not replace a supported antivirus/EDR solution.
- **Protect the evidence directory:** access controls, retention and data lifecycle policies still need hardening.
- **Not a complete chain of custody:** an HTML report `.sha256` checksum can detect changes, but cannot independently demonstrate authorized collection, custody, or integrity of the source events.
- **Bounded collection has gaps:** polling can miss short-lived activity; queue pressure may drop events; user-mode collection cannot reliably resist a privileged attacker.
- **Validate performance** on a disposable Windows VM before deploying beyond a lab.

## Known Limitations

This preview **does not** contain:

- A fully integrated **YARA-X** scanner or general-purpose **Sigma** YAML engine.
- An AI/ML threat detection model or automated malware classification.
- Deep memory forensics, kernel-level rootkit detection, or malware sandbox execution.
- Packet capture/inspection or IPv6 process-ID attribution.
- Verified Authenticode chain/revocation/tampering checks.
- Full WMI, service, task, and all-user persistence coverage.
- Production-grade self-protection, hardened IPC permissions, signed evidence bundles, or a complete installer.

Additionally, file entropy samples only the first **1 MiB**; the callback repetition rule is a simple count rather than a validated beaconing model; purely polling-based PID correlation may be affected by PID reuse.

## Roadmap

- [ ] **Verify Windows builds and WPF startup** on supported .NET 10 installations.
- [ ] **Automated tests:** event parsers, IOC rules, rotation, correlation and upgrade/rollback.
- [ ] **Detection engineering:** validated YARA-X and Sigma integrations with versioned rules.
- [ ] **Code provenance:** full Authenticode verification and section-aware PE inspection.
- [ ] **Investigation context:** richer process trees and statistical beaconing analysis.
- [ ] **Evidence integrity:** signed evidence packages, collection metadata and custody procedures.
- [ ] **Operational hardening:** ACLs, retention, observability, installer, recovery and performance testing.

Roadmap items are **planned**, not existing capabilities.

## Verification Status

| Component | Current verification |
|---|---|
| Source archive and structure | Described as inspected |
| XML / ZIP structure | Described as validated during source preparation |
| v0.1 predecessor | Previously built on the user's Windows SDK (per project notes) |
| **v0.2 Windows build** | **Not verified** in the preparation environment |
| **v0.2 Windows runtime** | **Not verified** |
| Production security, forensic certification | **Not claimed** |

If you find a compiler or startup error, include the redacted build output, Windows version, `dotnet --info`, and the relevant event log message in a GitHub issue. **Do not attach private evidence files or secret-bearing logs.**

## Contributing

Defensive improvements, reproducible bug reports, documentation corrections, tests, and validated detection rules are welcome. Please avoid submitting real private endpoint logs, credentials, or claims of detection coverage without reproducible testing.

## License

**Educational/research source preview.** No open-source license grant is asserted in this README. Review the repository's actual `LICENSE` file (if present) and all dependency licenses before redistribution or reuse.

## 🇵🇸 نبذة بالعربية

**Sentinel DFIR X v0.2** مشروع بحثي دفاعي مفتوح للتطوير يهدف إلى مراقبة أنشطة أجهزة Windows وتحليل الأحداث الأمنية وربط المؤشرات للمساعدة في التحقيق في السلوك المشبوه. يجمع بين خدمة مراقبة تعمل في الخلفية، وواجهة WPF، ورصد العمليات والاتصالات، وتحليل ملفات PE، ومؤشرات الاستمرارية، وسجلات JSONL محلية وتقارير HTML.

**تنبيه:** الوظائف موصوفة على مستوى الشيفرة المصدرية ولم يتم تأكيد نجاح بناء النسخة v0.2 وتشغيلها على Windows. الأداة ليست مضاد فيروسات تجاريًا ولا تؤكد وجود برمجية خبيثة من إشارة واحدة، ولا تستبدل Microsoft Defender. يُنصح باختبارها أولًا في جهاز افتراضي والحفاظ على سجلات الأدلة وعدم رفعها علنًا.

---

<div align="center">

**Sentinel DFIR X — Investigate signals, not assumptions.**

[GitHub Repository](https://github.com/Hassan-Jouda/Sentinel-DFIR-X-v0.2)

</div>
