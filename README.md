# Patch Compliance Dashboard

A read-only PowerShell tool that turns WSUS patch status into a clear compliance dashboard: an overall score, compliance broken down by server group, the servers furthest behind, and the critical CVEs still open across the estate.

Patch status lives in WSUS as rows nobody reads. This surfaces the part that matters — who is missing security updates right now — in one page you can send to management or a patch bridge.

**[View the sample dashboard →](https://aayyagar.github.io/patch-compliance-dashboard/sample-report/)**

## What it shows

- **Overall compliance** — the share of servers fully patched.
- **By group** — compliance per WSUS target group (Domain Controllers, Web Tier, Database…), worst first, with a count of open critical updates.
- **Servers** — each server's state, missing-update count, missing-critical count, last check-in, and the specific KBs it needs. Servers that have stopped reporting are flagged separately so a silent agent is never mistaken for a compliant one.
- **Open critical CVEs** — a rollup of the known-critical CVEs still missing and which servers are exposed.

## Data sources

```powershell
# Built-in sample data
.\Invoke-PatchComplianceReport.ps1 -Demo

# Query a WSUS server directly (run where the WSUS console/API is available)
.\Invoke-PatchComplianceReport.ps1 -WsusServer wsus01.corp.local -UseSsl

# From a CSV export (works anywhere; reshape an SCCM/Intune export to these columns)
.\Invoke-PatchComplianceReport.ps1 -InputCsv .\wsus-export.csv
```

### CSV format

See [`wsus-export.example.csv`](wsus-export.example.csv). Columns:

`Server, Group, OS, MissingUpdates, MissingCritical, LastReportStatusTime, KBs, CVEs`

`KBs` and `CVEs` are optional, semicolon- or comma-separated. This makes the tool source-agnostic: if you can export patch status to these columns from WSUS, SCCM/MECM, Intune or AWS Systems Manager, the dashboard works.

## Highlighting critical CVEs

[`critical_cves.json`](critical_cves.json) maps KBs to known-critical CVEs so the dashboard can flag them. Extend it from your own patch-Tuesday tracking; the CVE column in a CSV export is used directly as well.

## Server states

| State | Meaning |
|---|---|
| **Critical** | Missing one or more security/critical updates |
| **Stale** | Has not reported to WSUS within the threshold (default 7 days) |
| **Behind** | More than 10 updates missing (non-critical) |
| **Minor** | 1–10 updates missing |
| **Compliant** | Up to date |

## Parameters

| Parameter | Description |
|---|---|
| `-WsusServer` / `-WsusPort` / `-UseSsl` | Query WSUS directly |
| `-InputCsv` | Report from a CSV export |
| `-CriticalCVEs` | Path to the KB→CVE map (default `critical_cves.json`) |
| `-StaleReportDays` | Not-reporting threshold (default 7) |
| `-OutputPath` | Output folder (default `.\PatchReport`) |
| `-Demo` | Built-in sample data |

## Why this exists

Managing WSUS upstream/downstream servers and patch compliance across large fleets means answering one question every month: *which servers still need the security updates, and which ones stopped reporting?* This tool answers it on demand, read-only, in a format you can hand to a change board.

## Requirements

- PowerShell 5.1 or 7+
- For `-WsusServer`: the WSUS Administration API on the host (RSAT / WSUS console)
- For `-InputCsv`: works anywhere

## Output

HTML dashboard, plus JSON and CSV for automation and ticketing.

## Author

**Akhilesh Ayyagari**, Cloud Infrastructure & Identity Architect · [Portfolio](https://aayyagar.github.io) · [LinkedIn](https://www.linkedin.com/in/akhilesh-ayyagari)

## License

MIT
