# Nexus Sentinel

Build a production-grade, fully functional Enterprise Security Operations Center (SOC) web application named "NexusSIEM Pro" with a sleek, dark-mode cybersecurity aesthetic (using Tailwind CSS with deep slate and cyan/blue neon accents, JetBrains Mono for telemetry, and Lucide icons).

The application must be a robust, client-side Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) dashboard containing the following core architectural modules:

1. TOP NAVIGATION HEADER:
- App Title: "NexusSIEM Pro" with an ENTERPRISE v4.0 badge.
- Subtitle: "Advanced Threat Hunting, Real-Time Sigma Engine & Autonomous SOAR Playbooks".
- Action Buttons: "Start Live Attack Stream" (with a pulsing green/red status indicator), "Sigma Rules Repository", and "Purge SIEM Buffer".

2. METRICS & KPI CARDS (Top Row):
- Total Ingested Events counter.
- Active Security Alerts counter.
- Critical / High Severity counter.
- Isolated Hosts / Blocked IPs counter.

3. ANALYTICS & CHARTS SECTION:
- Severity Distribution Donut Chart (Chart.js or Recharts) showing breakdown across Critical, High, Medium, and Low.
- Top Attack Categories / Event Types Bar Chart.

4. LEFT SIDEBAR (Ingestion & Threat Intelligence):
- Raw Log Ingestion Pipeline: Textarea for pasting custom syslog, SSH brute-force logs, web server access logs (Nginx/Apache), or UFW firewall drops, plus a normalize/scan button and file upload option.
- Threat Intelligence Enrichment Lookup: Input box to lookup IP reputation (e.g., flagging known malicious IPs with geo-location, confidence scores, and threat tags like "SSH Brute Force" or "Path Traversal").
- Active ATT&CK TTPs Summary: Quick-view list showing triggered MITRE ATT&CK techniques (e.g., T1110.001 - Password Guessing, T1190 - Exploit Public-Facing Application).

5. MAIN DATA TABLE (Logs & Alerts):
- Search bar supporting real-time filtering across IPs, usernames, MITRE IDs, and event types.
- Severity filter dropdown (All, Critical, High, Medium, Low).
- Export Audit Report button (downloads a JSON audit file).
- Data table displaying: Severity Badge, Timestamp, Event Type, Source IP, User/Asset, Matched Sigma Rule / MITRE ID, and a "Forensics" action button.

6. INTERACTIVE MODALS & SOAR PLAYBOOKS:
- Sigma Rules Repository Modal: Displays active detection rules with severity levels and MITRE ATT&CK mappings.
- Forensic Inspector & SOAR Playbook Modal: Clicking "Forensics" on any log row opens a detailed modal displaying the raw payload, normalized schema, and one-click autonomous SOAR playbook buttons: "Block Source IP at Firewall" and "Quarantine Endpoint".

7. LIVE ATTACK SIMULATION ENGINE:
- When the user clicks "Start Live Attack Stream", a background timer automatically streams simulated attacks ($sshd$ brute force, web fuzzing, firewall drops) into the dashboard every 3.5 seconds, dynamically updating the charts, metrics counters, and log table in real time.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://nexus-siem-pro.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/3a694e01-82a3-4435-b1f8-4b2404da1ae2).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
