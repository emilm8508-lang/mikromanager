# Historia zmian MikroManager

Numer wersji agenta (`agent_version`) i krótki opis co zostało dodane, poprawione lub zmienione w każdym wydaniu. Wersja bieżąca to najwyższy numer na górze listy.

## 1.85 — 2026-09-04
- Add a per-host credential override for Windows hosts (WindowsHost.credential_id, mirrors DellServer's own) - the single shared WinRM credential couldn't authenticate both domain-joined and workgroup-only hosts at once, which the user hit directly (two real hosts, one in a domain and one not, both failing "credentials rejected" against the one shared account). Every action (check/upgrade/restart/run-script/services/resources) and the automatic discovery-refresh loop now resolve each host's own assigned credential first, falling back to the shared one only when unset. New per-host credential dropdown on each Windows host card.

## 1.84 — 2026-09-04
- Redesign the Dell/BMC server card's component health display as bold color-filled tiles (green/amber/red, one per component with an icon) instead of a row of small text badges — the user asked for something more graphical and spacious, pointing at a PRTG sensor gauge dashboard and a Grafana stat-panel dashboard as references

## 1.83 — 2026-09-04
- Add network (Redfish) health monitoring for HP/HPE (iLO) and Fujitsu (iRMC) servers, alongside Dell — confirmed by the user to have ~3 such servers. Network discovery now registers any Redfish BMC with its detected vendor instead of skipping non-Dell ones; Fujitsu gets a safe default credential attempt (admin/admin) like Dell's root/calvin, HP gets none (iLO5+ has no universal default - a credential must be assigned manually rather than guessed, to avoid an account lockout)
- Add a vendor selector to the Dell/BMC server form and a vendor badge on each server card and in Central's panel
- Local WinRM access (iSM/RACADM/OMSA) stays Dell-only for now - HP/Fujitsu use Redfish over the network exclusively until local tooling for those vendors is confirmed needed

## 1.82 — 2026-09-04
- Add OMSA (OpenManage Server Administrator / "Dell Server Administrator") as a third local Dell health-check method, alongside iSM/RACADM — confirmed live that some servers only have this one installed; its local CLI authenticates via the Windows OS session itself, no separate credential needed
- Broaden the RACADM/OMSA path search with a bounded recursive scan under Dell's Program Files tree, not just the two hardcoded rac5 paths — different OpenManage/iDRAC-tools package versions install to different subfolders
- Add docs/dell-idrac-setup.md — a setup and troubleshooting guide for getting a Dell server's health checks working (which tool to install, how the three local methods differ, how to diagnose "installed but still failing")

## 1.81 — 2026-09-04
- Poll Mikrotik devices for resources/interfaces once an hour instead of every 2 minutes (30x/hour was confirmed excessive), decoupled the same way Linux/Windows already were — the fast 2-minute cycle now only does a cheap DB-only threshold check
- Automatically fetch each router's log every hour and surface new critical/error entries as alert events (agent -> Central -> Telegram), deduped so the same buffered entry never re-fires; previously this only existed as a live, on-demand dashboard view nobody saw unless they had it open
- Stop mislabeling non-Dell Redfish BMCs (HP/Lenovo/Fujitsu etc) as Dell servers during network discovery — detected via the unauthenticated ServiceRoot's Oem key, skipped with a visible note instead of registered with Dell's default credential

## 1.80 — 2026-09-02
- Show the shared "scan everything" panel (CVE + Linux/Windows/Dell discovery + Mikrotik/Cisco refresh) on the Linux, Windows, and Dell Servers pages too, alongside each page's own narrower scan button — previously only on Vulnerabilities/Scanner, so covering the whole network meant clicking several separate buttons across different pages

## 1.79 — 2026-09-02
- Skip virtual machines when discovering local Dell (iDRAC) servers — a VM can never have its own physical iDRAC, so trying iSM/RACADM on one just wasted a WinRM round trip and produced a confusing "not found" note every scan

## 1.78 — 2026-09-01
- Add an "affected_ips" column to the vulnerability CSV export — findings were only ever a bare affected_count number, so opening the export gave no way to tell which machine to go fix

## 1.77 — 2026-09-01
- Add an in-app changelog (Sidebar version footer → "Historia zmian"), sourced from this very file — single source of truth for both the reported agent_version and the UI history

## 1.76 — 2026-09-01
- Let Central force an on-demand iDRAC check per Dell server

## 1.75 — 2026-09-01
- Surface the real iSM/RACADM error instead of a generic "not installed?"

## 1.74 — 2026-08-31
- Surface iDRAC HealthRollup and auto-discover Dell servers

## 1.73 — 2026-08-31
- Add Dell server (iDRAC) hardware health monitoring

## 1.72 — 2026-08-31
- Fix the real remaining fd leak: puresnmp drops its UDP transport on cancellation

## 1.71 — 2026-08-31
- Give Mikrotik binary-API calls a dedicated thread pool, close leaked WinRM sessions

## 1.70 — 2026-08-31
- Page through AnyDesk history import instead of capping at the newest 500 OVH sessions

## 1.69 — 2026-08-29
- Fix Mikrotik CVE coverage gap and consolidate scan triggers into one place

## 1.68 — 2026-08-29
- Add disk/memory/network-interface monitoring for Linux, Windows, and Mikrotik hosts

## 1.67 — 2026-08-28
- Fix file-descriptor leak in Mikrotik binary-API login on bad credentials

## 1.66 — 2026-08-28
- Add domain/host-type detection, per-host service watch, and workstation port monitoring to Windows management

## 1.65 — 2026-08-27
- Clarify the Windows domain-field hint for non-domain-joined hosts

## 1.64 — 2026-08-27
- Point at the real fix for expired-session import failures

## 1.63 — 2026-08-27
- Self-heal an expired Central per-user session in centralRequest()

## 1.62 — 2026-08-27
- Actually merge Central AnyDesk data into the local tab, with a real import

## 1.61 — 2026-08-27
- Bump agent_version for the Central AnyDesk restore

## 1.60 — 2026-08-27
- Merge AnyDesk time tracking into the local trace-based history

## 1.59 — 2026-08-27
- Add local AnyDesk connection history (no REST API needed)

## 1.58 — 2026-08-26
- Fix WinRM domain credentials being rejected when Domain is an FQDN

## 1.57 — 2026-08-26
- Fix phantom-looking tunnel rows: collapse duplicate query-failure placeholders

## 1.56 — 2026-08-26
- Add configuration-hardening (compliance) checks for Linux/Windows/RouterOS

## 1.55 — 2026-08-26
- Add OSV.dev as a free, keyless third CVE source for Linux package audits

## 1.54 — 2026-08-26
- Add heuristic remediation recommendations + per-ScanRange scan schedules

## 1.53 — 2026-08-25
- Move Windows-management enable toggle from env var to a DB setting

## 1.52 — 2026-08-25
- Add standalone software inventory + run-script action on managed hosts

## 1.51 — 2026-08-25
- Add Windows server patch management (Windows Update + restart with reason)

## 1.50 — 2026-08-25
- Surface the Inventory grouping in Central too

## 1.49 — 2026-08-25
- Add an Inventory page grouping every scanned host by type

## 1.48 — 2026-08-25
- Surface why a host visible in Vulnerabilities never becomes a Linux Hosts candidate

## 1.47 — 2026-08-25
- Add live scan progress streaming to the Linux and Vulnerabilities pages

## 1.46 — 2026-08-25
- Add a low-concurrency recheck pass to vuln_scan's port probe too

## 1.45 — 2026-08-25
- Extend single-address probe: scan-range membership + vuln_scan's own isolated probe

## 1.44 — 2026-08-24
- Cache the session secret instead of re-reading it from disk on every request

## 1.43 — 2026-08-24
- Retry vuln_scan's own port probe once too — it never got the earlier fix

## 1.42 — 2026-08-24
- Read the SPA shell into memory instead of FileResponse's stat-then-stream

## 1.41 — 2026-08-24
- Give the network scan its own thread pool instead of starving the shared default one

## 1.40 — 2026-08-24
- Build the frontend to a staging dir and atomically swap it in during self-update

## 1.39 — 2026-08-23
- Add plain-socket comparison to the single-address probe diagnostic

## 1.38 — 2026-08-23
- Add single-address diagnostic probe to the Scanner page

## 1.37 — 2026-08-23
- Add a low-concurrency recheck pass for hosts that looked dead in the main scan burst

## 1.36 — 2026-08-23
- Fix api-ssl cipher incompatibility spamming a router's log every poll

## 1.35 — 2026-08-23
- Retry the liveness check once before declaring a host dead

## 1.34 — 2026-08-23
- Ping devices immediately on startup instead of after the first 5-min sleep

## 1.33 — 2026-08-23
- Fix EoIP-via-SNMP fallback, api-ssl support, Winbox liveness ping, scan speed

## 1.32 — 2026-08-23
- Add EoIP/GRE/VXLAN/IPIP status to tunnel monitoring (e.g. sanmed R1<->R2/R3/R4)

## 1.31 — 2026-08-22
- Fix SNMP fallback misreading printer/switch firmware as a RouterOS version

## 1.30 — 2026-08-22
- Require a confirmed RouterOS version before querying IPsec too

## 1.29 — 2026-08-22
- Only query WireGuard on RouterOS v7+, not every router regardless of support

## 1.28 — 2026-08-22
- Only query real Mikrotik routers for tunnel status, not every credentialed device

## 1.27 — 2026-08-22
- Surface tunnel query failures instead of silently omitting the device

## 1.26 — 2026-08-22
- Bump agent_version to 1.26 for the new tunnel_status snapshot field

## 1.25 — 2026-08-22
- Surface WireGuard/IPsec query errors instead of silently hiding them

## 1.24 — 2026-08-21
- Make Linux tab's "scan network now" actually scan the network

## 1.23 — 2026-08-21
- Fix pip install blocking self-update on agents with Python <3.10

## 1.22 — 2026-08-21
- Monitor WireGuard/IPsec tunnels with Telegram alerts, same as WAN

## 1.21 — 2026-08-21
- Default Linux apt/dnf management to enabled, not opt-in

## 1.20 — 2026-08-21
- Add centralized Linux (apt/dnf) patch management, local tab + Central trigger

## 1.18 — 2026-08-20
- Fix full device enrichment never running on frequently-restarted agents

## 1.17 — 2026-08-20
- Add PHP static analysis for Central's own code to supply-chain scan

## 1.16 — 2026-08-20
- Fix silent pip install failures during self-update, add retry

## 1.15 — 2026-08-20
- Trigger supply-chain scans from Central + view results for all agents

## 1.14 — 2026-08-18
- Add fully autonomous daily self-update (opt-out via env var)

## 1.13 — 2026-08-17
- Add static code analysis (SAST) to the supply-chain scan

## 1.12 — 2026-08-14
- Bundle E2E key into downloaded backup file, auto-detect it on restore

## 1.11 — 2026-08-14
- Add in-app restore from backup (upload + one click, no CLI needed)

## 1.10 — 2026-08-14
- Add asset inventory (owner/criticality + CSV export) and supply-chain scan (pip-audit + npm audit)

## 1.9 — 2026-08-13
- Add agent self-backup / BCP: weekly encrypted DB+key backup to OVH, with restore

## 1.8 — 2026-08-13
- Make firmware compliance % verifiable: expose per-device data source + fetch health

## 1.7 — 2026-08-13
- Add Fernet encryption-key rotation (documented key lifecycle, ISO 27001 A.8.24)

## 1.6 — 2026-08-13
- Add firmware/patch compliance report (% of fleet on approved version)

## 1.5 — 2026-08-13
- Add WAN IP change detection + alert (ISP address change coming up)

## 1.4 — 2026-08-13
- Add vulnerability remediation workflow: status, per-severity SLA, overdue alerts, CSV export

## 1.3 — 2026-08-04
- wip: alerts + edge monitoring

## 1.2 — 2026-05-30
- Add central server integration (OVH PHP+MySQL + agent uplink + viewer)

