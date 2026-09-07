# Historia zmian MikroManager

Numer wersji agenta (`agent_version`) i krótki opis co zostało dodane, poprawione lub zmienione w każdym wydaniu. Wersja bieżąca to najwyższy numer na górze listy.

## 2.9 — 2026-09-07
- Fix Check_MK "Test connection" always returning 404 - reported live right after the previous entry's error-display fix made the failure visible for the first time. Root cause: the site name gets appended twice when the URL field already includes it (e.g. url="http://host/sanmed/check_mk" + site="sanmed" built the request against ".../sanmed/check_mk/sanmed/check_mk/api/1.0/") - an easy mistake since that full path is exactly what you'd copy from a browser tab open on Checkmk. _base_url() now strips a trailing "/check_mk" and/or "/<site>" from the URL before appending them back, so either input style (bare host, or the full browser URL) resolves to the same correct endpoint.

## 2.8 — 2026-09-07
- Add PRTG and Check_MK connectors (connection settings + a read-only test-connection call for each, polling itself is a later follow-up) - API tokens/secrets encrypted at rest with the same Fernet key already used for credential passwords, folded into the existing key-lifecycle/rotation flow in crypto.py and into agent_backup.py's backup file list. Fix the Save button on both connectors' Central config forms silently failing with no visible error - reported directly ("I try to save a PRTG API key and it doesn't save, no error shown"). Root cause: the save/test mutations had no onError handler at all, so any real failure (bad URL, network error, validation error) was completely invisible in the UI. Added a shared error-message helper (prefers FastAPI's own {"detail": ...} body over the generic axios error) and an inline error message next to the Save button on both panels.

## 2.7 — 2026-09-07
- Add remote restart to Linux hosts, matching the remote restart already available for Windows - reported directly ("I have remote restart from Central for Windows but not Linux"). Same 8-layer pattern as Windows: new LinuxHost.last_restart_at/last_restart_reason columns, linux_manage.restart_host() (shutdown -r +1 "<reason>" - a 1-minute delay so the SSH channel gets a clean exit code back before the connection drops, instead of the connection dying mid-command with a plain reboot/shutdown -r now), a new POST /api/linux/hosts/{id}/restart endpoint, matching request_linux_restart/pending_linux_restarts marker-file actions in ovh/api.php and a drain step in ovh/ingest.php, a linux_restart command branch in uplink.py, and Restart buttons in both the local Linux Hosts page and Central's Linux panel.

## 2.6 — 2026-09-07
- Fix Windows compliance checks (and other WinRM PowerShell calls) getting corrupted by PowerShell's progress stream - reported live (Central Rekomendacje showing raw CLIXML garbage instead of a clean firewall-check result, e.g. "True,True,True #< CLIXML <Objs ..."). A cmdlet's one-time "Preparing modules for first use" message (Write-Progress) was getting serialized by pywinrm and appended directly into stdout, which broke the compliance check's plain-text parsing into a false FAIL despite the real answer being all-True. Added a shared _run_ps_safe() wrapper (services/vuln_scan.py) that prepends $ProgressPreference='SilentlyContinue' to every WinRM PowerShell call, and applied it across all 13 call sites in windows_manage.py, dell_local.py, and vuln_scan.py itself - the same bug class could have silently corrupted any of them, not just this one compliance check.

## 2.5 — 2026-09-07
- Fix Windows hosts never producing any vulnerability findings at all - reported directly ("no Windows vulnerabilities showing"). Root cause: the WinRM host-identification step parsed `systeminfo`'s free-text output looking for the English labels "OS Name:"/"OS Version:" - on any non-English-locale Windows (confirmed: this whole deployment is Polish-locale, where systeminfo prints "Nazwa systemu operacyjnego:"/"Wersja systemu operacyjnego:"), the regex never matched, silently returning nothing. That cascaded into skipping the host from vulnerability scanning ENTIRELY (not just a missed CVE match) - no package inventory collected, no OS-level CVE lookup, and the (correct) credential got cached as "failed" for 30 days. Replaced systeminfo text parsing with a Get-CimInstance Win32_OperatingSystem query - its Version property is a plain locale-independent number regardless of system language. Known remaining gap (separate, smaller issue): Windows installed-software CVE matching still needs a paid Vulners API key, unlike Linux which gets a free OSV.dev equivalent - Windows hosts will now at least get identified and scanned for OS-level CVEs for free, same as Linux/Mikrotik already do.

## 2.4 — 2026-09-07
- Group Central's "Podatnosci" page by device instead of a flat finding list, and add CSV export (Excel-compatible - UTF-8 BOM so Polish diacritics render correctly) - properly quoted/escaped (unlike this app's existing AnydeskSessions CSV export helper, which doesn't quote fields, a real problem here since CVE summaries are free-text prose that routinely contains commas), plus the same OWASP CSV-formula-injection guard.

## 2.3 — 2026-09-07
- Add CRITICAL/HIGH vulnerability findings to Central, as a new "Podatnosci" left-sidebar page - explicitly requested and confirmed as a deliberate tradeoff: the full findings summary stays E2E-encrypted-only (unchanged, still the agent's most sensitive payload), but a new, narrower CRITICAL/HIGH-only cut now also rides the plaintext envelope (vuln_findings_status) so Central can show it without every viewer needing the tenant's key. New vuln_findings_status_all action in ovh/api.php mirrors compliance_status_all exactly. MEDIUM/LOW findings never leave the agent this way - only via the existing encrypted channel for someone who does hold the key.

## 2.2 — 2026-09-07
- Split "Serwery fizyczne" into two separate left-sidebar pages in Central mode instead of one combined view: Dell/iDRAC hardware health stays under "Serwery fizyczne" (a real hardware-health concept), and Linux/Windows OS patch status gets its own new "Serwery Linux/Windows" page - reported directly that these shouldn't be combined, since Linux/Windows hosts aren't necessarily physical machines and patch status is a different concern from hardware health. Removed the old "servers" tab from Central's own tab bar entirely, matching the same left-sidebar promotion already done for Inwentarz/Rekomendacje.

## 2.1 — 2026-09-07
- Give Compliance recommendations their own left-sidebar page in Central mode ("Rekomendacje", /central/compliance), mirroring the existing /central/inventory pattern - the cramped card list buried at the bottom of the Monitoring tab (squeezed alongside Tunele/Lacza WAN/SupplyChain) was reported as unreadable. Redesigned the display too: severity-colored left border per finding, larger readable text (no more monospace/truncated recommendation text), a per-severity count summary, and tenant/severity filters - removed the old embedded panel from the Monitoring tab entirely to avoid showing it twice.

## 2.0 — 2026-09-07
- Surface Compliance recommendations in Central, mirroring the same pattern already used for Tunele/Lacza WAN - the firewall recommendations added last commit were only visible on each agent's own Compliance page. New compliance.py public_summary() (FAILED checks only - actual recommendations to act on, not a full pass/fail report) rides the snapshot's plaintext envelope as compliance_status, a new compliance_status_all action in ovh/api.php mirrors wan_links_status_all/tunnel_status_all exactly, and a new "Rekomendacje - wszyscy klienci" panel in Central's Monitoring tab lists every open recommendation across every tenant with its severity and full recommendation text.

## 1.99 — 2026-09-07
- Add firewall/NAT rule recommendations to the existing Compliance checks for RouterOS - directly requested, with the exact example given (a NAT rule forwarding traffic to an internal server, e.g. sanmed R1): (1) flags a NAT (port forwarding) rule with no corresponding chain=forward filter rule at all - RouterOS's own default with an empty forward chain is accept-everything, so the forwarded service is fully exposed with zero restriction; (2) flags chain=input not ending in an unconditional drop; (3) flags management services (Winbox/API/SSH/etc.) accepted on the WAN interface-list without a restricted src-address, reusing the same "WAN" interface-list signal built for WAN link monitoring. Each finding's detail is a real, actionable recommendation (what to add and why), not just pass/fail - fits the existing Compliance UI/data model directly, so no new page needed. Also fixed the Compliance page truncating long detail text to one line, which would have hidden most of these recommendations.

## 1.98 — 2026-09-07
- Add the same graphical CPU/RAM/disk tile view already used for Dell/iDRAC servers to Windows and Linux hosts, and move all three (Dell/Linux/Windows) into one unified "Serwery fizyczne" tab in Central - previously Linux/Windows patch-status tables lived in the separate Monitoring tab with no visual resource view, so Central couldn't show at a glance whether a Linux/Windows server was actually under load. Linux CPU is estimated from load1/nproc (no extra tooling/sudo needed, unlike mpstat/top); Windows CPU comes from Win32_Processor's average LoadPercentage. Completed and verified a mostly-finished uncommitted feature already sitting in the working tree (new cpu_used_pct column + collection + public_summary() enrichment on both host types, and a new UtilizationTile/HostUtilizationRow component) - the remaining piece was moving the Linux/Windows panels into the physical-servers tab instead of leaving them in general Monitoring.

## 1.97 — 2026-09-05
- Surface the local WAN up/down check in Central, not just on each agent's own Devices page - the user asked directly how to verify WAN links across all tenants from Central, same as the existing "Tunele VPN" cross-tenant panel. New edge_discovery.py public_summary() rides the snapshot's plaintext envelope (wan_link_status, same mechanism as tunnel_status/dell_servers_status), a new wan_links_status_all action in ovh/api.php mirrors tunnel_status_all exactly, and a new "Lacza WAN — wszyscy klienci" panel in Central's Monitoring tab lists every WAN interface across every tenant with its current status - no E2E key needed, checked locally by each agent, not by an external ping.

## 1.96 — 2026-09-05
- Fix WAN badge showing false "down" on switches and access points - reported live (CRS326 switches, wAP access points all showing "WAN nie dziala"). Root cause: the route-based fallback (added two commits ago) treated ANY active default route as a WAN signal, but every device - not just real routers - typically has one, just pointing back to the actual router for its own management traffic; route data alone can't tell a real internet uplink apart from that. Removed the fallback entirely - RouterOS's own "WAN" interface-list (already proven correct on real routers R1/R2) is now the only signal used. A router without an explicit WAN interface-list simply gets no badge, which is honest, not a guess.
- Fix edge_discovery.py never filtering by device vendor - confirmed live, an iDRAC and another non-Mikrotik host were being queried with RouterOS-specific WAN checks and failing every one, cluttering the log with irrelevant errors. Same vendor filter tunnel_monitor.py already had is now applied here too.
- Fix dell_monitor.py crashing its own SEL (event log) persistence with a SQLite UNIQUE constraint error whenever a device's SEL read contained two entries with an identical message+timestamp in the same poll - replaced the select-then-insert check (which couldn't see its own not-yet-flushed row) with a proper INSERT ... ON CONFLICT DO NOTHING upsert.

## 1.95 — 2026-09-05
- Add diagnostic logging to the WAN link scan (edge_discovery.py) - every failure/skip case that previously returned silently (no credential assigned, get_ip_addresses/get_interfaces/get_routes/get_interface_list_members failing, no WAN interface found at all, or a found WAN interface whose running-state couldn't be determined) now prints a specific, traceable reason. Needed because a device reported showing NO WAN badge at all on the Devices page, with no way to tell which of several possible causes was responsible without guessing again.

## 1.94 — 2026-09-05
- Prefer RouterOS's own named "WAN" interface-list membership (Winbox: Interfaces > Interface List) for identifying which interfaces are WAN, when a router defines one - confirmed live on a real multi-WAN router (R1: WAN list containing ether1+ether8, matching exactly what the operator sees in Winbox). This is the operator's own explicit intent rather than an inference, and more reliable than the route-based guess for complex routing setups (PCC/mangle, VRFs) where "which route is currently active" can be ambiguous. Route-based detection (added last commit) is kept as the fallback for routers that don't define a WAN list at all.

## 1.93 — 2026-09-05
- Fix two real causes of the new WAN link check reporting "down" for links that were actually up, reported live (mcprojekt, a router with two separate WAN links): (1) a router's /interface entry can omit the "running" field entirely for some interface types/API paths rather than returning an explicit false - the code was defaulting a missing field to "not running", silently misreporting healthy interfaces as down; now a missing field is correctly treated as unknown (no badge/alert) instead. (2) the previous route-matching only ever returned a SINGLE interface even when a router has multiple simultaneously-active default routes (failover/load-balancing/PCC) - meaning a genuine second WAN link was either never checked, or the wrong one got picked. Now returns every interface backing an active default route, each tracked and alerted independently.

## 1.92 — 2026-09-05
- Fix local WAN up/down detection finding nothing at all for routers behind double-NAT/ISP CGNAT - confirmed live (mcprojekt): a router's WAN-facing interface can hold only a private address (e.g. ether1 = 192.168.0.2, assigned by the ISP's own upstream box), so the previous public-IP-based detection had literally nothing to check there. Now identifies the WAN interface via the active default route's gateway (subnet-matched against each local interface's own address) instead of requiring a public address on it - works identically whether that interface's address is public or private. collect_public_ips() (used for OVH edge-device sync, which genuinely needs a real public address) is unchanged; the new route-based detection is a separate, parallel signal feeding only the local wan_down/wan_up alerts and the Devices page badge. Both come from the same per-device scan, so this adds no extra device polling.

## 1.91 — 2026-09-05
- Add a persistent WAN up/down badge to the Devices page, next to the existing online/offline badge - the local wan_down/wan_up detection added earlier only fired alert events with no way to see current status at a glance. Reads edge_discovery.py's own cached WAN-interface scan (no extra device polling), multi-WAN safe (a device with several public interfaces shows "down" if any one of them is). A device with no known public WAN interface shows no badge at all, rather than a misleading one.

## 1.90 — 2026-09-05
- Fix tunnel_monitor.py scanning Mikrotik devices every ~2 min uplink cycle instead of hourly, and doing so via several separate REST/API round-trips per device (each of WireGuard/IPsec/EoIP/GRE/VXLAN/IPIP independently tries REST then falls back to the binary API on a 404/unsupported endpoint) - reported directly, seen live in a device's own user log as frequent login/logout pairs via multiple methods even when nothing was actually wrong. This module was added after the hourly-scanning fix earlier in this effort (resource_monitor.py's DEVICE_RESOURCE_CHECK_MIN) but never got the same TTL-cache treatment - added the same pattern here (MIKROTIK_TUNNEL_CHECK_MIN, default 60 min), reusing edge_discovery.py's collect_public_ips()-style cached-scan approach.

## 1.89 — 2026-09-05
- Add local WAN link up/down detection (wan_down/wan_up alert events), reading each WAN interface's own "running" flag straight from the router over the LAN (services/edge_discovery.py) instead of relying on an external reachability probe. Motivated by live evidence: several routers' WAN IPs kept failing every external TCP-port check tried from OVH ("connection timed out") because their own firewall correctly blocks all inbound WAN traffic by default - no external prober (OVH or another agent) could ever succeed there, since it's not specific to OVH's IP. Checking locally needs no firewall hole punched on any router and isn't affected by NAT/CGNAT/ISP filtering - a strictly better signal than continuing to fight external probing for sites where that isn't viable.

## 1.88 — 2026-09-05
- Add iDRAC/BMC alert events: wire dell_monitor.py's already-built collect_dell_events() into uplink.py's snapshot (it was computing idrac_health_degraded but never actually being called), and add a second, new transition it didn't have yet - idrac_unreachable/idrac_reachable, firing when a server's health check itself starts/stops failing (BMC unreachable, credential rejected, host powered off), not just when a component's health rating degrades. Both event types are now selectable in Central's alert rules (idrac_unreachable/idrac_reachable were missing from the dropdown even though idrac_health_degraded already had full plumbing) with proper Telegram message formatting instead of the generic fallback text.
- Add an "agent stopped sending data" alert (agent_offline/agent_online), detected server-side on OVH since a dead agent obviously can't self-report its own silence - a new tenant_stale_check_due() in ovh/notifications.php, ticked opportunistically from every incoming ingest request (same no-real-cron trick as edge_check_due()), comparing each tenant's snapshot age against a new agent_offline_threshold_sec (20 min default) distinct from the existing 5-minute display-only badge threshold, debounced via a small state file so it fires once per transition, not every request.

## 1.87 — 2026-09-05
- Fix dell_local.py ignoring a Windows host's own per-host credential override (added in 1.85) and always using the shared credential instead - caught live: a server with OMSA confirmed working (reachable and healthy via its own web UI on port 1311) still failed all three local methods (iSM/RACADM/OMSA) with the identical generic "credentials rejected" error, because the WinRM/NTLM handshake itself was failing on the wrong shared credential before any tool got a chance to run - the per-host override existed but this code path never read it.

## 1.86 — 2026-09-04
- Add a "Serwery fizyczne" tab to Central, showing the same graphical tile view (per-component color-coded health) as the agent's own Dell/BMC page, grouped by tenant with a "Sprawdź teraz" trigger per server - the user asked for the new tile visual to also be available in Central, promoted to its own dedicated tab instead of the old plain compact table it replaces. Extracted the tile components into a shared frontend/src/components/DellHealthTile.tsx so both pages render identically.

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

