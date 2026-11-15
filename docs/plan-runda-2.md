# Plan: druga runda poprawek (etapy A–E)

Rozpoznanie z 15.11.2026 na kodzie 3.65 (a198a07) i danych z Centrali z 14–15.11.

## Punkt wyjścia: co działa u klientów

Na agentach klientów działa **3.63** (4d18fd7). Wersje 3.64 i 3.65 są w repozytorium, ale nie zostały wdrożone. Część punktów briefu opisuje więc stan sprzed nich:

| Punkt briefu | Co jest już w 3.64 / 3.65 | Co zostaje do zrobienia |
|---|---|---|
| 3.1 certyfikaty | 3.64: jeden alert na urządzenie, `self_signed_default` low, stare alerty per port zamykane | duplikat ALU-SW2: alert raz przypięty do IP, raz do nazwy. Klucz ma być id zasobu, nie nazwa. |
| 3.3 pętla anomalii | 3.64: progi z etykiet per seria i godzina, raport precyzji per reguła i host | precyzja per klient w Centrali; zmierzyć po wdrożeniu |
| 3.4 zamykanie | 3.64: zamykanie alertów podatności, których wynik zniknął; deduplikacja po odcisku (reguła, urządzenie, parametry) już działa | ogólne zamykanie „warunek ustał od X” dla każdej reguły |
| 3.5 `client_device_logs` | 3.65: filtry klient, urządzenie, godziny, temat, rodzaj, ważność, tekst; limit i stronicowanie | nic, poza sprawdzeniem po wdrożeniu |
| 2.4 R1-S3 | 3.65: ponowne sprawdzenie par, na które NVD nie odpowiedział | test „wersja z API wygrywa z banerem” i sprawdzenie po wdrożeniu |

**Wniosek:** najpierw trzeba wdrożyć 3.65 i odczytać liczby. Część etapu 3 może się po tym zamknąć sama.

## Przyczyny błędów z etapu 1 (sprawdzone w kodzie i danych)

| # | Przyczyna |
|---|---|
| 1.1 | Reguła „suspected nie tworzy alertu critical ani KEV w ryzyku” działa (`soc_rules._rule_new_vuln`, `soc_risk`). Wszystkie 7 krytycznych alertów CVE-2026-123158 ma pewność **likely**, nie suspected. Źródło: `hosts_with_findings` daje wynikom z banera `product_confidence="likely"`, a `finding_confidence` zwraca likely, gdy NVD powie „affected”, a dystrybucji nie widać. Tak jest na Windows (psb HYPER-V, OpenSSH 8.6), drukarce (OpenSSH 3.9) i starych banerach bez nazwy dystrybucji (5.2, 7.4, 9.9). Brakuje też warunków środowiska: NVD opisuje je tylko tekstem („on Linux, when musl libc is used without PAM”), a dopasowanie patrzy wyłącznie na wersję. |
| 1.2 | `server_health.py:235` ustawia `reboot_required_since = now`, gdy pierwszy raz zobaczy flagę restartu. Po wdrożeniu 3.63 wszystkie hosty dostały 14.11 ~17:53. |
| 1.3 | „Prywatne” wynikało z zapisanego typu `asset_type == "mobile"`. Ten typ zostaje na adresie po urządzeniu, które miało go wcześniej (np. telefon z tą samą dzierżawą DHCP): nowa nazwa i producent się zapisują, a typ nie, bo nowa ocena wychodzi „other” (`assets.py`: typ zmienia się tylko na inny niż other). Przykłady: psb KSIEGOWOSC (Xerox WorkCentre, typ mobile) i MCPROJEKTPC014 (192.168.1.14, OUI BroadLink). Ani OUI, ani nazwa nie dają tam typu mobile. Poprawione w 3.66: o „prywatnym” decydują sygnały, nie zapisany typ. Sam „lepki” typ zostaje do etapu B (2.3). |
| 1.4 | `netflow.public_summary` liczy `detections_24h` z listy w pamięci (`_detections`). Każdy restart agenta, np. przy wdrożeniu, ją zeruje, a alerty zostają w bazie. Pusty słownik idzie w JSON jako `[]`. |
| 1.5 | `os_name` hosta Windows jest zapisywany tylko przy dodaniu hosta (`windows_manage.py:326/334`) i nigdy nie jest odświeżany. |
| 2.6 | Historia skanów (`_scan_times`) **jest** zapisywana na dysk (`netflow_state.json`); poprawka z etapu A (3.66). Przyczyną braku sugestii jest warunek regularności: `flow_rules.regular` wymagał odchylenia ≤ 0,2 od średniej i jeden opuszczony przebieg (przerwa 12 h przy rytmie 6 h) wystarczał, by go nie spełnić. Nie sprawdzone na danych klientów. |
| 2.3 | Producent i typ: oznaczenie `not_mikrotik` zmienia tylko typ na `other`. Producent „MikroTik” pochodzi z MAC routera, który widać za routerem (L3, proxy-ARP), np. mcprojekt wazuh w lokalizacji swidniczek. Do sprawdzenia na kopii bazy: czy `Device.vendor` puste liczy się jako mikrotik (`(d.vendor or "mikrotik")` w `assets.py`). |
| 2.5 | `iface_roles.role_of`: gdy router nie ma listy WAN, interfejs z domyślną trasą jest uplinkiem. Ale switch czy punkt dostępowy z adresem publicznym albo z ether1 na liście WAN (domyślna konfiguracja) dostaje rolę wan. `wan_links` w dostępności nie sprawdza, czy urządzenie jest routerem brzegowym. Tuneli jako osobnej roli brak. |
| 3.2 | `availability.root` i `comm_watch.cause` liczą się z mapy podłączeń (`attach`). U klientów wychodzą puste. Do ustalenia na kopii bazy, czy brakuje źródła topologii (MAC z mostów i switchy, bramka), czy samej mapy. |
| 3.6 | `host_logs.parse_windows` bierze `IpAddress`, a gdy jest „-”, bierze `WorkstationName`, które też bywa „-”. Nie pobiera LogonType, FailureReason, Status ani SubStatus. |

## Etapy

Każdy etap to osobna wersja z testami regresyjnymi (`backend/tests`, unittest), migracjami z bezpiecznymi wartościami domyślnymi i zgodnym wstecz API/MCP.

### A — 3.66: błędy z pierwszej rundy

- **1.1 Warunki środowiska CVE** (nowy `services/vuln_env.py`):
  - Z opisu i konfiguracji NVD wyciąga warunki: system (Linux, Windows, macOS, BSD), libc (musl, glibc), PAM, konkretna konfiguracja.
  - Środowisko hosta bierze z tego, co agent wie: dystrybucja z `LinuxHost`, host Windows, `OpenSSH_for_Windows` w banerze, typ drukarki lub urządzenia.
  - Warunek wykluczony → wynik zamknięty jako `auto_closed: environment_not_affected` (Ubuntu i Oracle to glibc+PAM, Windows nie jest Linuksem). Warunek niepotwierdzony → najwyżej suspected.
  - Baner pakietu z dystrybucji (OpenSSH, Apache, OpenSSL, nginx, PHP) nigdy nie daje więcej niż suspected. Gdy host ma odczyt pakietów (`match_source=package`), wyniki z banera dla tego produktu są ukryte jako `superseded_by_package` (np. sanmed glpi2, Apache 2.4.52).
  - Ponowne przeliczenie `vuln_reeval` VERSION 2 z liczbami przed i po.
- **1.2 Faktyczny czas oczekującego restartu**:
  - Windows: czas ostatniej zainstalowanej aktualizacji po ostatnim starcie (zdarzenie 19 WindowsUpdateClient albo `Get-HotFix InstalledOn`), gdy klucz RebootRequired lub PendingFileRenameOperations jest ustawiony.
  - Linux: data modyfikacji `/var/run/reboot-required`. Na RHEL/Oracle: czas instalacji najnowszego jądra (`rpm -q --last kernel`), jeśli jest nowsze niż start systemu.
  - Gdy nie da się ustalić: `null` i `reboot_required_since_unknown`.
  - Migracja: czasy wpisane jako czas pierwszego odczytu (14.11 ~17:53) są zerowane do „unknown”.
- **1.3 Urządzenia prywatne**:
  - Prywatne tylko przy sygnale osobistym: OUI telefonu, DHCP vendor class (android-dhcp, iPhone), nazwa w stylu iPhone/Galaxy/Redmi, losowy MAC razem z innym sygnałem.
  - Firmowe ma pierwszeństwo: nazwa według wzorca firmowego (wyprowadzonego z nazw hostów z agentem lub domeną, np. `MCPROJEKTPC\d+`), członkostwo w domenie AD, agent.
  - Przy każdym zasobie widać sygnał, który zdecydował.
- **1.4 i 2.6 NetFlow**:
  - Wykrycia i czasy skanów zapisywane w `data/` (mały JSON, przycięty do 14 dni).
  - `detections_24h` liczone z tego samego źródła co alerty `net.*`.
  - Regularność liczona z mediany przerw, a przerwy będące wielokrotnością rytmu są dopuszczone. Wymagane minimum: 7 dni obserwacji, ≥ 6 przebiegów, powtarzalna lista portów.
  - Sugestia podaje proponowany zakres wyjątku (źródło, porty, rytm) i nigdy nie jest dodawana sama.
- **1.5 Nazwa systemu**: `os_name` odświeżany z `Win32_OperatingSystem.Caption` przy każdym odczycie zasobów. Edycja z licencji ma pierwszeństwo przy wyświetlaniu.

### B — 3.67: inwentarz (2.1, 2.3, 2.5)

- **2.1 Ważność**:
  - Router z WAN i domyślną trasą, który jest jedynym lub głównym wyjściem klienta, dostaje sugestię critical.
  - Kontroler domeny, hypervisor i serwer plików: critical, gdy jest jedyny, w przeciwnym razie important.
  - Ręczne ustawienie przez UI (pole już jest) i plik konfiguracji klienta. W MCP widać `criticality_source: manual | suggested`.
  - Raport „ważne zasoby bez potwierdzonej ważności” (strona i MCP).
- **2.3 Producent i typ**:
  - `not_mikrotik` zmienia producenta (z OUI), typ (np. drukarka po portach lub nazwie BRN…) i system (czyści RouterOS).
  - Producent tylko z OUI własnego MAC urządzenia (nie MAC routera ani proxy-ARP) albo z danych systemu.
- **2.5 Role interfejsów**:
  - WAN to domyślna trasa, adres publiczny albo wpis w `/interface list WAN`, ale tylko na routerze (urządzenie, które routuje: ma domyślną trasę i więcej niż jedną sieć).
  - Adres w podsieci LAN to uplink. EoIP, WireGuard, GRE, IPIP i ovpn dostają rolę `tunnel`.
  - `wan_links` tylko z routerów brzegowych.

### C — 3.68: logi routerów i podatności RouterOS (2.2, 2.4)

- **`not_read` z przyczyną**: brak danych dostępowych, brak uprawnień API (`read` / `policy`), timeout, SwOS bez API, nie jest routerem. Drukarki i SwOS nie są na liście.
- **Podpowiedź konfiguracji**: gotowy skrypt `/system logging action add target=remote remote=<adres agenta>` i `/system logging add topics=…` (system, account, critical, error, warning, firewall jeśli jest logowanie) do skopiowania. Aplikacja niczego nie zmienia na routerze.
- **2.4**: test, że wersja z API ma zawsze pierwszeństwo przed banerem. Sprawdzenie R1-S3 po wdrożeniu 3.65; jeśli nadal ma te CVE, osobna ścieżka zamknięcia.

### D — 3.69: alerty (3.1, 3.2, 3.4, 3.6)

- **3.1**: odcisk alertu TLS po id zasobu (scalenie IP i nazwy). Istniejące duplikaty są scalane.
- **3.2**: mapa zależności z ARP/MAC routerów i switchy, bramki domyślnej, LLDP/MNDP. Pola `root` i `grouped_under` wypełnione, alerty dzieci zgrupowane.
- **3.4**: dla każdej reguły czas „warunek ustał” (np. skan 48 h, beacon 72 h, utrata komunikacji po powrocie). Zamknięcie z powodem `auto: condition gone for N h`.
- **3.6**: z 4625 pobierane IpAddress, WorkstationName, LogonType, FailureReason, Status i SubStatus. Gdy brak IP, korelacja z NetFlow (połączenia SMB, RDP, LDAP do tego hosta w oknie ±2 min).

### E — 3.70: ostatnie logowania na zasobie (etap 4)

- **Tabela `asset_logons` (migracja)**: asset_id, user, domain, logon_type / service, source_ip, source_host, at, ended_at, result, source, is_privileged. Tenant nie jest kolumną: każdy agent to jeden klient, a izolację w Centrali zapewnia `McpContext`.
- **Źródła**:

  | Źródło | Co pobiera | Stan |
  |---|---|---|
  | Windows | 4624 / 4634 / 4647 / 4778 / 4779 / 4625 przez WinRM | rozszerzenie `host_logs`, które już czyta 4625 i 4624 typu 10 |
  | Windows | bieżące sesje: `quser` / `Win32_LoggedOnUser` | nowe |
  | Windows | alerty Wazuha | zapasowe |
  | Kontroler domeny | `lastLogonTimestamp` z oznaczeniem „±14 dni” | nowe |
  | Linux | `last` / `lastlog` / journald sshd | `host_logs` czyta już sshd Accepted/Failed |
  | RouterOS | `/user/active` i logi tematu account | `router_logs` już rozpoznaje login_ok |
  | iDRAC | Redfish Sessions i Lifecycle Log | nowe |

- **Podsumowanie przy zasobie**: last_logon, last_logons (10), active_sessions, distinct_users_30d, last_failed_logon. Gdy danych brak, `null` z powodem: `no_source`, `source_silent` albo `not_supported`.
- **Filtry**: pomijane są konta komputerów (`*$`), SYSTEM, LOCAL/NETWORK SERVICE, DWM-*, UMFD-*, ANONYMOUS LOGON i konto serwisowe MikroManagera. Logowania typu 3 są tylko liczone.
- **Uprzywilejowane**: Domain Admins / Administrators, root, admin, grupa full.
- **Reguły** (włączane i wyłączane per klient):
  - konto uprzywilejowane z nowego adresu lub nowej stacji;
  - logowanie na zasób critical poza godzinami pracy;
  - pierwsze logowanie nowego konta na serwerze lub routerze;
  - wbudowane konto admin lub Administrator;
  - nieudane logowania na nieistniejące konta.
- **RODO**:
  - retencja szczegółów 90 dni, konfigurowalna;
  - podsumowania przechowywane dłużej;
  - dostęp tylko dla roli z uprawnieniem do danych bezpieczeństwa;
  - wpis w dzienniku audytu przy przeglądaniu;
  - nazwy użytkowników escapowane i przycinane.
- **MCP**: `last_logon` i `active_sessions` w `client_assets` oraz nowe narzędzie `client_logons` z filtrami i stronicowaniem. Test izolacji: klient A niewidoczny dla użytkownika klienta B.

## Kolejność i liczby

1. Wdrożenie 3.65 i odczyt liczb (stan „przed”): wyniki CVE, alerty critical, ryzyko, otwarte alerty, routery wysyłające logi, zasoby z danymi o logowaniach.
2. Etapy A → E. Po A obowiązkowe ponowne przeliczenie podatności i ryzyka z liczbami przed i po.
3. Raport końcowy z tymi samymi liczbami po wdrożeniu.

## Przypadki testowe briefu → etap

| Przypadek | Etap |
|---|---|
| OpenSSH 8.9 na Ubuntu 22.04 zamknięty jako environment_not_affected, OpenSSH 9.6 na Alpine dopasowany; OpenSSH na Windows bez CVE linuksowych; suspected bez critical i bez KEV w ryzyku | A |
| Restart oczekujący od 10.11 | A |
| MCPROJEKTPC014 i Redmi | A |
| Skaner co 6 h przez 7 dni i skaner jednorazowy | A |
| RouterOS z API kontra baner | C |
| Router z jedynym wyjściem dostaje critical; drukarka not_mikrotik; uplink switcha nie jest WAN | B |
| Kamera z certyfikatem z 1970 r. | D (już w 3.64; test o duplikacie IP i nazwy) |
| 4624 typu 10 dla jkowalski; DC1$ i konto MikroManagera pominięte; admin z nowego adresu; no_source; izolacja | E |
