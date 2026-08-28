# MikroManager

Aplikacja do zarządzania i monitorowania sieci — urządzenia Mikrotik
(RouterOS v7+, z fallbackiem na starsze wersje i Cisco SB przez SNMP), oraz
serwery Linux i Windows w tej samej sieci. Jeden lokalny agent (Python +
React) na komputerze administratora, z opcjonalnym centralnym widokiem
wielu klientów przez OVH.

## Wymagania

- **Python 3.10+** — backend
- **Node.js 18+** — budowanie frontendu

## Instalacja (jednorazowo)

```powershell
python setup.py
```

Instaluje zależności Python, npm i buduje frontend.

## Uruchamianie

```powershell
# Produkcyjnie (serwuje zbudowany frontend):
python run.py

# Tryb deweloperski (hot reload obu stron):
python run.py --dev
```

Aplikacja otwiera się automatycznie w przeglądarce na `http://localhost:8888` (prod) lub `http://localhost:5173` (dev).

Port można zmienić przez zmienną środowiskową `MIKROMANAGER_PORT` (np. `MIKROMANAGER_PORT=9000 py run.py`) lub przełącznik `--port`.

## Pierwsze kroki

1. **Poświadczenia** → dodaj login/hasło do routerów (i opcjonalnie wspólne
   poświadczenia SSH/WinRM dla hostów Linux/Windows w zakładkach Linux/Windows)
2. **Skaner** → dodaj zakresy CIDR (np. `192.168.1.0/24`) → uruchom skan —
   jeden przycisk uruchamia zarówno wykrywanie urządzeń Mikrotik/Cisco, jak
   i pełny skan podatności + Linux + Windows (patrz niżej)
3. **Urządzenia** → przypisz poświadczenia do wykrytych urządzeń
4. **Mapa sieci** → ułóż topologię przeciągając węzły
5. **Logi** → wybierz urządzenie i kliknij "Start live"

## Funkcje

- **Urządzenia Mikrotik/Cisco** — REST API v7 (z fallbackiem na binary API
  i SNMP dla starszych/ograniczonych urządzeń), interfejsy, adresy, trasy,
  firewall, wireless, DHCP, tunele L2/VPN (WireGuard/IPsec/EoIP/GRE/VXLAN),
  zasoby (CPU/pamięć/dysk), zdalna aktualizacja firmware, backup konfiguracji.
- **Skanowanie sieci** — jeden, wspólny mechanizm: wykrywanie urządzeń
  Mikrotik/Cisco po CIDR, cotygodniowy skan podatności (CVE), odświeżanie
  wersji RouterOS na znanych urządzeniach oraz wykrywanie hostów Linux/
  Windows — wszystko wyzwalane z jednego miejsca (zakładka **Skaner**),
  każde na swoim harmonogramie.
- **Podatności (CVE)** — pasywne wykrywanie wersji usług sieciowych +
  sprawdzenie w NVD/vulners.com/OSV.dev, pełny audyt pakietów dla hostów z
  działającymi poświadczeniami, śledzenie remediacji (status/notatka/SLA).
- **Zarządzanie Linux** (apt/dnf) — wykrywanie hostów, sprawdzanie/instalacja
  aktualizacji, uruchamianie skryptów, monitoring dysku/pamięci.
- **Zarządzanie Windows** (Windows Update) — jak wyżej, plus wykrywanie
  domeny/typu hosta (serwer/stacja robocza), obserwowane usługi (Get-Service),
  lista nietypowych otwartych portów dla stacji roboczych.
- **Monitoring zasobów** — zajętość dysku i pamięci (Linux/Windows/Mikrotik),
  przeciążenia i błędy/drops na interfejsach sieciowych (Mikrotik) — z
  alertami Telegram przy przekroczeniu progu.
- **Zgodność (compliance)** — podstawowe sprawdzenia hardeningu konfiguracji
  (SSH/RDP/firewall/domyślne hasła) dla Linux/Windows/RouterOS.
- **Inwentarz sprzętu i oprogramowania** — zbiorczy widok urządzeń + hostów,
  lista zainstalowanego oprogramowania per host.
- **AnyDesk** — lokalna historia połączeń (z plików trace, bez potrzeby
  płatnego API) do rozliczania czasu pracy u klientów.
- **Centrala (OVH)** — opcjonalny, szyfrowany E2E widok wielu klientów z
  jednego miejsca: alerty, status urządzeń, zdalne komendy (aktualizacja
  firmware/agenta, restart, skan), zarządzanie użytkownikami.
- **Bezpieczeństwo agenta** — logowanie z MFA (TOTP), dziennik audytu akcji,
  automatyczna aktualizacja agenta z git (opcjonalna), szyfrowane
  poświadczenia (Fernet).

## Skaner podatności (CVE)

Cotygodniowy skan całej sieci (bez logowania/exploitów) — wykrywa otwarte
usługi i sprawdza ich wersje w publicznych bazach CVE. Ten sam przebieg
odświeża też wersję RouterOS na znanych urządzeniach (żeby nie polegać
wyłącznie na osobnym, dobowym cyklu odświeżania) i wyzwala wykrywanie
hostów Linux/Windows — patrz `services/vuln_scan.py`. Trzy źródła CVE:

- **NVD** (nvd.nist.gov) — zawsze aktywne, klucz opcjonalny (podnosi limit
  zapytań): `MIKROTIK_NVD_API_KEY`.
- **vulners.com** — opcjonalne, dokładniejsze dopasowanie CVE (przez CPE, nie
  samo wyszukiwanie tekstowe); wymaga darmowej rejestracji na vulners.com i
  klucza API: `MIKROTIK_VULNERS_API_KEY` (puste = pominięte).
- **OSV.dev** (api.osv.dev) — dodatkowe, darmowe źródło dla pakietów
  Debian/Ubuntu, bez klucza API.

Dla hostów, gdzie już działają zapisane poświadczenia (SSH/WinRM), skaner
opcjonalnie idzie głębiej niż sama wersja systemu — pełny audyt
zainstalowanych pakietów/oprogramowania przez `vulners.com` (wymaga
`MIKROTIK_VULNERS_API_KEY`, jak wyżej). Rzadziej niż zwykły cotygodniowy
skan, bo to "cięższa" operacja (potencjalnie tysiące pakietów na raz):
domyślnie raz na 7 dni per host, zmienialne przez
`MIKROTIK_VULN_PACKAGE_AUDIT_DAYS`.

## Monitoring zasobów i sieci

Dysk/pamięć (Linux przez SSH, Windows przez WinRM, Mikrotik przez
`/system/resource`) oraz błędy/przeciążenia interfejsów (Mikrotik) —
`services/resource_monitor.py`. Mikrotik sprawdzany co 2 minuty (razem ze
snapshotem do Centrali), Linux/Windows na osobnym, wolniejszym cyklu
(domyślnie 30 min, `MIKROTIK_RESOURCE_CHECK_MIN`) — SSH/WinRM jest za
"ciężkie" na cykl 2-minutowy. Progi alarmowe (Telegram, z histerezą):

- `MIKROTIK_DISK_ALERT_PCT` (domyślnie 90%)
- `MIKROTIK_MEM_ALERT_PCT` (domyślnie 90%)
- `MIKROTIK_IFACE_ERROR_COOLDOWN_SEC` (domyślnie 1800s) — jak często
  najwyżej może odezwać się alert błędów/drops na tym samym interfejsie
- próg Mbps dla przeciążenia łącza ustawiany ręcznie per urządzenie
  (zakładka Urządzenia → wybrane urządzenie → "Sieć"), domyślnie wyłączony

## Struktura projektu

```
mikrotik/
├── backend/
│   ├── main.py                    # FastAPI app + rejestracja tła (refresher, uplink, skanery...)
│   ├── api/                       # Routery FastAPI — po jednym per obszar (devices, credentials,
│   │   │                          # scanner, vuln_scan, linux_manage, windows_manage, compliance,
│   │   │                          # inventory, anydesk_history, logs, audit, auth, system)
│   ├── services/
│   │   ├── mikrotik_client.py     # RouterOS REST/API/SNMP client (+ cisco_client.py, snmp_client.py)
│   │   ├── scanner.py             # Async wykrywanie urządzeń po CIDR
│   │   ├── vuln_scan.py           # Skan podatności (CVE) — banery + wersje urządzeń, cotygodniowy
│   │   ├── linux_manage.py        # Patch management Linux (apt/dnf) przez SSH
│   │   ├── windows_manage.py      # Patch management Windows (Windows Update) przez WinRM
│   │   ├── resource_monitor.py    # Dysk/pamięć/interfejsy — progi + alerty
│   │   ├── tunnel_monitor.py      # Status tuneli VPN (WireGuard/IPsec/EoIP/GRE/VXLAN)
│   │   ├── compliance.py          # Sprawdzenia hardeningu (Linux/Windows/RouterOS)
│   │   ├── refresher.py           # Cykliczne odświeżanie tożsamości/wersji urządzeń
│   │   ├── firmware.py            # Aktualizacja firmware RouterOS + backup konfiguracji
│   │   ├── anydesk_history.py     # Lokalna historia połączeń AnyDesk (pliki trace)
│   │   ├── uplink.py              # Szyfrowany snapshot do Centrali (OVH)
│   │   ├── updater.py             # Samo-aktualizacja agenta z git
│   │   ├── auth.py / ovh_auth.py  # Logowanie lokalne (MFA) / logowanie kontem OVH
│   │   └── crypto.py              # Szyfrowanie poświadczeń (Fernet)
│   ├── models/database.py         # SQLAlchemy + SQLite (migracje w _migrate_add_columns())
│   └── requirements.txt
├── frontend/src/
│   ├── pages/                     # Dashboard, Devices, Scanner, Vulnerabilities, LinuxHosts,
│   │                              # WindowsHosts, Compliance, Inventory, Software, AnydeskSessions,
│   │                              # NetworkMap, Logs, Credentials, Security, AuditLog, Central*
│   ├── components/                # Sidebar, UI komponenty, RunScriptModal, VulnScanStatusPanel
│   └── lib/api.ts                 # Axios klient API
├── ovh/                           # Opcjonalny backend Centrali (PHP+MySQL na współdzielonym
│   │                              # hostingu) + statyczny podgląd z telefonu (ovh/viewer/)
├── data/                          # SQLite DB + klucz szyfrowania (auto-created)
├── run.py                         # Launcher (z pętlą auto-restartu po self-update)
└── setup.py                       # Instalator
```

## Komunikacja z urządzeniami

- **RouterOS REST API** (port 80/443, `/rest/`) — główna metoda dla ROS v7
- **Mikrotik API** (port 8728/8729) — fallback via `librouteros`
- **SNMP v2c** — fallback dla starszych/ograniczonych urządzeń oraz Cisco SB
- **SSH** (paramiko) — Linux (apt/dnf, dysk/pamięć) oraz identyfikacja/audyt
  pakietów na dowolnym hoście z otwartym portem 22
- **WinRM** (pywinrm) — Windows (Windows Update, usługi, dysk/pamięć)
- Logi: SSE stream, bez składowania lokalnie
