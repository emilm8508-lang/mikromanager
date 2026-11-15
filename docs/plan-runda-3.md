# Plan: trzecia runda poprawek (etapy A–E)

Rozpoznanie z 15.11.2026 na kodzie 3.73 (28693c8) i danych z Centrali (klienci na 3.68 lub nowszej).

## Jak dziś działa inwentarz

| Element | Stan |
|---|---|
| Urządzenia MikroTik (`devices`) | Klucz: **adres IP** (`ip` unique). Seryjny, MAC i firmware to zwykłe kolumny. Nowy adres tego samego routera to nowy wiersz; stary zostaje na zawsze. |
| Odczyt wersji / modelu / nazwy / firmware | `refresher.py`: **raz na dobę** (`MIKROTIK_REFRESH_MIN=1440`). Gdy odczyt się nie uda, stare wartości zostają bez daty odczytu. |
| Inwentarz (`assets`) | Klucz rekordu: `ip:<adres>` (monitory `mon:`, drukarki lokalne `prt:`, VM bez IP `vm:<guid>`). Duplikaty są szukane po zarządzanym obiekcie, MAC, numerze seryjnym i nazwie (`asset_merge.py`). Scalanie automatyczne tylko dla obiektu, MAC lub numeru seryjnego. Nazwa jest tylko propozycją. |
| Historia zmian | Brak (tylko zdarzenia SOC i dostępności). |
| Stany wpisu | Brak: wpis jest „aktywny” wg `last_seen` (30 dni) albo znika po ręcznym usunięciu. |
| Logowania API | Od 3.73 jedno logowanie na router na 60 s bezczynności (punkt 4.4 jest już w kodzie, brak tylko pomiaru). Linie logowania konta agenta są pomijane od 3.73. |
| AnyDesk | Jest `anydesk_history.py`: parser `connection_trace.txt` i `ad_svc.trace`, ale tylko dla jednego komputera operatora, wywoływany ręcznie. Wykrywania na hostach klientów nie ma. |

## Przypadek wzorcowy: co się stało (z Centrali)

| | wpis „wAP” | wpis „R2-ĄP1” |
|---|---|---|
| skąd | wiersz `devices` pod .90 | wiersz `devices` pod .94, **z poprzedniego sprzętu** (cAP ac): model, wersja 7.23.1 i nazwa z „Ą” zostały z ostatniego udanego odczytu starego AP |
| dlaczego nie znika | — | `devices` ma klucz IP, a nieudany odczyt (timeout, api-ssl w back-off) nie usuwa wpisu ani nie oznacza go jako martwego |
| wersja | 7.23.2 przy faktycznym 7.25.1: odczyt raz na dobę albo nieudany (do sprawdzenia w logu agenta) | 7.23.1 z dawnego cAP |
| skutki | podatności 7.23.x po dwa razy (po 7 na wpis, `confirmed`) | alerty `rule.new_vuln` 14101–14106 (KEV, critical), alert „Device not answering”, próby połączeń na 33 portach |

Model „cAP ac” nie był zgadywany. To prawdziwy odczyt ze starego sprzętu, który nigdy nie dostał daty ani nie został wycofany. Z tego wynika etap B (data każdego odczytu) i etap C (wycofanie wpisu).

## Źródło „155 tych samych nazw” w sanmed

**143 z 155 to wpisy „HyperVMonitor”**: typ monitor, producent „MSH”, model „062E”, bez IP. To **wirtualne monitory Hyper-V**, które WMI raportuje z wnętrza każdej maszyny wirtualnej jako podpięty monitor. Inwentarz robi z każdego osobny zasób (klucz `mon:a<asset>|<model>|n`).

Do tego przez „HyperV” w nazwie każdy dostaje sugestię ważności „hypervisor” (important). Stąd ok. 60 pozycji „HyperVMonitor” na liście „ważne bez potwierdzenia”.

Pozostałe 12 z 155 do sprawdzenia po poprawce.

## Etapy

### A — 3.74: tożsamość, historia, scalanie

- **Stały klucz w `devices`.** Nowe kolumny (migracja): `serial`, `software_id` (CHR z `/system license`), `mac_physical` (ether1 `orig-mac-address`). `ip` przestaje być kluczem logicznym; zostaje unique w tabeli, a wiersz jest przenoszony na nowy adres.
  - Odczyt przez API: `/system/routerboard`, `/system/license`, `/interface/ethernet` (ether1).
  - Router znaleziony pod nowym IP albo z nową nazwą z tym samym kluczem: aktualizacja wiersza, nie nowy wiersz.
- **Hosty.**
  - Windows: `Win32_ComputerSystemProduct.UUID` w skrypcie zasobów.
  - Linux: `/etc/machine-id`.
  - Zapasowo: MAC.
  - Kolumny w `windows_hosts` / `linux_hosts`.
- **Historia (`asset_history`, nowa tabela):** asset_id, pole, stara wartość, nowa wartość, czas, źródło. Zapisywana przy każdej zmianie nazwy, IP, modelu, wersji, firmware i stanu. W karcie zasobu: „wcześniej: wAP / R2-ĄP1, 192.168.2.94”.
- **Jednorazowe scalanie (`identity_merge`, z liczbami przed i po):**
  - wpisy z tym samym kluczem (seryjny, MAC fizyczny, UUID, machine-id) są scalane;
  - alerty, podatności, historia, ważność i ustawienia ręczne przechodzą na wpis aktualny;
  - stary wpis dostaje `merged_into`;
  - bez klucza: tylko propozycja (ten sam MAC, albo podobna nazwa w tej samej podsieci i jeden wpis od dawna milczy).
- **Nazwy:** porównania po NFC i casefold. Pary różniące się tylko diakrytykami (`R2-ĄP1` / `R2-AP1`) trafiają do raportu jakości danych i nie są scalane na tej podstawie.
- **Model z wiarygodnego źródła:** `/system/routerboard` przez API, a gdy API niedostępne, MNDP z tabeli sąsiadów. Zapisywany `model_source`.
- **Wirtualne monitory:** monitory Hyper-V, RDP i „Generic / Microsoft Basic Display” nie są zasobami. Istniejące wpisy są usuwane migracją z liczbą. Sugestia ważności nie dotyczy typu monitor.
- **Test integracyjny:** przypadek wzorcowy (dwa wiersze `devices`, .90 i .94) daje po scaleniu jeden wpis R2-AP1 / .90 / wAP ax / HM20B0T2CND / 7.25.1 z historią.

### B — 3.75: świeżość i wersje

- **Odczyt w każdym cyklu `resource_monitor`** (przez wspólne logowanie z 3.73): identity, wersja, kanał, model, numer seryjny i firmware. Każde pole dostaje `*_seen_at`. Dobowy `refresher` zostaje dla reszty.
- **Zmiana wersji:**
  - podatności urządzenia są przeliczane;
  - nieaktualne zamykane z powodem `fixed_by_upgrade: <stara> → <nowa>`;
  - zdarzenie „zaktualizowano RouterOS” trafia do historii (dowód łatania).
- **Pewność zależna od świeżości:**

  | Wiek odczytu wersji z API | Pewność |
  |---|---|
  | do 24 h | `confirmed` |
  | 24 h – 7 dni | `likely` |
  | ponad 7 dni | `suspected` z flagą `stale_version` |

  Data odczytu jest widoczna w MCP i UI.
- **MNDP (`/ip neighbor`) z każdego routera:** gdy dane dla danego MAC-a różnią się od inwentarza, wpis jest aktualizowany, jeśli API nie ma świeższych. W przeciwnym razie niezgodność trafia do raportu jakości danych.
- **RouterBOOT:** pola `routerboot_current` i `routerboot_upgrade` (dziś `current_firmware` / `upgrade_firmware` są w `devices`, ale nigdzie nie pokazane). Gdy current < upgrade, alert low z instrukcją `/system routerboard upgrade` i restartem w oknie serwisowym.
- **`not_read`:** przyczyna (rozszerzenie 3.68 / 3.72 o „adres martwy”) i czas ostatniego udanego odczytu.

### C — 3.76: wycofywanie martwych wpisów

- **Stan `probably_removed`:** brak ARP, brak MAC w mostach, brak DHCP i brak pingu przez N dni (domyślnie 7, konfigurowalne). Wtedy:
  - alerty o niedostępności zamieniają się w jedno przypomnienie „potwierdź usunięcie”;
  - podatności nie liczą się do ryzyka;
  - agent sprawdza tylko ARP i ping, raz na godzinę.
- **Ten sam klucz pod innym adresem:** stary wpis od razu dostaje `replaced_by` albo jest scalany.
- **Stany ręczne:** `decommissioned`, `replaced_by`, `ignore` (UI i Central przez `asset_op` z 3.70). Dane kasuje tylko ręczne usunięcie.

### D — 3.77: ruch i konta agenta

- **Kierunek do martwych adresów:** próby do adresu, który nie odpowiada (SYN bez odpowiedzi), liczą się jako ruch do celu. Nie są cechą anomalii celu. Do zbadania, skąd anomalia przypisała ruch „z” .94 (kod `netflow` / `anomaly`).
- **ARP lub ping przed skanem usług i TLS:** bez odpowiedzi nie ma prób usług w tym cyklu.
- **Konfiguracja klienta:** adresy agenta i konta techniczne (dziś: konta z poświadczeń agenta). Konta i adresy agenta:
  - są pomijane w logowaniach i liczone osobno jako „odpytywanie przez MikroManager”;
  - są wyłączone z reguł skanowania i ruchu poziomego w zadeklarowanym zakresie portów i godzin, a przekroczenie zakresu nadal daje alert.
- **Raport kont z pełnymi uprawnieniami:** `/user` + `/user/group` na każdym routerze. Zalecenie: konto `mikromanager` w grupie `read,api,rest-api` z `address=<IP agenta>/32`.
- **Pomiar logowań:** licznik logowań API na router i godzinę (z puli 3.73) trafia do Centrali, co daje liczby „przed i po” do raportu.

### E — 3.78: AnyDesk na hostach

- **Model ogólny `remote_access_tools`** (tabela: asset_id, tool, present, install_type, version, running, service_start, tool_id, unattended, source, seen_at; połączenia w `asset_logons` ze źródłem `anydesk_trace`). Inne narzędzia dochodzą bez migracji.
- **Windows (WinRM, w cyklu zasobów albo raz dziennie):**
  - klucze odinstalowania (64 i 32 bit), usługa `AnyDesk` (stan, typ startu), wersja z pliku `AnyDesk.exe`;
  - procesy `AnyDesk.exe` spoza katalogu instalacji, czyli wersja przenośna;
  - z `system.conf` **tylko** klucz `ad.anynet.id` oraz flaga, czy ustawione jest hasło dostępu nienadzorowanego (sama obecność klucza, nigdy wartość);
  - ostatnie wpisy `connection_trace.txt` (parser z `anydesk_history.py`).
- **Linux (SSH):** `dpkg -s` / `rpm -q anydesk`, `systemctl is-active anydesk`, `ad.anynet.id` z `/etc/anydesk/system.conf`.
- **Sieć:** NetFlow do portu 6568 i domen `*.net.anydesk.com` (gdy nazwa jest rozwiązana) daje `present: unknown, likely (network)`, nigdy `true`.
- **Reguły:**
  - nowa instalacja: medium, a na zasobie important / critical high;
  - wersja przenośna na serwerze: high;
  - dostęp nienadzorowany na serwerze lub zasobie critical: medium;
  - wersja starsza niż minimalna z konfiguracji (domyślnie 8.0.8, do potwierdzenia w źródłach AnyDesk przy implementacji).
- **Raport, MCP i RODO:**
  - raport klienta: serwery i stacje robocze osobno;
  - MCP: `remote_access_tools` w `client_assets`, `q=anydesk`, połączenia w `client_logons`;
  - retencja i dostęp jak przy logowaniach (3.70).

## Przypadki testowe briefu → etap

| Przypadek | Etap |
|---|---|
| 1, 3, 4 (wpis wzorcowy, zmiana identity, zmiana IP), 12 (diakrytyki) | A |
| 2, 5, 6, 7 (fixed_by_upgrade, stale_version, aktualizacja, RouterBOOT) | B |
| 8 (probably_removed) | C |
| 9, 10, 11 (ruch do martwego adresu, konto webshot, jedno logowanie na cykl; 10 i 11 częściowo już w 3.73) | D |
| 13–16 (AnyDesk) | E |
| 17 (izolacja) | każdy etap: dane w bazie agenta danego klienta, w Centrali ten sam filtr klientów co w pozostałych narzędziach MCP |

## Kolejność

Etap A jako pierwszy, bo usuwa źródło fikcyjnych wpisów. B przed C, bo stan `probably_removed` opiera się na datach odczytu.
