# Plan: prawdziwe, kompletne i wyjaśnialne dane (etapy 1–8)

Rozpoznanie z 14.11.2026, na kodzie (3.57) i danych produkcyjnych z Centrali (narzędzia MCP).

## Gdzie co jest

| Obszar | Pliki |
|---|---|
| Podatności: skan, banery, NVD, cache, remediacja | `backend/services/vuln_scan.py` (2270 l.), `nvd_central.py`, `ovh/nvd.php`, `exploit_intel.py` (KEV/EPSS), `vuln_sla.py` |
| Wersja i producent urządzeń | `services/scanner.py` (SNMP sysObjectID/sysDescr, porty 8291/8728, WebFig), `snmp_client.py`, `refresher.py` (dzienna aktualizacja przez API/REST/SNMP) |
| Inwentarz, typy, deduplikacja | `assets.py`, `asset_merge.py`, `host_identity.py`, `device_class.py`, `oui.py`, `asset_lifecycle.py` |
| Dostępność, pokrycie źródeł | `availability.py` (pole `root`), `coverage.py`, `escalation.py`, `alerts.py` |
| Logi routerów | `syslog_receiver.py`, `host_logs.py`, `soc_rules.py` |
| NetFlow | `netflow.py` (kierunek: wyższy port = inicjator; wyjątki `beacon_ignore_ports`) |
| SOC, ryzyko, ML | `soc.py`, `soc_risk.py`, `anomaly.py`, `tls_scan.py` |
| Serwery | `windows_manage.py`, `linux_manage.py`, `dell_monitor.py`, `idrac_client.py`, `dell_local.py` |
| Centrala i MCP | `ovh/api.php`, `ovh/mcp.php`, `ovh/ingest.php`; agent wysyła stan w `services/uplink.py` |
| Migracje | `models/database.py` → `_migrate_add_columns` (ALTER TABLE ADD COLUMN z wartościami domyślnymi) |
| Testy | brak zestawu i brak pytest → `backend/tests/` na `unittest` (biblioteka standardowa) |

## Przyczyny potwierdzone na danych

- **Fałszywe CVE RouterOS (etap 1).** `vuln_scan._nvd_query_live_sync` szuka CPE słowem kluczowym; gdy NVD nie zna CPE dla tej wersji (7.25.1), bierze **pierwsze** CPE z listy (starą wersję) i przepisuje wszystkie jego CVE. Zakresów wersji nikt nie sprawdza, a `nvd_central.cve_object` odrzuca `configurations`. Skutek w Centrali: CVE-2018-14847 i CVE-2018-7445 (KEV, CVSS 9.8) na 27 urządzeniach u mcprojekt, psb i sanmed, w tym na 7.25.1 i 7.24.4.
- **Błędny produkt (etap 1/2).** `hosts_with_findings` i `_device_version_pair` traktują każdą wersję urządzenia z `vendor == "mikrotik"` jako RouterOS. SwOS ma ten sam numer firmy w SNMP (14988), więc switche CSS dostają „RouterOS 2.16–2.21”. Drukarki Brother („BRN…”, wersje 1.03 i 1.37) i urządzenie „ET0021B73C433C” (2.6.18) też są oznaczone jako mikrotik.
- **`null` w `client_risk` (etap 8).** Czyszczenie w `ovh/mcp.php` (`mcp_clean`) ucina dane poniżej 7. poziomu zagłębienia, a identyfikatory czynników ryzyka leżą na 8. To błąd konektora z 3.57, nie samego wyniku ryzyka.

## Etapy, pliki, schemat, ryzyka

1. **Dopasowanie podatności**
   - nowy moduł `services/vuln_match.py`: porównywarka wersji, zakresy CPE, tożsamość produktu (RouterOS, SwOS albo nieznany, z źródłem i pewnością);
   - `vuln_scan.py`: zapytanie NVD przez `virtualMatchString` z wersją, filtr zakresów, pola `confidence` / `match_source` / `fixed_version`, ponowna ocena istniejących wyników, data przeglądu dla `accepted_risk`;
   - `nvd_central.py` i `ovh/nvd.php`: przekazanie `virtualMatchString` i `configurations`;
   - `soc_risk.py`: wyniki `suspected` nie liczą się jako KEV.
   - **Schemat:** `vuln_findings` + `confidence`, `match_source`, `fixed_version`; `vuln_remediations` + `review_by`; `devices` + `os_product`, `os_source`, `os_confidence`.
   - **Ryzyka:** ponowne pobranie z NVD wszystkich par produkt+wersja (dławione, w tle). Dopóki Centrala nie ma nowego `nvd.php`, agent pyta NVD bezpośrednio (wolniej).
2. **Inwentarz:** wersja, kanał, numer seryjny i RouterBOOT z API; deduplikacja po MAC i numerze seryjnym; typ z wielu sygnałów ze źródłem; role interfejsów `wan` / `uplink` / `access`; `criticality` (critical / important / normal / ignore) z podpowiedzią.
   - **Schemat:** pola na `assets` i `devices`.
   - **Ryzyko:** scalanie zmienia identyfikatory zasobów (historia ryzyka, etykiety). Scalanie ma być zapisywane i odwracalne, jak w `asset_merge.py`.
3. **Utrata komunikacji:** oczekiwane źródła per zasób z `last_seen`; stany down / silent / degraded / stale; progi zależne od ważności; histereza; alert o przywróceniu; drzewo zależności (`root`); milczący agent jako alert krytyczny w Centrali.
   - **Schemat:** tabela `asset_sources`.
   - **Ryzyko:** liczba alertów. Wszystko przez jeden otwarty incydent na zasób.
4. **Logi routerów:** kontrola `/system logging action` przez API; parser pól; nowe reguły; korelacja z NetFlow; ASN i znane skanery.
   - **Ryzyko:** ASN bez ciężkich zależności. Wystarczy mała lokalna tabela znanych sieci plus opcjonalne zapytanie whois z cache.
5. **NetFlow:** kierunek przy adresach WAN; wyjątki skanerów z zakresem (źródło, porty, okno, limit hostów); propozycje wyjątków bez automatycznego dodawania; broadcast i protokoły wykrywania urządzeń poza beaconami; kategoria urządzeń prywatnych.
6. **Serwery:** edycja i wygaśnięcie licencji Windows (Evaluation); tabela EOL z datami i źródłem; normalizacja stanów Redfish; prognoza zapełnienia dysków; osobny próg dla `/boot`; wiek oczekującego restartu.
7. **Higiena alertów:** grupowanie certyfikatów per urządzenie i `self_signed_default`; strojenie ML z etykiet; automatyczne zamykanie z powodem; raport jakości.
8. **MCP i API:** naprawa zagłębienia; nowe pola; narzędzia `client_device_logs`, `client_coverage`, `client_data_quality`; stronicowanie.

Izolacja klientów: każdy agent liczy tylko swoje dane, a Centrala filtruje po `allowed_tenants`. Nowe wyjątki i progi są zapisywane na agencie klienta, nie globalnie w Centrali.
