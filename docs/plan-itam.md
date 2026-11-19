# Plan: zarządzanie zasobami IT (ITAM) w zakładce Zasoby, etapy A–F

Plan powstał 19.11.2026 na kodzie 3.88 (e67e760). Punktem wyjścia jest sześć kart funkcji z zestawu ITAM, które pokazał użytkownik:
- IT Asset Management;
- CMDB;
- licencje (SAM);
- zamówienia i umowy;
- raporty;
- aplikacja mobilna.

Bez chmury: wszystko działa w agencie i w Centrali.

## Co już jest

| Karta | Jest | Brakuje |
|---|---|---|
| Cykl życia zasobu | Stany wpisu: `probably_removed`, `decommissioned`, `replaced_by`, `ignore` (3.76). Historia zmian `asset_history` (3.74). Cykl życia **systemu operacyjnego** (`asset_lifecycle.py`). | Etapów sprzętu od zakupu do utylizacji. Dat: zakup, gwarancja, planowana wymiana. Kosztu, dostawcy, faktury i miejsca powstawania kosztów. |
| Wykrywanie sprzętu i oprogramowania | Inwentarz z ARP/DHCP, skanów WMI/SSH/SNMP i Hyper-V. Oprogramowanie z hostów (`VulnPackage`, strona Oprogramowanie). | Nic (zostaje). |
| Szczegóły zasobu | Karta hosta, historia, podatności, oprogramowanie, logowania. | Zakładek: cykl życia, relacje, licencje, umowy. |
| CMDB | Topologia: port przełącznika, AP, VM na hoście Hyper-V (`topology_map`). Usługi biznesowe (`business_services`). | Klas CI (karta mówi o ~50 typach, my mamy 7 typów). Jawnych relacji między zasobami. Widoku wpływu „co padnie, gdy padnie X” i przyczyny „od czego zależy X”. |
| Licencje (SAM) | Lista zainstalowanego oprogramowania. | Licencji (produkt, liczba stanowisk, wygaśnięcie, koszt). Zgodności: zainstalowane a kupione. Licencji niewykorzystanych. Wykresów. |
| Zamówienia i umowy | Nic. | Dostawców, umów (z załącznikami i powiadomieniem przed końcem), zamówień (prosty obieg: szkic → zatwierdzone → zamówione → przyjęte). |
| Raporty | Raporty Word do konkretnych rzeczy (hostmon, DRP, dowody NIS2/ISO). | Raportów zasobów (gotowych i własnych z filtrami). Harmonogramu z wysyłką e-mail (agent nie ma dziś poczty). |
| Aplikacja mobilna | Strona „Na miejscu” (`OnSite`) dla telefonu, tylko do odczytu. | Numeru inwentarzowego i etykiet z kodem QR. Skanowania kodu aparatem telefonu. Szybkiej edycji zasobu z telefonu. Zrobione jako strona WWW (PWA), nie aplikacja natywna. |

## Zasady (jak w poprzednich rundach)

- **Izolacja klientów nienaruszalna.**
- **Schemat bazy tylko przez migracje:** `_migrate_add_columns` dla nowych kolumn, `create_all` dla nowych tabel.
- **Zgodność wsteczna:** API i MCP nie tracą pól. MCP tylko do odczytu, a nowe dane dochodzą do istniejących narzędzi albo jako nowe narzędzia.
- **Niskie wymagania sprzętowe.**
- **Dane osobowe:** właściciel zasobu i użytkownik licencji to dane osobowe. W Centrali są widoczne tylko dla administratora, tak jak logowania.
- **Załączniki:** tylko PDF, obrazy i dokumenty biurowe, do 10 MB każdy. Trzymane w `data/attachments/` i nigdy nie wykonywane.
- **Po każdym etapie:** testy regresji, tsc, CHANGELOG, commit i push.

## Etap A (3.89): cykl życia sprzętu i finanse

- **Nowe kolumny `Asset`:**
  - etap cyklu życia: `ordered | in_stock | deployed | in_repair | retired | disposed` (puste = `deployed`, dla zgodności);
  - daty: `purchased_at`, `warranty_until`, `replace_at`, `disposed_at`, plus sposób utylizacji;
  - koszt i waluta, dostawca, numer faktury lub zamówienia, miejsce powstawania kosztów, numer inwentarzowy (`asset_tag`).
- **Zmiana etapu** trafia do `asset_history` (kto, kiedy, z czego na co). Etap „disposed” wymaga daty i sposobu utylizacji. Spójność z istniejącymi stanami: `decommissioned` ↔ `retired` (nie ruszamy logiki 3.76).
- **Alerty:**
  - koniec gwarancji za 30 dni (niski);
  - planowana wymiana minęła (niski).
- **Prognozy:** pozycje „gwarancja” w widoku Prognozy (3.87).
- **Interfejs:** sekcja „Cykl życia i koszty” na stronie zasobu, kolumny i filtry na liście zasobów.
- **Centrala:** edycja tych pól przez `asset_op` (rozszerzenie `set`), liczniki w podsumowaniu zasobów, MCP `client_assets` z nowymi polami.

## Etap B (3.90): CMDB, czyli klasy CI i relacje

- **Klasy CI:** około 45 predefiniowanych klas (`ci_class`), m.in. serwer fizyczny, serwer wirtualny, hipernadzorca, stacja robocza, laptop, router, przełącznik, AP, zapora, UPS, NAS, macierz, drukarka, kamera IP, telefon IP, kontroler domeny, serwer bazy danych, serwer WWW, serwer poczty, aplikacja, usługa biznesowa i inne. Klasa jest proponowana z wykrytego typu, roli i usług. Operator może ją zmienić.
- **Jawne relacje (nowa tabela `ci_relation`):** `runs_on`, `depends_on`, `connected_to`, `backs_up`, `member_of`, `uses_license`, `covered_by_contract`.
- **Relacje automatyczne** z tego, co już wiemy: port przełącznika lub AP (`connected_to`), VM na hoście (`runs_on`), członkostwo w usłudze biznesowej (`member_of`). Są oznaczone jako automatyczne i nie da się ich usunąć ręcznie, ale da się je ukryć.
- **Wpływ:** przechodnio, co zależy od X (do 4 poziomów). **Przyczyna:** od czego zależy X. Na alercie SOC widać „dotyczy też” i „może wynikać z”.
- **Interfejs:** zakładka „Relacje” na stronie zasobu (lista i prosty graf), strona CMDB (klasy, liczby, wyszukiwanie).
- **Centrala i MCP:** klasy i relacje w danych zasobu, nowe narzędzie MCP `client_cmdb` (tylko odczyt).

## Etap C (3.91): licencje oprogramowania (SAM)

- **Nowa tabela `software_license`:**
  - produkt, producent i wzorzec dopasowania do nazw zainstalowanego oprogramowania;
  - typ (na urządzenie / na użytkownika / na serwer / na rdzeń / witryna), liczba stanowisk;
  - daty od–do, koszt, dostawca, klucz (zaszyfrowany, widoczny tylko dla administratora), powiązane umowy i zamówienia (etap D).
- **Zgodność** z oprogramowania na hostach:
  - instalacje ponad liczbę stanowisk (niezgodność);
  - stanowiska niewykorzystane;
  - instalacje na zasobach wycofanych lub nieżywych od 30 dni (do odzyskania);
  - licencja wygasła lub wygasa.
- **Alerty:**
  - niezgodność (średni);
  - wygasanie za 30 dni (niski).
- **Interfejs:** strona Licencje z wykresami (wykorzystanie stanowisk, zgodność), szczegóły licencji z listą instalacji, sugestie produktów z listy oprogramowania.
- **Centrala i MCP:** podsumowanie zgodności (bez kluczy), MCP `client_licenses`.

## Etap D (3.92): dostawcy, umowy i zamówienia

- **Nowe tabele:**
  - `vendor` (nazwa, kontakt);
  - `contract`: rodzaj (wsparcie / serwis / gwarancja / leasing / licencja / SLA), numer, daty, wartość, automatyczne odnowienie, ile dni przed końcem powiadomić, osoba odpowiedzialna, powiązane zasoby i licencje;
  - `purchase_order`: numer, dostawca, pozycje, kwota, status `draft → approved → ordered → received | cancelled`, kto i kiedy zmienił;
  - `attachment` dla umów i zamówień.
- **Przyjęcie zamówienia** może utworzyć zasoby w etapie `in_stock` (z kosztem, dostawcą i datą zakupu) albo przypisać stanowiska do licencji.
- **Powiadomienia:**
  - przed końcem umowy alert SOC i zdarzenie do Centrali `contract_expiring`, z regułą Centrali jak dla innych zdarzeń;
  - w widoku Prognozy pozycje „umowa”.
- **Interfejs:** strony Umowy, Zamówienia i Dostawcy w menu Zasoby, zakładka „Umowy” na stronie zasobu.
- **Centrala:** podsumowanie (umowy kończące się w 60 dni, otwarte zamówienia), MCP `client_contracts`.

## Etap E (3.93): raporty

- **Raporty gotowe:**
  - rejestr zasobów;
  - gwarancje kończące się;
  - zasoby do wymiany;
  - koszty według miejsca powstawania kosztów i roku;
  - zgodność licencji;
  - umowy kończące się;
  - otwarte zamówienia;
  - zasoby zutylizowane;
  - oprogramowanie według produktu.
- **Raport własny:** zakres (zasoby / licencje / umowy), filtry (typ, klasa CI, etap, lokalizacja, właściciel, daty) i kolumny. Raport własny można zapisać.
- **Formaty:** CSV, XLSX i PDF/Word (Word jak w innych raportach).
- **Harmonogram:**
  - dzienny, tygodniowy lub miesięczny, wysyłany e-mailem;
  - agent dostaje ustawienia SMTP (serwer, port, TLS, użytkownik, hasło zaszyfrowane, nadawca) i przycisk „wyślij test”;
  - odbiorcy na raport, historia wysyłek.

## Etap F (3.94): zasoby z telefonu

- **Numer inwentarzowy** (z etapu A) i **etykiety z kodem QR** do druku: arkusz A4 lub pojedyncza etykieta. Kod prowadzi do strony zasobu.
- **Mobilna strona zasobu:** wyszukiwanie, skanowanie kodu QR lub kreskowego aparatem (`BarcodeDetector` w przeglądarce, wpisanie ręczne jako zapas), szybka zmiana lokalizacji, właściciela, etapu i notatki, zdjęcie do załączników.
- **PWA:** instalowalna ikona na ekranie telefonu (manifest). Bez trybu offline dla zapisu.
- **Odczyt z Centrali** dla administratora (z linkiem do agenta), bez zmian w modelu uprawnień.
