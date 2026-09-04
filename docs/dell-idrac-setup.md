# Monitorowanie serwerów (iDRAC/iLO/iRMC) — instalacja i rozwiązywanie problemów

Ten dokument opisuje, jak przygotować serwer Dell (a od niedawna też
HP/HPE i Fujitsu — patrz sekcja na końcu), żeby MikroManager mógł
odczytywać jego stan zdrowia (CPU/pamięć/zasilanie/wentylatory/dyski) —
zarówno przez sieć (Redfish), jak i lokalnie przez host Windows/Hyper-V
(na razie tylko dla Dell), gdy BMC nie ma własnego adresu w sieci.

## Dwie zupełnie różne ścieżki dostępu

### 1. Sieciowo — Redfish (zalecane, gdy iDRAC ma własny adres IP)

Jeśli iDRAC ma skonfigurowany, aktywny adres IP w sieci (sprawdź w
**iDRAC Settings → Connectivity → Network Settings → "Active NIC
Interface"** — musi pokazywać coś innego niż "None", z realnym adresem
IP, nie `0.0.0.0`), agent połączy się bezpośrednio przez Redfish (REST
API po HTTPS, port 443). Nic dodatkowego nie trzeba instalować — samo
dodanie serwera w zakładce **Serwery Dell** (albo automatyczne
wykrycie) wystarczy.

Domyślne poświadczenie fabryczne Dell to `root` / `calvin` — używane
automatycznie, jeśli nie przypiszesz własnego poświadczenia.

**Jeśli iDRAC nie ma aktywnego interfejsu sieciowego** (typowy przypadek:
skonfigurowany tylko "Shared LOM"/wewnętrzny port USB-NIC, dostępny tylko
z poziomu samego hosta pod adresem `169.254.x.x` albo przez `idrac.local`)
— Redfish przez sieć **nigdy nie zadziała**, i to jest oczekiwane, nie
błąd. W takim wypadku jedyna droga to metoda lokalna poniżej.

### 2. Lokalnie — przez host Windows/Hyper-V (gdy iDRAC nie ma adresu w sieci)

Agent łączy się przez WinRM do hosta Windows Server działającego NA tym
serwerze Dell, i stamtąd lokalnie odpytuje jedno z trzech możliwych
narzędzi zainstalowanych na tym hoście. Próbowane są **wszystkie trzy po
kolei** (nie trzeba wiedzieć z góry, które jest zainstalowane):

1. **iDRAC Service Module (iSM)** — nowoczesne, lekkie narzędzie Della.
2. **RACADM CLI** — starsze narzędzie wiersza poleceń.
3. **OMSA (OpenManage Server Administrator / "Dell Server Administrator")**
   — najstarsze, najcięższe narzędzie, z własnym interfejsem web (port
   1311).

**Wymaganie wstępne**: w zakładce **Windows** w agencie musi być ustawione
wspólne poświadczenie WinRM (to samo konto administratora Windows co do
zarządzania aktualizacjami) — to NIE jest osobne poświadczenie dla
iDRAC, tylko zwykłe konto administratora tego serwera Windows.

## Co zainstalować

Najprościej zainstalować **iSM** — jest lekkie i najlepiej wspierane:

1. Pobierz "Dell EMC iDRAC Service Module" ze strony Della (Support →
   Drivers & Downloads → wybierz model serwera → kategoria "Systems
   Management").
2. Zainstaluj z domyślnymi opcjami.
3. Sprawdź, że usługa faktycznie działa:
   ```powershell
   Get-Service | Where-Object { $_.DisplayName -like "*iDRAC*" }
   ```
   Powinno pokazać `DSM iDRAC Service Module` ze statusem `Running`.

**Jeśli iSM nie działa poprawnie mimo instalacji** (patrz sekcja
rozwiązywania problemów niżej) — zainstaluj dodatkowo **RACADM** (pakiet
"iDRAC Tools" albo pełne "OpenManage Server Administrator" ze strony
Della) jako alternatywę. Agent i tak spróbuje obu.

**OMSA** zwykle nie trzeba instalować specjalnie — jeśli jest już
obecne na serwerze (starsze wdrożenia), agent go automatycznie wykryje
i użyje bez dodatkowej konfiguracji (uwierzytelnienie przez OMSA lokalnie
to zwykłe konto administratora Windows, nie osobne konto — nie trzeba nic
dodatkowo ustawiać).

## Rozwiązywanie problemów — dlaczego "nie łączy się" mimo instalacji

### Krok 1: sprawdź dokładny błąd w agencie

Na stronie **Serwery Dell**, kliknij "Sprawdź teraz" na danym serwerze
(albo uruchom "Skanuj w poszukiwaniu serwerów Dell") i przeczytaj czerwony
komunikat błędu pod kartą serwera — pokazuje osobno błąd dla iSM, RACADM
i OMSA, np.:

```
iSM: Invalid namespace | RACADM: racadm.exe not found on this host | OMSA: omreport.exe not found on this host
```

To już mówi, które narzędzie w ogóle nie jest zainstalowane (`... not
found on this host`) a które jest zainstalowane, ale coś nie działa
(inny komunikat, np. `Invalid namespace`).

### Krok 2 (jeśli "not found"): sprawdź czy narzędzie faktycznie tam jest

Na samym serwerze Windows (RDP/konsola), sprawdź:

```powershell
# RACADM
Get-Command racadm.exe -ErrorAction SilentlyContinue
Get-ChildItem "C:\Program Files\Dell","C:\Program Files (x86)\Dell" -Filter racadm.exe -Recurse -ErrorAction SilentlyContinue

# OMSA
Get-Command omreport.exe -ErrorAction SilentlyContinue
Get-ChildItem "C:\Program Files\Dell","C:\Program Files (x86)\Dell" -Filter omreport.exe -Recurse -ErrorAction SilentlyContinue
```

Jeśli obie komendy dla danego narzędzia nic nie zwrócą — narzędzie
faktycznie nie jest zainstalowane, trzeba je doinstalować (patrz wyżej).

### Krok 3 (jeśli "Invalid namespace" dla iSM): sprawdź czy usługa faktycznie działa

To był realny, napotkany przypadek — usługa iSM pokazywała się jako
"Running", ale sam dostawca danych WMI nie był poprawnie zarejestrowany
(częściowo nieudana instalacja). Sprawdź:

```powershell
Get-Service | Where-Object { $_.DisplayName -like "*iDRAC*" }
Get-CimInstance -Namespace root\cimv2\DCIM -ClassName DCIM_ComputerSystem -ErrorAction Stop
winmgmt /verifyrepository
```

- Jeśli ostatnia komenda pokaże `Get-CimInstance` z błędem "Invalid
  namespace", a `winmgmt /verifyrepository` pokaże "repository is
  consistent" (czyli to NIE jest uszkodzenie repozytorium WMI) —
  najpewniejsza przyczyna to niedokończona/uszkodzona instalacja iSM.
  **Rozwiązanie: odinstaluj iSM całkowicie i zainstaluj od nowa** (świeży
  instalator ze strony Della).
- Jeśli to nie pomoże, zostań przy RACADM albo OMSA na tym konkretnym
  serwerze — nie ma potrzeby naprawiać wszystkich trzech metod naraz,
  wystarczy że jedna działa.

### Krok 4: WinRM w ogóle nie łączy się (żaden z trzech komunikatów, tylko błąd połączenia)

Sprawdź, że host jest widoczny w zakładce **Windows** w agencie (jeśli
go tam nie ma — sprawdź czy WinRM jest włączony: `winrm quickconfig` na
tym serwerze) i że wspólne poświadczenie w zakładce Windows jest
poprawne (to samo konto, którym normalnie logujesz się/zarządzasz tym
serwerem).

## Serwery innych producentów (HP, Fujitsu — sieciowo)

Agent monitoruje też serwery HP/HPE (iLO) i Fujitsu (iRMC), **ale na razie
wyłącznie sieciowo (Redfish)** — lokalna ścieżka przez WinRM (jak
iSM/RACADM/OMSA dla Della) jeszcze dla nich nie istnieje. Jeśli taki
serwer ma BMC bez własnego adresu w sieci, na razie nie da się go
monitorować (zgłoś to, jeśli tak jest u Ciebie).

Przy dodawaniu serwera (albo po automatycznym wykryciu) wybierz
producenta w polu **"Producent"**:

- **Dell** — domyślne poświadczenie `root`/`calvin` próbowane automatycznie.
- **Fujitsu (iRMC)** — domyślne poświadczenie `admin`/`admin` próbowane
  automatycznie (typowe dla iRMC S4/S5 — jeśli zostało zmienione,
  przypisz własne poświadczenie).
- **HP/HPE (iLO)** — **brak automatycznej próby logowania**. Nowsze iLO
  (5 i wyżej) generują unikalne, losowe hasło per-serwer (widoczne na
  naklejce z tyłu obudowy albo w BIOS-ie) — nie ma jednego uniwersalnego
  hasła do wypróbowania, więc trzeba samodzielnie dodać poświadczenie w
  zakładce Poświadczenia i przypisać je do tego serwera ręcznie.

Wykrywanie sieciowe samo rozpoznaje producenta (przez pole `Oem` w
odpowiedzi Redfish, bez logowania) i pokazuje odznakę producenta przy
każdym serwerze na liście.
