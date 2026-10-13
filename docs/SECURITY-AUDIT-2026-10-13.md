# Audyt bezpieczeństwa MikroManager — 2026-10-13

Zakres: agent (FastAPI, `backend/`), frontend (React), przekaźnik Centrali (PHP, `ovh/`). Metoda: przegląd kodu i testy dynamiczne na odizolowanej kopii agenta (automatycznie wszystkie 229 tras bez sesji, manipulacja ciasteczkiem, brute-force MFA, role, nagłówki). Nie testowano produkcji ani zewnętrznych hostów.

## Naprawione w 2.69

| # | Waga | Znalezisko | Naprawa |
|---|------|-----------|---------|
| 1 | Wysoka | `GET /api/scanner/probe?ip=…&credential_id=…`: agent logował się zapisanym hasłem na **dowolny** adres (także z konta tylko-do-odczytu, bo to GET). Pozwalało wyprowadzić hasła routerów na host wybrany przez atakującego i skanować dowolne adresy. | Adres musi być znanym urządzeniem lub leżeć w aktywnym zakresie skanowania; użycie poświadczenia tylko dla admina. |
| 2 | Wysoka | `POST /api/auth/mfa/confirm` bez sesji i bez ograniczenia prób: gdy konfiguracja konta nie została dokończona, 10^6 kodów można przebrać (~100 prób/s) i dostać sesję administratora. | Limit 5 prób / 60 s. |
| 3 | Wysoka | `GET /api/system/uplink/enc-key` zwracał klucz szyfrowania E2E każdemu zalogowanemu, także kontu viewer. | Tylko administrator. |
| 4 | Średnia | CSRF przez nawigację: ciasteczko `SameSite=Lax` jest wysyłane przy przejściu z obcej strony, a skanowanie (`/scanner/run`, `/vuln/scan-stream`, `*-stream`) to GET. | `SameSite=Strict`. |
| 5 | Średnia | Blokada logowania per konto: obcy mógł nieustannie blokować prawdziwego administratora (5 błędnych prób na minutę). | Licznik per (konto, adres źródłowy) + luźny licznik globalny (40 prób / 5 min). |
| 6 | Średnia | Kod TOTP dało się użyć ponownie w oknie ważności (do ~90 s). | Kod jednorazowy. |
| 7 | Średnia | Wylogowanie nie unieważniało ciasteczka (ważne 7 dni). | Unieważnienie tokenu przy wylogowaniu (do restartu agenta). |
| 8 | Średnia | Proxy Centrali: pierwszy host był „przypinany” przez dowolnego zalogowanego i dostawał nagłówek `Authorization`. | Przypiąć host może tylko administrator. |
| 9 | Niska | `/openapi.json`, `/docs`, `/redoc` dostępne bez logowania (pełna mapa API). | Wyłączone (włączenie: `MIKROMANAGER_API_DOCS=1`). |
| 10 | Niska | Brak nagłówków bezpieczeństwa. | CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, `Cache-Control: no-store` dla `/api`. |
| 11 | Niska | `ping` dostawał niewalidowany adres (wstrzyknięcie opcji). | Walidacja `ipaddress`. |
| 12 | Niska | Przywracanie kopii: na Pythonie bez filtra tar fallback rozpakowywał bez zabezpieczeń (path traversal). | Odmowa zamiast fallbacku. |
| 13 | Niska | Webhook w Centrali: `FILTER_VALIDATE_URL` przepuszcza `file://` i `php://` do `file_get_contents`. | Tylko `http(s)://`. |
| 14 | Wysoka (zależność) | axios: znane luki w używanej wersji frontendu. | `npm audit fix` — 0 podatności w zależnościach produkcyjnych. |

Ciasteczko dostaje też `Secure`, gdy żądanie przyszło po HTTPS (także za proxy z `X-Forwarded-Proto`).

## Otwarte — wymagają Twojej decyzji

1. **Brak TLS (średnia/wysoka, zależnie od sieci).** Agent słucha na `0.0.0.0` po zwykłym HTTP: hasło, kod MFA i ciasteczko lecą jawnym tekstem po LAN. Zalecenie: reverse proxy z HTTPS (Caddy/nginx), `MIKROMANAGER_HOST=127.0.0.1`, `MIKROMANAGER_COOKIE_SECURE=1`.
2. **Pierwsze uruchomienie (`/api/auth/setup`)** jest otwarte dla każdego, kto dotrze do agenta, dopóki konto nie istnieje. Zalecenie: nie wystawiać świeżego agenta do sieci przed konfiguracją.
3. **Hasło Centrali w przeglądarce** (`localStorage`/`sessionStorage`, plik `central_proxy.json`): odczytalne przy ewentualnym XSS. Nie znaleziono miejsc XSS (`dangerouslySetInnerHTML` nie występuje), a CSP z poprawki 10 jest dodatkową warstwą.
4. **Klucze w `backend/data/`** (`.key`, `.session_secret`) leżą jako zwykłe pliki — każdy z dostępem do dysku lub kopii zapasowej odszyfruje poświadczenia. Zalecenie: uprawnienia tylko dla konta usługi, szyfrowane kopie.
5. **Rola admin = wykonanie dowolnego skryptu** na zarządzanych hostach (`run_script`) i pełny dostęp do poświadczeń — zamierzone, ale oznacza, że konto admina (sesja 7 dni) to najcenniejszy cel; rozważ krótszy TTL sesji.
6. **Audyt zależności Pythona** nie przeszedł (błąd certyfikatu SSL do pypi.org w tym środowisku). Uruchom `pip-audit -r backend/requirements.txt` na maszynie z działającym dostępem.
7. `Access-Control-Allow-Origin: *` w `ovh/api.php`: uwierzytelnianie jest nagłówkiem, nie ciasteczkiem, więc ryzyko niskie, ale warto zawęzić do domeny przeglądarki.

## Zweryfikowane jako poprawne

Wszystkie 229 tras poza `/api/auth/*` i `/api/health` odrzucają żądanie bez sesji; sfałszowany token (zmieniona rola) → 401; viewer nie wykonuje POST/PUT/DELETE; zapytania SQL są parametryzowane (jedyne `text(f"…")` to stałe nazwy kolumn w migracjach); brak `shell=True`, `eval`, `pickle`; PHP używa `prepare`, `hash_equals` i rzutuje `LIMIT`; porównania sygnatur HMAC są stałoczasowe; serwowanie SPA nie jest podatne na path traversal.
