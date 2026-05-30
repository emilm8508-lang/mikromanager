# MikroManager OVH Backend

Lekki PHP+MySQL receiver odbierający snapshoty od agentów MikroManagera u klientów
i wystawiający API dla widoku zbiorczego na laptopie.

## Wymagania

- PHP 7.4+ (najlepiej 8.x) z PDO MySQL
- MySQL/MariaDB
- HTTPS (TLS) — OVH oferuje SSL za darmo (Let's Encrypt) lub przez ich panel

## Instalacja

### 1. Stwórz bazę

W panelu OVH → Bazy danych utwórz nową bazę (lub użyj istniejącej). Zapisz:
- nazwę bazy
- użytkownika
- hasło
- host (zwykle `mysqlXX.ovh.net` lub `localhost`)

Wykonaj `schema.sql` przez phpMyAdmin (panel OVH → bazy → Manage).

### 2. Skonfiguruj `config.php`

Edytuj `config.php` i wpisz:
- dane do MySQL
- klucze API per tenant (po 32 znaki losowe — wygeneruj np. `openssl rand -hex 16`)
- hasło dla viewera (laptop)

### 3. Wgraj pliki na hosting

Przez FTP/SFTP wgraj **w katalogu publicznym** (zwykle `www/` lub `public_html/`),
najlepiej w podkatalogu np. `www/mm/`:

```
www/mm/
├── ingest.php
├── api.php
└── config.php          ← NIE wgrywaj jeśli zostawiasz domyślne klucze!
```

`schema.sql` i `README.md` **nie wgrywaj** — to do lokalnego użytku.

### 4. Skonfiguruj agenta (MikroManager u klienta)

W przeglądarce na agencie → **Centralny** → **Konfiguracja uplink**:
- URL: `https://twojadomena.pl/mm/ingest.php`
- Tenant: identyfikator klienta (np. `klient-a`) — musi pasować do klucza w `config.php`
- API key: 32-znakowy klucz z `config.php`
- Interval: 120 (s)

### 5. Skonfiguruj viewer (laptop)

Na laptopie w MikroManager → **Centralny** → **Konfiguracja viewer**:
- URL API: `https://twojadomena.pl/mm/api.php`
- Hasło viewera: z `config.php`

## Struktura danych

- Tabela `tenants` — jeden wiersz per klient, ostatni heartbeat
- Tabela `snapshots` — ostatnie 50 snapshotów per klient (starsze auto-kasowane)

## Bezpieczeństwo

- **Wymuś HTTPS** w `.htaccess`:
  ```apache
  RewriteEngine On
  RewriteCond %{HTTPS} off
  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
  ```
- **Ukryj** `config.php` — w `.htaccess`:
  ```apache
  <Files "config.php">
    Order Allow,Deny
    Deny from all
  </Files>
  ```
- Klucze tenantów są porównywane przez `hash_equals()` (timing-safe)
- Agent może być za NAT — wszystko działa po wychodzącym 443

## Logi i debug

W `ingest.php` możesz odkomentować `error_log()` żeby zobaczyć ruch w logach OVH.
