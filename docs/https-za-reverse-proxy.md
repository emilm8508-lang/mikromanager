# HTTPS przed agentem MikroManager

Agent mówi po zwykłym HTTP (domyślnie `0.0.0.0:8888`). W sieci lokalnej oznacza to, że hasło, kod MFA i ciasteczko sesji
przechodzą jawnym tekstem. Zalecane ustawienie: agent słucha tylko na `127.0.0.1`, a TLS kończy reverse proxy.

## 1. Agent tylko lokalnie

Zmienne środowiskowe usługi (NSSM / systemd / `run.py`):

| Zmienna | Wartość | Po co |
|---|---|---|
| `MIKROMANAGER_HOST` | `127.0.0.1` | agent niedostępny bezpośrednio z sieci |
| `MIKROMANAGER_PORT` | `8888` (domyślnie) | port, na który kieruje proxy |
| `MIKROMANAGER_COOKIE_SECURE` | `1` | ciasteczko sesji tylko po HTTPS (agent ustawia `Secure` sam, gdy żądanie przyszło po HTTPS lub z `X-Forwarded-Proto: https`) |
| `MIKROMANAGER_SESSION_HOURS` | np. `12` | jak długo ważne jest logowanie (domyślnie 168 h, maks. 720 h) |

## 2. Caddy (najprościej — certyfikat sam)

`Caddyfile`:

```
mikromanager.firma.lan {
    tls internal            # własne CA Caddy; dla domeny publicznej usuń tę linię (Let's Encrypt)
    reverse_proxy 127.0.0.1:8888
}
```

Dla `tls internal` zaimportuj certyfikat główny Caddy (`caddy trust` na serwerze, plik `root.crt` na stacje) do zaufanych
w przeglądarkach administratorów.

## 3. nginx

```
server {
    listen 443 ssl http2;
    server_name mikromanager.firma.lan;
    ssl_certificate     /etc/ssl/mikromanager.crt;
    ssl_certificate_key /etc/ssl/mikromanager.key;

    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_buffering off;            # strumienie SSE (skan, logi na żywo)
        proxy_read_timeout 3600s;
    }
}
server { listen 80; server_name mikromanager.firma.lan; return 301 https://$host$request_uri; }
```

## 4. Uwagi

- Blokada logowania liczy się per adres źródłowy. Uvicorn domyślnie ufa nagłówkom `X-Forwarded-*` od proxy na `127.0.0.1`,
  więc przy proxy na tym samym komputerze agent widzi prawdziwy adres klienta. Proxy na innym komputerze: uruchom agenta z
  `--forwarded-allow-ips=<adres proxy>`.
- Po włączeniu HTTPS wszyscy zalogują się ponownie (inne ciasteczko).
- Sprawdzenie: `curl -sI https://mikromanager.firma.lan/api/health` powinno pokazać nagłówki `Content-Security-Policy`,
  `X-Frame-Options`; a `curl -sI http://<adres-serwera>:8888/api/health` ma przestać odpowiadać z sieci.
