# MikroManager

Aplikacja do zarządzania siecią opartą na urządzeniach Mikrotik (RouterOS v7+).

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

1. **Poświadczenia** → dodaj login/hasło do routerów
2. **Skaner** → dodaj zakresy CIDR (np. `192.168.1.0/24`) → Skanuj
3. **Urządzenia** → przypisz poświadczenia do wykrytych urządzeń
4. **Mapa sieci** → ułóż topologię przeciągając węzły
5. **Logi** → wybierz urządzenie i kliknij "Start live"

## Struktura projektu

```
mikrotik/
├── backend/
│   ├── main.py               # FastAPI app
│   ├── api/
│   │   ├── devices.py        # CRUD + dane z urządzeń
│   │   ├── credentials.py    # Zaszyfrowane poświadczenia
│   │   ├── logs.py           # Live SSE stream logów
│   │   └── scanner.py        # Skaner sieci SSE
│   ├── services/
│   │   ├── mikrotik_client.py # RouterOS REST API v7 client
│   │   ├── scanner.py        # Async port scanner
│   │   └── crypto.py         # Szyfrowanie Fernet
│   ├── models/database.py    # SQLAlchemy + SQLite
│   └── requirements.txt
├── frontend/src/
│   ├── pages/                # Dashboard, Devices, Scanner, Logs, Map, Credentials
│   ├── components/           # Sidebar, UI komponenty
│   └── lib/api.ts            # Axios klient API
├── data/                     # SQLite DB + klucz szyfrowania (auto-created)
├── run.py                    # Launcher
└── setup.py                  # Instalator
```

## Komunikacja z urządzeniami

- **RouterOS REST API** (port 80/443, `/rest/`) — główna metoda dla ROS v7
- **Mikrotik API** (port 8728/8729) — fallback via `librouteros`
- Logi: SSE stream, bez składowania lokalnie
