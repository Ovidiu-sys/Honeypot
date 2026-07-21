# Architecture

Technical documentation: module structure, data flow, design decisions,
installation, and usage. For context and motivation, see [README.md](README.md).

---

## Project structure

```
honeypot/
├── core/
│   ├── db.py           # SQLite storage, thread-safe
│   ├── logger.py       # structured JSON logging (console + file + SQLite)
│   └── geo.py          # offline IP geolocation via MaxMind GeoLite2
├── ssh/
│   ├── server.py       # paramiko SSH server — accepts any credentials
│   └── fake_shell.py   # fake Linux shell with plausible command responses
├── http_trap/
│   └── server.py       # Flask catch-all — logs every HTTP request
├── analysis/           # statistics and report generation (in progress)
├── docs/
│   └── class_diagram.mmd   # source for the architecture diagram
├── data/               # honeypot.db + honeypot.log (gitignored)
├── main.py             # entry point: starts both servers in parallel threads
├── requirements.txt
├── .gitignore
├── README.md
├── ARCHITECTURE.md     # this file
└── DEPLOYMENT.md       # step-by-step VPS deployment guide
```

---

## Data flow

```
SSH attacker  →  ssh/server.py   →  core/logger.py  →  honeypot.db
                 ssh/fake_shell                       →  honeypot.log
                      ↕
                 core/geo.py (MaxMind)

HTTP attacker →  http_trap/server.py  →  core/logger.py  →  honeypot.db
                      ↕                                   →  honeypot.log
                 core/geo.py (MaxMind)
```

Both servers run in separate daemon threads started by `main.py`, sharing
the same `Database` and `HoneypotLogger` instances. Thread-safety is
handled by a `threading.Lock` inside `Database`.

---

## Module responsibilities

### `core/db.py`

SQLite storage layer. Creates three tables on first run:

| Table | Contents |
|-------|----------|
| `ssh_attempts` | IP, port, username, password, geolocation, timestamp |
| `ssh_commands` | commands typed in the fake shell, linked to the attempt |
| `http_requests` | IP, method, path, User-Agent, body, geolocation, timestamp |

All write methods acquire a lock before opening a connection, so concurrent
SSH and HTTP events do not corrupt the database.

### `core/logger.py`

Writes every event to three destinations simultaneously:
- **Console** — human-readable, colour-coded by event type (for live monitoring)
- **`honeypot.log`** — one JSON object per line (SIEM-ready)
- **SQLite** — via `core/db.py` (for structured queries during analysis)

### `core/geo.py`

Wraps the MaxMind `geoip2` reader. Returns `(country, city)` for any public
IP, or `(None, None)` if the database file is missing or the IP is private.
Falls back gracefully — geolocation being unavailable does not break logging.

### `ssh/server.py`

Implements `paramiko.ServerInterface` with three key overrides:

- `check_auth_password` — accepts **any** username/password and logs both
- `check_channel_shell_request` — signals that a shell was requested
- `check_channel_pty_request` — accepts PTY requests so interactive clients
  can connect (always returns `True`; terminal dimensions are ignored)

Each incoming connection is handled in a dedicated daemon thread so one
slow attacker does not block others.

### `ssh/fake_shell.py`

Returns plausible responses to common commands (`whoami`, `id`, `uname -a`,
`cat /etc/passwd`, `ps aux`, etc.). Unknown commands return
`bash: <cmd>: command not found`. `wget` and `curl` return a timeout error
to prevent attackers from concluding a download succeeded.

The shell is intentionally imperfect — a careful human attacker would
notice. Automated bots do not check.

### `http_trap/server.py`

A single Flask catch-all route handles every path and HTTP method. Returns
plausible responses for common targets (`.env`, `/wp-admin`, `/admin`,
`/shell.php`) and 404 for everything else.

The directory is named `http_trap` (not `http`) to avoid shadowing
Python's standard library `http` module, which Flask imports internally.

---

## Thread model

```
main thread
├── ssh-honeypot thread  (daemon)  — blocking accept() loop
└── http-honeypot thread (daemon)  — Flask dev server, threaded=True
        └── per-connection thread  — one per SSH client
```

`daemon=True` on both server threads means they are killed automatically
when the main thread exits (Ctrl+C or SIGTERM).

---

## Installation

```bash
pip install -r requirements.txt
```

Download the MaxMind GeoLite2-City database (free, requires registration):
https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Place `GeoLite2-City.mmdb` in the `data/` directory.

---

## Usage

```bash
# local testing (no root required)
python3 main.py --ssh-port 2222 --http-port 8080

# production (on VPS, as root)
python3 main.py

# suppress console output (when running as a systemd service)
python3 main.py --no-print
```

---

## Known limitations

- IP fragmentation is not handled.
- The fake shell does not simulate a stateful filesystem (e.g. `cd` does
  not actually change the working directory shown in the prompt).
- No HTTPS support — port 443 traffic is not captured.
- Flask's development server is used for HTTP. Sufficient for a honeypot
  but not recommended for high-traffic production deployments.
