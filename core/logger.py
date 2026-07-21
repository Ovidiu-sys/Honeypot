
"""
Structured JSON logging for all honeypot events.
Simultaneously writes to:
  - console (for live monitoring while connected to the VPS)
  - file (honeypot.log, for auditing and as a backup independent of SQLite)
  - SQLite database (via core/db.py, for analytical queries)

Why JSON instead of plain text:
Just like with the firewall, a JSON log can be directly ingested by a SIEM
(such as Splunk or ELK) or processed by any analysis tool without relying
on fragile regex-based parsing.

"""


import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .db import Database

LOG_PATH = Path(__file__).resolve().parent.parent / "data" / "honeypot.log"


def _now() -> str:
    # timestamp ISO 8601 in UTC - standard format for security logs
    return datetime.now(timezone.utc).isoformat()

class HoneypotLogger:
    def __init__(self, db: Database, log_path: str=None, also_print: bool=True):
        self.db = db
        self.log_path = log_path or str(LOG_PATH)
        self.also_print = also_print

        self._file_logger = logging.getLogger("honeypot")
        self._file_logger.setLevel(logging.INFO)
        if not self._file_logger.handlers:
            handler = logging.FileHandler(self.log_path)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._file_logger.addHandler(handler)

    def _write(self, entry: dict):
        #write an event in the JSON file and optionally in the console
        line = json.dumps(entry)
        self._file_logger.info(line)
        if self.also_print:
            ts = entry.get("timestamp","")[:19].replace("T"," ")
            event = entry.get("event","")
            ip = entry.get("ip", "")
            detail=""
            if event == "ssh_attempt":
                detail = f"{entry.get('username')}:{entry.get('password')}"
            elif event == "ssh_command":
                detail = f"$ {entry.get('command')}"
            elif event == "http_request":
                detai = f"{entry.get('method')} {entry.get('path')}"
            location = ""
            if entry.get("country"):
                location = f"[{entry['country']}]"
            print(f"[{ts}] {event:<15} {ip}{location} {detail}")

    def log_ssh_attempt(self, ip: str,port: int, username: str, password: str,country: str=None, city: str=None) -> int:
        #logs a SSH authentication attempt
        timestamp = _now()
        entry = {
            "timestamp": timestamp,
            "event": "ssh_attempt",
            "ip": ip,
            "port": port,
            "username": username,
            "password": password,
            "country": country,
            "city": city,
        }
        self._write(entry)
        return self.db.log_ssh_attempt(timestamp,ip,port,username,password,country,city)

    def log_ssh_command(self,attempt_id: int, ip: str, command: str, country: str=None):
        # logs a command runned in the fake shell
        timestamp = _now()
        entry = {
            "timestamp": timestamp,
            "event": "ssh_command",
            "ip": ip,
            "attemp_id": attempt_id,
            "command": command,
            "country": country
        }
        self._write(entry)
        self.db.log_ssh_command(attempt_id, timestamp, command)

    def log_http_request(self,ip:str,port: int, method: str,path: str,
                         user_agent: str=None, body:str=None, country: str=None,
                         city:str=None):
        # logs an HTTP request captured
        timestamp = _now()
        entry = {
            "timestamp": timestamp,
            "event": "http_request",
            "ip": ip,
            "port": port,
            "method": method,
            "path": path,
            "user_agent": user_agent,
            "body": body,
            "country": country,
            "city": city
        }
        self._write(entry)
        self.db.log_http_request(
            timestamp, ip, port, method, path, user_agent, body, country, city
         )
