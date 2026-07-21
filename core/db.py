
"""
SQLite database for storing events captured by the honeypot.

SQLite was deliberately chosen over JSON or text files because:
  - It supports queries (e.g., top credentials, IP filtering, time-range filtering).
  - It is persistent and crash-resilient (atomic transactions).
  - It does not require a separate server (self-contained in a single .db file).

Two tables:
  - ssh_attempts: SSH authentication attempts + commands executed in the shell.
  - http_requests: Captured HTTP requests (web scanners, targeted/requested paths).

"""


import sqlite3 
import threading
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "honeypot.db"

class Database:
    def __init__(self,db_path: str = None):
        self.db_path = db_path or str(DB_PATH)
        # lock for thread safety: SSH and HTTP run in separated threads
        # both can write in the database
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self):
        #check_same_thread=False is safe because I used manual lock
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        # creates tables if they're non-existent
        with self._lock:
            conn = self._get_conn()
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ssh_attempts(
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    ip          TEXT NOT NULL,
                    port        INTEGER,
                    username    TEXT,
                    password    TEXT,
                    country     TEXT,
                    city        TEXT,
                    success     INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS ssh_commands(
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    attempt_id  INTEGER REFERENCES ssh_attempts(id),
                    timestamp   TEXT NOT NULL,
                    command     TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS http_requests(
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    ip          TEXT NOT NULL,
                    port        INTEGER,
                    method      TEXT,
                    path        TEXT,
                    user_agent  TEXT,
                    body        TEXT,
                    country     TEXT,
                    city        TEXT
                );
                """
            )
            conn.commit()
            conn.close()

    def log_ssh_attempt(self,timestamp,ip,port,username,password,country=None, city=None) -> None:
        # saves a SSH authentication attempt. Returns the row id
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """
                INSERT INTO ssh_attempts
                (timestamp,ip,port,username,password,country,city)  
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp,ip,port,username,password,country,city)
            )
            attempt_id = cursor.lastrowid
            conn.commit()
            conn.close()
        return attempt_id

    def log_ssh_command(self,attempt_id: int, timestamp: str, command: str):
        # saves a command in the fake shell, related to the ssh attempt
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """
                INSERT INTO ssh_commands
                (attempt_id, timestamp, command)
                VALUES (?,?,?)
                """,
                (attempt_id, timestamp, command)
            )
            conn.commit()
            conn.close()

    def log_http_request(self,timestamp, ip, port,method,path,user_agent=None, body=None, country=None, city=None):
        #saves an HTTP request captured
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """
                INSERT INTO http_requests
                (timestamp,ip,port,method,path,user_agent,body, country, city)
                VALUES (?, ? , ?, ? , ? , ? , ? , ? , ? )
                """,
                (timestamp,ip,port,method,path,user_agent,body,country,city)
            )
            conn.commit()
            conn.close()

    def query(self,sql: str, params: tuple = ()):
        #generic query, for the analysis script
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute(sql, params).fetchall()
            conn.close()
        return rows
