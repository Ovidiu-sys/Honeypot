
"""
The entry point of the honeypot. Starts the SSH and HTTP servers
in separate threads and keeps them running until Ctrl+C is pressed.

Usage:
    python3 main.py                         # default ports (22 and 80)
    python3 main.py --ssh-port 2222         # SSH on 2222 (useful for local testing, no root required)
    python3 main.py --ssh-port 2222 --http-port 8080

"""


import argparse
import signal
import sys
import threading

from core.db import Database
from core.logger import HoneypotLogger
from core.geo import GeoLocator
from ssh.server import SSHHoneypot
from http_trap.server import HTTPHoneypot

def parse_args():
    parser = argparse.ArgumentParser(description="SSH + HTTP Honeypot")
    parser.add_argument("--ssh-port", type=int, default= 22, help="Port SSH (default: 22, root access)")
    parser.add_argument("--http-port", type=int, default=80,help="Port HTTP (default: 80, root access)")
    parser.add_argument("--host", default="0.0.0.0",help = "Listening from inteface (default: all)")

    parser.add_argument("--db", default=None, help="The path to the SQLite file (default: all)")

    parser.add_argument("--log", default=None, help = "The path to the log file (default; data/honeypot.db)")
    parser.add_argument("--no-print", action="store_true",help="Don't show the events in the terminal (useful when you run as service)")
    return parser.parse_args()


def main():
    args = parse_args()

    db = Database(args.db)
    logger = HoneypotLogger(db, log_path=args.log, also_print=not args.no_print)
    geo = GeoLocator()

    ssh_honeypot = SSHHoneypot(
        logger = logger, geo=geo,
        host=args.host, port=args.ssh_port
    )
    http_honeypot = HTTPHoneypot(
        logger=logger, geo=geo,
        host=args.host, port=args.http_port
    )

    ssh_thread=threading.Thread(target=ssh_honeypot.start, daemon=True, name="ssh-honeypot")
    http_thread= threading.Thread(target=http_honeypot.start, daemon=True, name="http_honeypot")

    ssh_thread.start()
    http_thread.start()

    print(f"\nActive Honeypot. Ctrl+C for a forced process shutdown")

    def shutdown(sig, frame):
        print("\nStopping Honeypot...")
        ssh_honeypot.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    ssh_thread.join()
    http_thread.join()

if __name__ == "__main__":
    main()
