
"""
A fake HTTP server that captures requests from web scanners and attackers.

Unlike SSH (where the attacker tries to authenticate), the HTTP server captures 
a different type of traffic: automated scans searching for:
  - administration panels (/admin, /wp-admin, /phpmyadmin)
  - accidentally exposed files (/.env, /config.php, /backup.zip)
  - known vulnerable endpoints (/cgi-bin/luci, /actuator/health)
  - path traversal attempts (/../../etc/passwd)

The responses are intentionally generic (404 Not Found or 200 OK with minimal HTML) to avoid revealing that this is a honeypot, while keeping the attacker engaged.

"""



import threading
from flask import Flask, request, Response

# fake responses for common patches searched by attackers
# the goal is to look like a real server
FAKE_RESPONSES = {
    "/": (200, "<html><body><h1>Welcome</h1></body></html>"),
    "/admin": (200, "<html><body><h1>Admin Panel</h1><form><input name='user'/><input name='pass' type='password'/><button>Login</button></form></body></html>"),
    "/wp-admin": (302, ""),           # WordPress redirect
    "/wp-login.php": (200, "<html><body><h1>WordPress Login</h1></body></html>"),
    "/phpmyadmin": (200, "<html><body><h1>phpMyAdmin</h1></body></html>"),
    "/.env": (200, "APP_ENV=production\nDB_PASSWORD=secret123\nAPP_KEY=base64:abc123"),
    "/config.php": (200, "<?php // config ?>"),
    "/login": (200, "<html><body><h1>Login</h1></body></html>"),
    "/shell.php": (200, ""),          # false web shell - looks like it exists
    "/actuator/health": (200, '{"status":"UP"}')
}

DEFAULT_RESPONSE = (404, "<html><body><h1>404 Not Found</h1></body></html>")

class HTTPHoneypot:
    def __init__(self,logger, geo, host: str = "0.0.0.0", port: int=80):
        self.logger = logger
        self.geo = geo
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        """
        Register a single catch-all route that catches any path. We want to capture 
        paths that are not anticipated
        """
        @self.app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
        @self.app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
        def catch_all(path):
            return self._handle_request(path)

    def _handle_request(self,path: str) -> Response:
        # logs the request and returns a plausible response
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        
        # X-Forwarded-For is important on the VPS, where you can have a proxy/load balancer in front, otherwise you would see only the proxy IP, not the attacker IP

        port = request.environ.get("SERVER_PORT", self.port)
        method = request.method
        full_path = "/" + path if path else "/"
        user_agent = request.headers.get("User-Agent", "")
        body = None

        if method in ("POST", "PUT") and request.data:
            try:
                body = request.data.decode("utf-8", errors="ignore")[:500]
                # 500 characters limit ( eg. upload, etc )
            except Exception:
                body = None

        country,city = self.geo.lookup(ip)

        self.logger.log_http_request(
            ip = ip,
            port = int(port),
            method = method,
            path = full_path,
            user_agent = user_agent,
            body = body,
            country = country,
            city = city
        )

        #we search for a specific answer for the requested path
        status, content = FAKE_RESPONSES.get(full_path, DEFAULT_RESPONSE)
        # directly for the WordPress
        if status == 302:
            return Response(status=302, headers={"Location": "/wp-login.php"})
        content_type = "application/json" if content.startswith("{") else "text/html"
        return Response(content,status=status, content_type=content_type)

    def start(self):
        # starts Flash server. Blocking - runs in a separated thread
        print(f"[HTTP] Honeypot listens on {self.host}:{self.port}")

        #use_reloader=False - Flash reloader starts a second process that interferes with out threads
        self.app.run(host=self.host, port=self.port, use_reloader=False, threaded=True)
