from mitmproxy import http
from mitmproxy.proxy import layers
import database
import logging

# ... (CookieCatcher class removed as it was dead code)

import base64

# Let's rewrite the class to be cleaner and verify domain access
class CookieCatcherAddon:
    def __init__(self):
        self.authorized_connections = set()

    def tls_clienthello(self, data: layers.tls.ClientHelloData):
        sni = data.client_hello.sni
        if not sni:
            return
            
        if self.is_watched(sni):
            logging.info(f"Intercepting connection for {sni}")
        else:
            logging.info(f"Ignoring connection for {sni} (not in watchlist)")
            data.ignore_connection = True

    def client_disconnected(self, client):
        # Clean up authorized connection state to prevent memory leak
        if client.id in self.authorized_connections:
            self.authorized_connections.discard(client.id)

    def is_watched(self, host: str) -> bool:
        watched_domains = database.get_domains()
        for d in watched_domains:
            # Normalize domain: strip leading "*." or "."
            if d.startswith("*."):
                d = d[2:]
            elif d.startswith("."):
                d = d[1:]
                
            if host == d or host.endswith("." + d):
                return True
        return False

    def http_connect(self, flow: http.HTTPFlow):
        # Handle HTTPS CONNECT - Enforce Auth
        if self.authenticate(flow):
            # Mark connection as authorized
            self.authorized_connections.add(flow.client_conn.id)
        else:
            # check_and_process not needed for CONNECT
            pass

    def request(self, flow: http.HTTPFlow):
        # Handle plain HTTP - Enforce Auth
        # If connection is already authorized (via CONNECT), skip check
        if flow.client_conn.id in self.authorized_connections:
            pass
        elif self.authenticate(flow):
             # Valid auth on this request. Mark connection authorized for keep-alive?
             # For HTTP/1.1 keep-alive, yes.
             self.authorized_connections.add(flow.client_conn.id)
        else:
             return

        self.check_and_process(flow, flow.request, "REQUEST")

    # Response method removed to ignore response cookies

    def authenticate(self, flow: http.HTTPFlow) -> bool:
        username = database.get_config("proxy_username")
        password = database.get_config("proxy_password")
        
        if not username or not password:
            # Not configured -> Reject traffic
            # "不允许未设置的时候无鉴权直接代理流量"
            # We return 407 to prompt just in case, or 503.
            # Returning 407 without valid creds set means NOTHING will work, which satisfies "not allowed".
            # Can also return 503 "Proxy Config Required".
            flow.response = http.Response.make(
                503, 
                b"Proxy Setup Required: Please configure username/password in Management UI (Port 8081).",
                {"Content-Type": "text/plain"}
            )
            return False

        auth_header = flow.request.headers.get("Proxy-Authorization")
        if not auth_header:
            self.send_auth_request(flow)
            return False
            
        # Verify
        try:
            type, val = auth_header.split(" ", 1)
            if type.lower() != "basic":
                self.send_auth_request(flow)
                return False
                
            decoded = base64.b64decode(val).decode("utf-8")
            u, p = decoded.split(":", 1)
            if u != username or p != password:
                self.send_auth_request(flow)
                return False
        except Exception:
            self.send_auth_request(flow)
            return False
            
        return True

    def send_auth_request(self, flow):
        flow.response = http.Response.make(
            407,
            b"Proxy Authentication Required",
            {
                "Proxy-Authenticate": 'Basic realm="MITM Cookie Catcher"',
                "Content-Type": "text/html",
                "Connection": "close"
            }
        )

    def check_and_process(self, flow, message, stage):
        host = flow.request.host
        watched_domains = database.get_domains()
        
        # Logging for debug
        logging.info(f"[{stage}] Checking host: {host} against {watched_domains}")

        if not self.is_watched(host):
            logging.debug(f"[{stage}] Host {host} NOT matched.")
            return

        logging.info(f"[{stage}] Host {host} MATCHED. Checking cookies...")

        # Check for cookies
        # message.cookies is a MultiDict
        if not message.cookies:
            logging.info(f"[{stage}] No cookies found in message.")
            return

        logging.info(f"[{stage}] Cookies detected: {message.cookies}")

        # Format cookies for storage
        cookie_header = message.headers.get("Cookie", "")
        if not cookie_header and "Set-Cookie" in message.headers:
            cookie_header = message.headers.get_all("Set-Cookie") # Set-Cookie can appear multiple times
            cookie_header = "; ".join(cookie_header)

        if not cookie_header:
            # Fallback to reconstructing from parsed cookies if header is missing
            items = []
            for k, v in message.cookies.items():
                items.append(f"{k}={v}")
            cookie_header = "; ".join(items)

        if cookie_header:
            # Upsert
            # Use host as the domain key
            database.upsert_cookie(host, cookie_header, cookie_header)
            logging.info(f"[{stage}] Captured cookie for {host}: {cookie_header}")

addons = [
    CookieCatcherAddon()
]
