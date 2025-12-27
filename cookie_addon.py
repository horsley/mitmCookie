from mitmproxy import http
import database
import logging

class CookieCatcher:
    def __init__(self):
        self.domains = set(database.get_domains())

    def load(self, loader):
        logging.info("CookieCatcher addon loaded")
        self.refresh_domains()

    def refresh_domains(self):
        self.domains = set(database.get_domains())

    def request(self, flow: http.HTTPFlow):
        # We also need to capture Request cookies
        self.process_cookies(flow.request, is_response=False)

    def response(self, flow: http.HTTPFlow):
        # And Response cookies (Set-Cookie)
        self.process_cookies(flow.response, is_response=True) 

    def process_cookies(self, message, is_response):
        # Refresh domains periodically or on every request? 
        # For simplicity, let's query DB purely or assume DB updates are infrequent.
        # But to be performant, we might want to cache content.
        # For now, let's fetch from DB to be reactive.
        watched_domains = database.get_domains()
        
        host = ""
        if hasattr(message, "host"):
            host = message.host
        else:
             # In response, flow.request.host is the source
             # but message here is response, which doesn't have host.
             # but flow logic: flow.request.host is the domain.
             pass
        
        # Accessing host from flow in general
        # Flow object handles the context.
        pass

    # Actually better to handle 'request' and 'response' with access to 'flow'
    pass

import base64

# Let's rewrite the class to be cleaner and verify domain access
class CookieCatcherAddon:
    def http_connect(self, flow: http.HTTPFlow):
        # Handle HTTPS CONNECT - Enforce Auth
        if self.authenticate(flow):
            # Mark connection as authorized
            flow.client_conn.metadata["authorized"] = True
        else:
            # check_and_process not needed for CONNECT
            pass

    def request(self, flow: http.HTTPFlow):
        # Handle plain HTTP - Enforce Auth
        # If connection is already authorized (via CONNECT), skip check
        if flow.client_conn.metadata.get("authorized"):
            pass
        elif self.authenticate(flow):
             # Valid auth on this request. Mark connection authorized for keep-alive?
             # For HTTP/1.1 keep-alive, yes.
             flow.client_conn.metadata["authorized"] = True
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
        print(f"[{stage}] Checking host: {host} against {watched_domains}")

        # Check if host matches any watched domain (exact or suffix)
        matched = False
        for d in watched_domains:
            if host == d or host.endswith("." + d):
                matched = True
                break
        
        if not matched:
            print(f"[{stage}] Host {host} NOT matched.")
            return

        print(f"[{stage}] Host {host} MATCHED. Checking cookies...")

        # Check for cookies
        # message.cookies is a MultiDict
        if not message.cookies:
            print(f"[{stage}] No cookies found in message.")
            return

        print(f"[{stage}] Cookies detected: {message.cookies}")

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
            print(f"[{stage}] Captured cookie for {host}: {cookie_header}")
            logging.info(f"Captured cookie for {host}")

addons = [
    CookieCatcherAddon()
]
