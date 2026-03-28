"""
Cookie Catcher Addon - Captures cookies from HTTP requests.
"""
from mitmproxy import http
from mitmproxy.proxy import layers
import database
import logging
import base64

from . import BaseAddon

logger = logging.getLogger(__name__)


class CookieCatcherAddon(BaseAddon):
    """Captures cookies from request headers for configured domains."""
    
    name = "cookie_catcher"
    description = "Capture cookies from HTTP requests"
    version = "1.0.0"
    
    def __init__(self):
        super().__init__()
        self.authorized_connections = set()
        self.config = {
            "capture_requests": True,
            "capture_responses": False
        }
    
    def load(self, loader):
        """Called by mitmproxy when addon is loaded."""
        logger.info(f"CookieCatcherAddon loaded with config={self.config} enabled={self.enabled}")
    
    def configure(self, options):
        """Configure addon."""
        pass
    
    def tls_clienthello(self, data: layers.tls.ClientHelloData):
        sni = data.client_hello.sni
        if not sni:
            return

        if not self.is_watched(sni):
            data.ignore_connection = True

    def client_disconnected(self, client):
        if client.id in self.authorized_connections:
            self.authorized_connections.discard(client.id)

    def is_watched(self, host: str) -> bool:
        watched_domains = database.get_domains()
        for d in watched_domains:
            normalized = d
            if normalized.startswith("*."):
                normalized = normalized[2:]
            elif normalized.startswith("."):
                normalized = normalized[1:]

            if host == normalized or host.endswith("." + normalized):
                return True

        return False

    def http_connect(self, flow: http.HTTPFlow):
        if self.authenticate(flow):
            self.authorized_connections.add(flow.client_conn.id)

    def request(self, flow: http.HTTPFlow):
        if flow.client_conn.id in self.authorized_connections:
            pass
        elif self.authenticate(flow):
            self.authorized_connections.add(flow.client_conn.id)
        else:
            return

        self.check_and_process(flow, flow.request, "REQUEST")

    def authenticate(self, flow: http.HTTPFlow) -> bool:
        username = database.get_config("proxy_username")
        password = database.get_config("proxy_password")

        if not username or not password:
            logger.warning("[AUTH] missing proxy credentials in config")
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

        try:
            auth_type, val = auth_header.split(" ", 1)
            if auth_type.lower() != "basic":
                logger.warning(f"[AUTH] unsupported auth type={auth_type}")
                self.send_auth_request(flow)
                return False

            decoded = base64.b64decode(val).decode("utf-8")
            u, p = decoded.split(":", 1)
            if u != username or p != password:
                logger.warning(f"[AUTH] invalid credentials supplied_username={u}")
                self.send_auth_request(flow)
                return False
        except Exception as e:
            logger.exception(f"[AUTH] failed to parse proxy auth header: {e}")
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

    def response(self, flow: http.HTTPFlow):
        host = flow.request.host
        if not self.is_watched(host):
            return

        set_cookie_headers = flow.response.headers.get_all("Set-Cookie") if "Set-Cookie" in flow.response.headers else []
        if set_cookie_headers and "Cookie" not in flow.request.headers:
            logger.info(
                f"[RESPONSE] watched host={host} returned Set-Cookie but request had no Cookie header"
            )

    def check_and_process(self, flow, message, stage):
        host = flow.request.host

        if not self.is_watched(host):
            return

        if not message.cookies:
            return

        cookie_header = message.headers.get("Cookie", "")
        if not cookie_header and "Set-Cookie" in message.headers:
            cookie_header = message.headers.get_all("Set-Cookie")
            cookie_header = "; ".join(cookie_header)

        if not cookie_header:
            items = []
            for k, v in message.cookies.items():
                items.append(f"{k}={v}")
            cookie_header = "; ".join(items)

        if cookie_header:
            database.upsert_cookie(host, cookie_header, cookie_header)
            logger.info(f"[{stage}] Captured cookie for {host}: {cookie_header}")
        else:
            logger.warning(f"[{stage}] message.cookies existed but cookie_header could not be constructed for host={host}")
