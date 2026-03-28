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
        client_id = getattr(getattr(data, 'context', None), 'client', None)
        client_id = getattr(client_id, 'id', 'unknown')

        if not sni:
            logger.info(f"[TLS_CLIENTHELLO] client={client_id} no SNI present")
            return

        watched = database.get_domains()
        matched = self.is_watched(sni)
        logger.info(f"[TLS_CLIENTHELLO] client={client_id} sni={sni} watched={watched} matched={matched}")

        if matched:
            logger.info(f"Intercepting connection for {sni}")
        else:
            logger.info(f"Ignoring connection for {sni} (not in watchlist)")
            data.ignore_connection = True

    def client_disconnected(self, client):
        if client.id in self.authorized_connections:
            logger.info(f"[CLIENT_DISCONNECTED] removing authorized client={client.id}")
            self.authorized_connections.discard(client.id)
        else:
            logger.info(f"[CLIENT_DISCONNECTED] client={client.id} was not in authorized set")

    def is_watched(self, host: str) -> bool:
        watched_domains = database.get_domains()
        for d in watched_domains:
            normalized = d
            if normalized.startswith("*."):
                normalized = normalized[2:]
            elif normalized.startswith("."):
                normalized = normalized[1:]

            if host == normalized or host.endswith("." + normalized):
                logger.info(f"[WATCH_MATCH] host={host} matched_rule={d} normalized_rule={normalized}")
                return True

        logger.info(f"[WATCH_NO_MATCH] host={host} watched_domains={watched_domains}")
        return False

    def http_connect(self, flow: http.HTTPFlow):
        logger.info(
            f"[HTTP_CONNECT] client={flow.client_conn.id} host={flow.request.host} "
            f"port={flow.request.port} method={flow.request.method}"
        )
        if self.authenticate(flow):
            self.authorized_connections.add(flow.client_conn.id)
            logger.info(f"[HTTP_CONNECT] client={flow.client_conn.id} authorized and added to cache")
        else:
            logger.info(f"[HTTP_CONNECT] client={flow.client_conn.id} authentication failed")

    def request(self, flow: http.HTTPFlow):
        logger.info(
            f"[REQUEST_ENTRY] client={flow.client_conn.id} method={flow.request.method} "
            f"host={flow.request.host} path={flow.request.path} "
            f"has_cookie_header={'Cookie' in flow.request.headers}"
        )

        if flow.client_conn.id in self.authorized_connections:
            logger.info(f"[REQUEST_ENTRY] client={flow.client_conn.id} already authorized")
        elif self.authenticate(flow):
            self.authorized_connections.add(flow.client_conn.id)
            logger.info(f"[REQUEST_ENTRY] client={flow.client_conn.id} authorized during request and cached")
        else:
            logger.info(f"[REQUEST_ENTRY] client={flow.client_conn.id} request authentication failed")
            return

        self.check_and_process(flow, flow.request, "REQUEST")

    def authenticate(self, flow: http.HTTPFlow) -> bool:
        username = database.get_config("proxy_username")
        password = database.get_config("proxy_password")

        logger.info(
            f"[AUTH] client={flow.client_conn.id} host={flow.request.host} "
            f"username_configured={bool(username)} password_configured={bool(password)}"
        )

        if not username or not password:
            logger.warning(f"[AUTH] missing proxy credentials in config for client={flow.client_conn.id}")
            flow.response = http.Response.make(
                503,
                b"Proxy Setup Required: Please configure username/password in Management UI (Port 8081).",
                {"Content-Type": "text/plain"}
            )
            return False

        auth_header = flow.request.headers.get("Proxy-Authorization")
        if not auth_header:
            logger.info(f"[AUTH] no Proxy-Authorization header for client={flow.client_conn.id}")
            self.send_auth_request(flow)
            return False

        try:
            type, val = auth_header.split(" ", 1)
            if type.lower() != "basic":
                logger.warning(f"[AUTH] unsupported auth type={type} for client={flow.client_conn.id}")
                self.send_auth_request(flow)
                return False

            decoded = base64.b64decode(val).decode("utf-8")
            u, p = decoded.split(":", 1)
            if u != username or p != password:
                logger.warning(
                    f"[AUTH] invalid credentials for client={flow.client_conn.id} supplied_username={u}"
                )
                self.send_auth_request(flow)
                return False
        except Exception as e:
            logger.exception(f"[AUTH] failed to parse proxy auth header for client={flow.client_conn.id}: {e}")
            self.send_auth_request(flow)
            return False

        logger.info(f"[AUTH] success for client={flow.client_conn.id} username={u}")
        return True

    def send_auth_request(self, flow):
        logger.info(f"[AUTH] sending 407 challenge to client={flow.client_conn.id} host={flow.request.host}")
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
        logger.info(
            f"[RESPONSE] client={flow.client_conn.id} host={host} path={flow.request.path} "
            f"status={flow.response.status_code} set_cookie_count={len(set_cookie_headers)}"
        )
        if set_cookie_headers:
            logger.info(f"[RESPONSE] Set-Cookie headers for host={host}: {set_cookie_headers}")

    def check_and_process(self, flow, message, stage):
        host = flow.request.host
        watched_domains = database.get_domains()

        logger.info(f"[{stage}] Checking host={host} path={flow.request.path} against watched={watched_domains}")

        if not self.is_watched(host):
            logger.info(f"[{stage}] Host {host} NOT matched, skipping cookie processing")
            return

        logger.info(f"[{stage}] Host {host} MATCHED. Checking cookies...")

        request_cookie_header = flow.request.headers.get("Cookie", "")
        response_set_cookie_headers = []
        if getattr(flow, 'response', None) is not None and 'Set-Cookie' in flow.response.headers:
            response_set_cookie_headers = flow.response.headers.get_all("Set-Cookie")

        logger.info(
            f"[{stage}] request_cookie_header_present={bool(request_cookie_header)} "
            f"request_cookie_count={len(message.cookies) if hasattr(message, 'cookies') else 'n/a'} "
            f"response_set_cookie_count={len(response_set_cookie_headers)}"
        )

        if not message.cookies:
            logger.info(f"[{stage}] No cookies found in message.cookies")
            if response_set_cookie_headers:
                logger.info(f"[{stage}] Response Set-Cookie seen but not persisted by current logic: {response_set_cookie_headers}")
            return

        logger.info(f"[{stage}] Cookies detected: {message.cookies}")

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
