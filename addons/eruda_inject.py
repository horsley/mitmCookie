"""
Eruda Inject Addon - Injects eruda console into HTML responses for mobile debugging.
"""
from mitmproxy import http
from mitmproxy.proxy import layers
import database
import logging
import re

from . import BaseAddon

logger = logging.getLogger(__name__)


class ErudaInjectAddon(BaseAddon):
    """Injects eruda (mobile debugging console) into HTML responses."""
    
    name = "eruda_inject"
    description = "Inject eruda console into HTML for mobile debugging"
    version = "1.0.0"
    
    # Eruda CDN URLs
    ERUDA_CDN = "https://cdn.jsdelivr.net/npm/eruda@3"
    
    def __init__(self):
        super().__init__()
        self.config = {
            "enabled": True,
            "domains": [],  # Empty means all domains, or specify ["example.com"]
            "insert_position": "beforeend",  # beforeend or afterbegin
            "eruda_version": "3"
        }
    
    def load(self, loader):
        logger.info(f"ErudaInjectAddon loaded")
    
    def configure(self, options):
        pass
    
    def response(self, flow: http.HTTPFlow):
        """Handle HTTP response."""
        # Only process HTML responses
        content_type = flow.response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            return
        
        # Check if domain is allowed
        host = flow.request.host
        if not self.is_allowed(host):
            logger.debug(f"Eruda: Skipping {host} (not in allowed domains)")
            return
        
        # Get response body
        if flow.response.content is None:
            return
        
        try:
            # Decode response (mitmproxy may have compressed it)
            body = flow.response.get_text(strict=False)
            if not body:
                return
            
            # Check if eruda already injected
            if "eruda" in body.lower():
                logger.debug(f"Eruda already injected in {host}{flow.request.path}")
                return
            
            # Inject eruda
            injected_body = self.inject_eruda(body)
            
            if injected_body != body:
                flow.response.set_text(injected_body)
                logger.info(f"Injected eruda into {host}{flow.request.path}")
        
        except Exception as e:
            logger.error(f"Error injecting eruda: {e}")
    
    def is_allowed(self, host: str) -> bool:
        """Check if host is allowed for eruda injection."""
        allowed_domains = self.config.get("domains", [])
        
        # If no domains specified, allow all
        if not allowed_domains:
            return True
        
        for d in allowed_domains:
            if d.startswith("*."):
                d = d[2:]
            if host == d or host.endswith("." + d):
                return True
        
        return False
    
    def inject_eruda(self, html: str) -> str:
        """Inject eruda script into HTML."""
        eruda_version = self.config.get("eruda_version", "3")
        cdn_base = f"https://cdn.jsdelivr.net/npm/eruda@{eruda_version}"
        
        # Eruda initialization script
        eruda_script = f'''{cdn_base}/eruda.min.js"></script>
    <script>eruda.init({{
        tool: ['console', 'elements', 'network', 'storage', 'sources', 'info'],
        useShadowDom: true,
        autoScale: true,
        defaults: {{
            theme: 'Monokai Pro',
            transparency: 0.9
        }}
    }});</script>'''
        
        # Try to inject before </body>
        if "</body>" in html:
            # Find the last </body> tag
            insert_pos = html.rfind("</body>")
            injection = f'    <script src="{eruda_script}\n'
            return html[:insert_pos] + injection + html[insert_pos:]
        
        # Fallback: inject at the end of <head>
        elif "</head>" in html:
            insert_pos = html.rfind("</head>")
            injection = f'    <script src="{eruda_script}\n'
            return html[:insert_pos] + injection + html[insert_pos:]
        
        # Last resort: inject at the beginning
        else:
            injection = f'<script src="{eruda_script}\n'
            return injection + html
