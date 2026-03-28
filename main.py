import asyncio
import threading
import uvicorn
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from web_server import app
import database
import os
import importlib

import logging
import sys

# Configuration
PROXY_PORT = 8080
WEB_PORT = 8081

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Available addons registry
ADDONS_REGISTRY = {}

def register_addon(name, addon_class):
    """Register an addon in the global registry."""
    ADDONS_REGISTRY[name] = addon_class

def load_addons():
    """Import and register all addons."""
    # Import built-in addons
    from addons.cookie_catcher import CookieCatcherAddon
    from addons.eruda_inject import ErudaInjectAddon
    
    register_addon("cookie_catcher", CookieCatcherAddon)
    register_addon("eruda_inject", ErudaInjectAddon)

# Global addon instances
addon_instances = {}

def start_web_server():
    logging.info(f"Starting Web Management UI at http://localhost:{WEB_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT, log_level="info")

async def start_proxy():
    logging.info(f"Starting Proxy at http://localhost:{PROXY_PORT}")

    onboarding_host = os.environ.get("MITM_ONBOARDING_HOST", "mitm.it")

    conf_dir = "~/.mitmproxy"
    if os.path.exists("/data") and os.path.isdir("/data"):
        conf_dir = "/data/mitmproxy"
        if not os.path.exists(conf_dir):
            os.makedirs(conf_dir)

    opts = options.Options(
        listen_host='0.0.0.0', 
        listen_port=PROXY_PORT,
        confdir=conf_dir
    )
    
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)

    if hasattr(master.options, "onboarding_host"):
        master.options.onboarding_host = onboarding_host
    else:
        logging.warning("onboarding_host option not found in mitmproxy options")

    # Load enabled addons from database
    db_addons = database.get_addons()

    for addon_config in db_addons:
        name = addon_config["name"]
        enabled = addon_config["enabled"]
        config = addon_config.get("config", {})
        
        if name in ADDONS_REGISTRY:
            addon_class = ADDONS_REGISTRY[name]
            instance = addon_class()
            instance.config = config
            instance.enabled = enabled

            if enabled:
                try:
                    master.addons.add(instance)
                    addon_instances[name] = instance
                    logging.info(f"Loaded and enabled addon: {name}")
                except Exception as e:
                    logging.exception(f"Failed to load addon {name}: {e}")
            else:
                logging.info(f"Addon {name} is disabled")
        else:
            logging.warning(f"Unknown addon in database: {name}")

    try:
        await master.run()
    except KeyboardInterrupt:
        master.shutdown()

def reload_addons():
    """Reload addon instances (called when config changes)."""
    # This would require stopping/starting the proxy or dynamic reloading
    # For now, this is a placeholder for hot-reload functionality
    pass

def main():
    database.init_db()

    # Register addons
    load_addons()

    # Start Web Server in a daemon thread
    t = threading.Thread(target=start_web_server)
    t.daemon = True
    t.start()
    
    # Run Proxy in main thread (asyncio)
    try:
        asyncio.run(start_proxy())
    except KeyboardInterrupt:
        print("Stopping...")

if __name__ == "__main__":
    main()
