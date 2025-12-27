import asyncio
import threading
import uvicorn
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from cookie_addon import CookieCatcherAddon
from web_server import app
import database
import os

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

def start_web_server():
    # Run uvicorn in a separate thread because it likes to be in control of the loop if using uvicorn.run
    # Or strict asyncio with uvicorn.Server
    print(f"Starting Web Management UI at http://localhost:{WEB_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT, log_level="info")

async def start_proxy():
    print(f"Starting Proxy at http://localhost:{PROXY_PORT}")
    
    onboarding_host = os.environ.get("MITM_ONBOARDING_HOST", "mitm.it")
    print(f"Onboarding host set to: {onboarding_host}")
    
    # Check for persistent configuration directory
    conf_dir = "~/.mitmproxy"
    if os.path.exists("/data") and os.path.isdir("/data"):
        conf_dir = "/data/mitmproxy"
        if not os.path.exists(conf_dir):
            os.makedirs(conf_dir)
        print(f"Using persistent mitmproxy config dir: {conf_dir}")
    
    opts = options.Options(
        listen_host='0.0.0.0', 
        listen_port=PROXY_PORT,
        confdir=conf_dir
    )
    
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    
    # helper for mitmproxy < 6 (not needed here but good practice to check)
    # or just set it directly as we know it's a recent version
    if hasattr(master.options, "onboarding_host"):
        master.options.onboarding_host = onboarding_host
    else:
        # Fallback or log if option doesn't exist
        print("Warning: onboarding_host option not found in mitmproxy options")

    master.addons.add(CookieCatcherAddon())
    
    try:
        await master.run()
    except KeyboardInterrupt:
        master.shutdown()

def main():
    database.init_db()
    
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
