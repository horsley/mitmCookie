from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import database
import uvicorn
import os
import json

app = FastAPI()

# Setup templates
if not os.path.exists("templates"):
    os.makedirs("templates")
templates = Jinja2Templates(directory="templates")

@app.on_event("startup")
def startup_event():
    database.init_db()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    response = templates.TemplateResponse("index.html", {"request": request})
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ========== Domains API ==========

@app.get("/api/domains")
def get_domains():
    return {"domains": database.get_domains()}

@app.post("/api/domains")
async def add_domain(request: Request):
    data = await request.json()
    domain = data.get("domain")
    if domain:
        if domain.startswith("*."):
            domain = domain[2:]
        elif domain.startswith("."):
            domain = domain[1:]
        database.add_domain(domain)
    return {"status": "ok", "domains": database.get_domains()}

@app.delete("/api/domains/{domain}")
def delete_domain(domain: str):
    database.remove_domain(domain)
    return {"status": "ok", "domains": database.get_domains()}

# ========== Config API ==========

@app.get("/api/config")
def get_config():
    username = database.get_config("proxy_username")
    password = database.get_config("proxy_password")
    return {
        "proxy_username": username, 
        "proxy_password_set": bool(password)
    }

@app.post("/api/config")
async def save_config(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    
    if username is not None: 
         database.set_config("proxy_username", username)
    if password is not None:
         database.set_config("proxy_password", password)
         
    return {"status": "ok"}

# ========== Cookies API ==========

@app.get("/api/cookies")
def get_cookies():
    return {"cookies": database.get_cookies()}

@app.delete("/api/cookies")
def clear_cookies():
    database.clear_cookies()
    return {"status": "ok", "cookies": database.get_cookies()}

@app.delete("/api/cookies/{cookie_id}")
def delete_cookie(cookie_id: int):
    database.delete_cookie(cookie_id)
    return {"status": "ok", "cookies": database.get_cookies()}

# ========== Addons API ==========

ADDONS_REGISTRY = {}

def get_addons_registry():
    """Lazy load addon registry to avoid circular imports."""
    global ADDONS_REGISTRY
    if not ADDONS_REGISTRY:
        try:
            from main import ADDONS_REGISTRY as registry
            ADDONS_REGISTRY = registry
        except ImportError:
            pass
    return ADDONS_REGISTRY

@app.get("/api/addons")
def get_addons():
    """Get all addons with their status."""
    registry = get_addons_registry()
    
    db_addons = database.get_addons()
    enabled_map = {a["name"]: a for a in db_addons}
    
    result = []
    for name, addon_class in registry.items():
        instance = addon_class()
        if name in enabled_map:
            db_config = enabled_map[name]
            instance.enabled = db_config["enabled"]
            instance.config = db_config.get("config", {})
        
        result.append(instance.to_dict())
    
    return {"addons": result}

@app.get("/api/addons/{addon_name}")
def get_addon(addon_name: str):
    """Get a specific addon."""
    db_addon = database.get_addon(addon_name)
    if not db_addon:
        return {"error": "Addon not found"}, 404
    return {"addon": db_addon}

@app.post("/api/addons/{addon_name}")
async def save_addon(addon_name: str, request: Request):
    """Save addon configuration."""
    data = await request.json()
    enabled = data.get("enabled", False)
    config = data.get("config", {})
    
    database.save_addon(addon_name, enabled, config)
    return {"status": "ok", "addon": database.get_addon(addon_name)}

@app.delete("/api/addons/{addon_name}")
def delete_addon(addon_name: str):
    """Reset addon to default."""
    database.delete_addon(addon_name)
    return {"status": "ok"}

def run_server(host="0.0.0.0", port=8081):
    uvicorn.run(app, host=host, port=port)
