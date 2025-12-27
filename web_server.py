from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import database
import uvicorn
import os

app = FastAPI()

# Setup templates
# We will write the template file to templates/index.html
if not os.path.exists("templates"):
    os.makedirs("templates")
templates = Jinja2Templates(directory="templates")

@app.on_event("startup")
def startup_event():
    database.init_db()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    response = templates.TemplateResponse("index.html", {"request": request})
    # Disable caching for the main page so updates are seen immediately
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/api/domains")
def get_domains():
    return {"domains": database.get_domains()}

@app.post("/api/domains")
async def add_domain(request: Request):
    data = await request.json()
    domain = data.get("domain")
    if domain:
        # Normalize domain
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

@app.get("/api/config")
def get_config():
    username = database.get_config("proxy_username")
    # Do not return password for security, or return a mask? 
    # For this tool, returning it or a flag is fine. Let's return mask
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

@app.get("/api/cookies")
def get_cookies():
    # Return cookies
    return {"cookies": database.get_cookies()}

@app.delete("/api/cookies")
def clear_cookies():
    database.clear_cookies()
    return {"status": "ok", "cookies": database.get_cookies()}

@app.delete("/api/cookies/{cookie_id}")
def delete_cookie(cookie_id: int):
    database.delete_cookie(cookie_id)
    return {"status": "ok", "cookies": database.get_cookies()}

def run_server(host="0.0.0.0", port=8081):
    uvicorn.run(app, host=host, port=port)
