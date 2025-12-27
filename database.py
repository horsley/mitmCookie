import sqlite3
import os
from datetime import datetime

DB_PATH = "cookies.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Table for watched domains
    c.execute('''CREATE TABLE IF NOT EXISTS domains
                 (domain TEXT PRIMARY KEY)''')
    
    # Table for captured cookies
    c.execute('''CREATE TABLE IF NOT EXISTS cookies
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  domain TEXT,
                  content TEXT,
                  full_cookie_header TEXT,
                  last_updated DATETIME,
                  UNIQUE(domain, content))''')
    
    # Table for system config (proxy_auth)
    c.execute('''CREATE TABLE IF NOT EXISTS config
                 (key TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()
    conn.close()

def set_config(key, value):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
    finally:
        conn.close()

def get_config(key):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT value FROM config WHERE key=?", (key,))
        row = c.fetchone()
        return row[0] if row else None
    finally:
        conn.close()

def add_domain(domain):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?)", (domain,))
        conn.commit()
    finally:
        conn.close()

def get_domains():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT domain FROM domains")
        return [row[0] for row in c.fetchall()]
    finally:
        conn.close()

def remove_domain(domain):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM domains WHERE domain=?", (domain,))
        conn.commit()
    finally:
        conn.close()

def delete_cookie(cookie_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM cookies WHERE id=?", (cookie_id,))
        conn.commit()
    finally:
        conn.close()

def clear_cookies():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM cookies")
        conn.commit()
    finally:
        conn.close()

def upsert_cookie(domain, content, full_header):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now()
    try:
        # Try to insert; if exists (domain, content conflict), update timestamp
        c.execute("""INSERT INTO cookies (domain, content, full_cookie_header, last_updated) 
                     VALUES (?, ?, ?, ?)
                     ON CONFLICT(domain, content) 
                     DO UPDATE SET last_updated=excluded.last_updated, full_cookie_header=excluded.full_cookie_header""",
                  (domain, content, full_header, now))
        conn.commit()
    finally:
        conn.close()

def get_cookies():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM cookies ORDER BY last_updated DESC")
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()
