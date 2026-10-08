"""
DarkWatch Local Test Lab Database Module (Revised Architecture)
Manages local SQLite database (data/local_lab/local_lab.db) for the 5 controlled services.
"""

import os
import sqlite3
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from werkzeug.security import generate_password_hash, check_password_hash

def get_db_path() -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    db_dir = os.path.join(base_dir, "data", "local_lab")
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, "local_lab.db")

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TEXT NOT NULL
    )
    """)
    
    # 2. Threads Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id TEXT NOT NULL,
        network_path TEXT NOT NULL,
        title TEXT NOT NULL,
        author_handle TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    
    # 3. Posts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id INTEGER NOT NULL,
        service_id TEXT NOT NULL,
        network_path TEXT NOT NULL,
        author_handle TEXT NOT NULL,
        text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        synthetic INTEGER DEFAULT 1,
        FOREIGN KEY (thread_id) REFERENCES threads(id)
    )
    """)
    
    # 4. Observations Table (Background Data Layer)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        observation_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        service_id TEXT NOT NULL,
        network_path TEXT NOT NULL,
        username TEXT NOT NULL,
        session_id TEXT NOT NULL,
        thread_id INTEGER NOT NULL,
        message_id INTEGER NOT NULL,
        message_text TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        tor_verified INTEGER DEFAULT 0,
        vpn_verified INTEGER DEFAULT 0,
        observed_exit_ip TEXT DEFAULT 'N/A',
        FOREIGN KEY (message_id) REFERENCES posts(id)
    )
    """)
    
    # 5. Analysis Results Table (DarkWatch ML/CTI Output)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        observation_id TEXT UNIQUE NOT NULL,
        prediction TEXT,
        confidence REAL,
        severity TEXT,
        risk_score REAL,
        cti TEXT,
        mitre TEXT,
        xai TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (observation_id) REFERENCES observations(observation_id)
    )
    """)
    
    conn.commit()
    conn.close()

# --- User Helper Functions ---

def create_user(username: str, password_raw: str, role: str = 'user') -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    pwd_hash = generate_password_hash(password_raw)
    now = datetime.utcnow().isoformat() + "Z"
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, pwd_hash, role, now)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username: str, password_raw: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row and check_password_hash(row["password_hash"], password_raw):
        return dict(row)
    return None

# --- Thread & Post Helpers ---

def create_thread(service_id: str, network_path: str, title: str, author_handle: str, initial_text: str) -> Dict[str, int]:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute(
        "INSERT INTO threads (service_id, network_path, title, author_handle, created_at) VALUES (?, ?, ?, ?, ?)",
        (service_id, network_path, title, author_handle, now)
    )
    thread_id = cursor.lastrowid
    
    cursor.execute(
        "INSERT INTO posts (thread_id, service_id, network_path, author_handle, text, timestamp, synthetic) VALUES (?, ?, ?, ?, ?, ?, 1)",
        (thread_id, service_id, network_path, author_handle, initial_text, now)
    )
    post_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"thread_id": thread_id, "post_id": post_id}

def add_reply(thread_id: int, service_id: str, network_path: str, author_handle: str, text: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute(
        "INSERT INTO posts (thread_id, service_id, network_path, author_handle, text, timestamp, synthetic) VALUES (?, ?, ?, ?, ?, ?, 1)",
        (thread_id, service_id, network_path, author_handle, text, now)
    )
    post_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return post_id

def get_threads(service_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT t.*, COUNT(p.id) as reply_count FROM threads t LEFT JOIN posts p ON t.id = p.thread_id"
    params = []
    if service_id:
        query += " WHERE t.service_id = ?"
        params.append(service_id)
    query += " GROUP BY t.id ORDER BY t.id DESC"
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_thread_detail(thread_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threads WHERE id = ?", (thread_id,))
    t_row = cursor.fetchone()
    if not t_row:
        conn.close()
        return None
    thread_dict = dict(t_row)
    
    cursor.execute("SELECT * FROM posts WHERE thread_id = ? ORDER BY id ASC", (thread_id,))
    posts = [dict(p) for p in cursor.fetchall()]
    thread_dict["posts"] = posts
    conn.close()
    return thread_dict

def get_post_by_id(post_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT p.*, t.title as thread_title FROM posts p JOIN threads t ON p.thread_id = t.id WHERE p.id = ?", (post_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None
