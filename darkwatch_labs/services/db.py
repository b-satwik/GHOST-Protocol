import os
import sqlite3
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_DIR = os.environ.get("DB_DIR")
if not DB_DIR:
    if os.path.exists("/.dockerenv") and os.path.exists("/app/data"):
        DB_DIR = "/app/data"
    else:
        candidate_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        if os.path.exists(candidate_dir) and os.access(candidate_dir, os.W_OK):
            DB_DIR = candidate_dir
        else:
            DB_DIR = os.path.join(os.path.expanduser("~"), ".darkwatch_lab_data")

os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "shadowboard.db")

DEFAULT_PASSWORD = "ShadowPass123!"

def get_db_connection():
    global DB_PATH
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError:
        fallback_dir = os.path.join(os.path.expanduser("~"), ".darkwatch_lab_data")
        os.makedirs(fallback_dir, exist_ok=True)
        DB_PATH = os.path.join(fallback_dir, "shadowboard.db")
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_token TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT DEFAULT 'General',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        parent_reply_id INTEGER NULLABLE,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_reply_id) REFERENCES replies(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
    """)

    conn.commit()
    conn.close()

    seed_initial_data()

def seed_initial_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Seed accounts user01 through user10
    default_hash = generate_password_hash(DEFAULT_PASSWORD, method='pbkdf2:sha256')

    test_users = [
        ("user01", default_hash, "user"),
        ("user02", default_hash, "user"),
        ("user03", default_hash, "user"),
        ("user04", default_hash, "user"),
        ("user05", default_hash, "user"),
        ("user06", default_hash, "user"),
        ("user07", default_hash, "user"),
        ("user08", default_hash, "user"),
        ("user09", default_hash, "user"),
        ("user10", default_hash, "admin"),
    ]

    user_map = {}
    for username, pwd_hash, role in test_users:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, pwd_hash, role)
            )
            user_map[username] = cursor.lastrowid
        else:
            user_map[username] = row['id']

    # 2. Seed initial synthetic cybersecurity discussions if posts table is empty
    cursor.execute("SELECT COUNT(*) as cnt FROM posts")
    post_count = cursor.fetchone()['cnt']

    if post_count == 0:
        # Post 1: ApexGlobal Infrastructure Audit
        cursor.execute("""
            INSERT INTO posts (author_id, title, content, category, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_map["user03"],
            "ApexGlobal Infrastructure Audit & Cloud Storage Security Review",
            "We completed the quarterly synthetic security audit of ApexGlobal infrastructure. Identified several unrestricted S3 bucket policies and legacy SSH endpoints on internal gateway 10.0.4.12. Recommend enforcing IAM policies and restricting SSH access immediately.",
            "Security Audit",
            "2026-10-04 09:15:00",
            "2026-10-04 09:15:00"
        ))
        p1_id = cursor.lastrowid

        # Reply to Post 1 from user07
        cursor.execute("""
            INSERT INTO replies (post_id, author_id, parent_reply_id, content, created_at, updated_at)
            VALUES (?, ?, NULL, ?, ?, ?)
        """, (
            p1_id,
            user_map["user07"],
            "Thanks for the report user03. I have reviewed the gateway logs for 10.0.4.12 and rotated the cloud API tokens. Network egress rules updated.",
            "2026-10-04 09:30:00",
            "2026-10-04 09:30:00"
        ))
        r1_id = cursor.lastrowid

        # Nested reply to r1 from user03
        cursor.execute("""
            INSERT INTO replies (post_id, author_id, parent_reply_id, content, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            p1_id,
            user_map["user03"],
            r1_id,
            "Good progress. Please verify if any unpatched dependencies remain on node-03 before closing ticket.",
            "2026-10-04 09:45:00",
            "2026-10-04 09:45:00"
        ))
        r1_nested_id = cursor.lastrowid

        # Nested reply to r1_nested from user05
        cursor.execute("""
            INSERT INTO replies (post_id, author_id, parent_reply_id, content, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            p1_id,
            user_map["user05"],
            r1_nested_id,
            "Confirmed: node-03 patch verification completed successfully. All dependencies updated to stable release.",
            "2026-10-04 10:05:00",
            "2026-10-04 10:05:00"
        ))

        # Post 2: Northstar Systems Traffic Anomalies
        cursor.execute("""
            INSERT INTO posts (author_id, title, content, category, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_map["user01"],
            "Northstar Systems Network Telemetry & Backup Traffic Anomalies",
            "Analyzing traffic spikes observed on Northstar Systems primary database backup cluster. Investigation indicates automated telemetry synchronization during peak scheduled hours. Network baseline restored.",
            "Telemetry Analysis",
            "2026-10-04 11:20:00",
            "2026-10-04 11:20:00"
        ))
        p2_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO replies (post_id, author_id, parent_reply_id, content, created_at, updated_at)
            VALUES (?, ?, NULL, ?, ?, ?)
        """, (
            p2_id,
            user_map["user02"],
            "Understood user01. We cross-referenced the backup timestamps with Northstar Systems maintenance schedules. Everything matches expected cron jobs.",
            "2026-10-04 11:35:00",
            "2026-10-04 11:35:00"
        ))

        # Post 3: BluePeak Labs Threat Intelligence
        cursor.execute("""
            INSERT INTO posts (author_id, title, content, category, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_map["user06"],
            "BluePeak Labs Synthetic Threat Intelligence Brief & YARA Detection Rules",
            "Sharing synthetic IOCs, file hash indicators, and YARA signatures compiled by BluePeak Labs for memory injection detection tests.",
            "Threat Intelligence",
            "2026-10-04 12:40:00",
            "2026-10-04 12:40:00"
        ))
        p3_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO replies (post_id, author_id, parent_reply_id, content, created_at, updated_at)
            VALUES (?, ?, NULL, ?, ?, ?)
        """, (
            p3_id,
            user_map["user08"],
            "Extremely useful ruleset. Validated YARA rule synthetic_mem_inject_v1 against test lab binaries without false positives.",
            "2026-10-04 13:10:00",
            "2026-10-04 13:10:00"
        ))

    conn.commit()
    conn.close()

def log_activity(user_id, event_type, details=None, ip_address=None, user_agent=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO activity_logs (user_id, event_type, details, ip_address, user_agent, timestamp)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (user_id, event_type, details, ip_address, user_agent))
    conn.commit()
    conn.close()

def reset_db(reseed=True, preserve_token=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    active_session = None
    if preserve_token:
        cursor.execute("SELECT * FROM sessions WHERE session_token = ?", (preserve_token,))
        active_session = cursor.fetchone()

    cursor.execute("DELETE FROM replies")
    cursor.execute("DELETE FROM posts")
    cursor.execute("DELETE FROM sessions")
    cursor.execute("DELETE FROM activity_logs")

    if active_session:
        cursor.execute(
            "INSERT INTO sessions (session_token, user_id, created_at) VALUES (?, ?, ?)",
            (active_session["session_token"], active_session["user_id"], active_session["created_at"])
        )

    # Reset autoincrement sequence for posts, replies, activity_logs
    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('posts', 'replies', 'activity_logs')")

    conn.commit()
    conn.close()

    if reseed:
        seed_initial_data()
