import os
import time
import datetime
import uuid
import json
from flask import (
    Flask, render_template_string, request, Response, redirect,
    url_for, jsonify, make_response, stream_with_context
)

from werkzeug.security import generate_password_hash, check_password_hash

try:
    from db import (
        init_db, get_db_connection, seed_initial_data, log_activity, reset_db,
        check_password_hash, DEFAULT_PASSWORD
    )
except ImportError:
    from darkwatch_labs.services.db import (
        init_db, get_db_connection, seed_initial_data, log_activity, reset_db,
        check_password_hash, DEFAULT_PASSWORD
    )

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ghost_protocol_shadowboard_secret_key_2026")

# Initialize database schema and seed data on startup
init_db()

# Global scenario state for legacy test compatibility
scenario_day = 1
post_counter = 0
ONION_HOSTS = {}

def load_onion_hosts():
    global ONION_HOSTS
    ONION_HOSTS.clear()

    search_dirs = [
        "/app/hs_data",
        "/var/lib/tor/services",
        "/var/lib/tor",
        "darkwatch_labs/hs_data",
        "./hs_data",
        "../darkwatch_labs/hs_data"
    ]

    service_paths = [
        ("shadowforum", ["hs_shadowforum/hostname", "shadowforum/hostname"]),
        ("dreadlab", ["hs_dreadlab/hostname", "dreadlab/hostname"]),
        ("pastevault", ["hs_pastevault/hostname", "pastevault/hostname"]),
        ("leaklocker", ["hs_leaklocker/hostname", "leaklocker/hostname"]),
        ("shadowboard", ["shadowboard/hostname", "hs_shadowboard/hostname"]),
        ("forum", ["hs_forum/hostname", "forum/hostname"])
    ]

    for service_name, rel_paths in service_paths:
        for d in search_dirs:
            for rel_path in rel_paths:
                hpath = os.path.join(d, rel_path)
                if os.path.exists(hpath):
                    try:
                        with open(hpath, "r") as f:
                            host = f.read().strip().lower()
                            if host.endswith(".onion") and host not in ONION_HOSTS:
                                ONION_HOSTS[host] = service_name
                                ONION_HOSTS[host.split(":")[0]] = service_name
                    except Exception:
                        pass

    ONION_HOSTS["shadowboard.lab.onion"] = "shadowforum"
    ONION_HOSTS["dreadlab.lab.onion"] = "dreadlab"
    ONION_HOSTS["pastevault.lab.onion"] = "pastevault"
    ONION_HOSTS["leaklocker.lab.onion"] = "leaklocker"

@app.before_request
def route_service_by_host():
    load_onion_hosts()
    service = get_service_for_request()
    if request.path == "/":
        if service in ("shadowforum", "forum"):
            return shadowforum()
        elif service == "dreadlab":
            return dreadlab()
        elif service == "pastevault":
            return pastevault()
        elif service == "leaklocker":
            return leaklocker()

def get_current_user():
    token = request.cookies.get("session_token")
    auth_header = request.headers.get("Authorization")
    if not token and auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]

    if not token:
        return None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.role, u.created_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ?
    """, (token,))
    user = cursor.fetchone()
    conn.close()
    return user

def login_required_response(is_api=False):
    if is_api or request.path.startswith("/api/"):
        return jsonify({"error": "Authentication required", "status": "LOGIN_REQUIRED"}), 401
    
    # Return 401 status with login page template so GHOST observer classifies source as LOGIN_REQUIRED
    resp = make_response(render_login_page(error="Authentication required. Please log in with a test account."), 401)
    return resp

# ============================================================================
# BASE LAYOUT TEMPLATE
# ============================================================================
BASE_CSS = """
<style>
    :root {
        --bg-dark: #090d16;
        --bg-card: #0f172a;
        --bg-hover: #1e293b;
        --border-color: #1e293b;
        --accent-green: #10b981;
        --accent-cyan: #06b6d4;
        --accent-purple: #8b5cf6;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
    }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: var(--bg-dark);
        color: var(--text-primary);
        margin: 0;
        padding: 0;
        line-height: 1.5;
    }
    .header {
        background-color: var(--bg-card);
        border-bottom: 1px solid var(--border-color);
        padding: 12px 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        position: sticky;
        top: 0;
        z-index: 100;
    }
    .logo {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 1.25rem;
        font-weight: 700;
        color: var(--accent-cyan);
        text-decoration: none;
    }
    .nav-links {
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .nav-link {
        color: var(--text-secondary);
        text-decoration: none;
        font-size: 0.9rem;
        font-weight: 500;
        transition: color 0.15s ease;
    }
    .nav-link:hover {
        color: var(--accent-cyan);
    }
    .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 6px 14px;
        border-radius: 6px;
        font-size: 0.875rem;
        font-weight: 600;
        text-decoration: none;
        cursor: pointer;
        border: none;
        transition: all 0.15s ease;
    }
    .btn-primary {
        background-color: var(--accent-cyan);
        color: #000000;
    }
    .btn-primary:hover {
        background-color: #22d3ee;
    }
    .btn-danger {
        background-color: #ef4444;
        color: #ffffff;
    }
    .btn-danger:hover {
        background-color: #dc2626;
    }
    .btn-secondary {
        background-color: #334155;
        color: #ffffff;
    }
    .btn-secondary:hover {
        background-color: #475569;
    }
    .container {
        max-width: 960px;
        margin: 24px auto;
        padding: 0 16px;
    }
    .card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 16px;
    }
    .post-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 14px;
        transition: border-color 0.15s ease;
    }
    .post-card:hover {
        border-color: #334155;
    }
    .meta-tag {
        font-size: 0.75rem;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 4px;
        background-color: #1e293b;
        color: var(--accent-green);
    }
    .user-badge {
        color: var(--accent-cyan);
        font-weight: 600;
        text-decoration: none;
    }
    .user-badge:hover {
        text-decoration: underline;
    }
    .post-title {
        margin: 8px 0 6px 0;
        font-size: 1.2rem;
        font-weight: 700;
    }
    .post-title a {
        color: var(--text-primary);
        text-decoration: none;
    }
    .post-title a:hover {
        color: var(--accent-cyan);
    }
    .comment-tree {
        margin-top: 16px;
        border-left: 2px solid #1e293b;
        padding-left: 16px;
    }
    .nested-comment {
        background: #0b1324;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
    .form-group {
        margin-bottom: 14px;
    }
    .form-group label {
        display: block;
        font-size: 0.85rem;
        color: var(--text-secondary);
        margin-bottom: 6px;
    }
    .form-control {
        width: 100%;
        padding: 10px;
        background: #090d16;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        color: var(--text-primary);
        box-sizing: border-box;
        font-size: 0.95rem;
    }
    .form-control:focus {
        outline: 1px solid var(--accent-cyan);
        border-color: var(--accent-cyan);
    }
    textarea.form-control {
        resize: vertical;
        min-height: 100px;
    }
    .badge-bar {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 12px;
    }
</style>
"""

def render_page(title, content, user=None):
    user_nav = ""
    if user:
        user_nav = f"""
        <span style="font-size:0.875rem; color: var(--text-secondary);">Logged in as: <a href="/user/{user['username']}" class="user-badge">{user['username']}</a></span>
        <a href="/user/{user['username']}" class="nav-link">My Profile</a>
        <a href="/admin" class="nav-link" style="color:#eab308;">Lab Admin</a>
        <a href="/logout" class="btn btn-secondary">Logout</a>
        """
    else:
        user_nav = """
        <a href="/login" class="btn btn-primary">Log In</a>
        <a href="/register" class="nav-link">Register Info</a>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} — ShadowBoard Lab</title>
        {BASE_CSS}
    </head>
    <body>
        <div class="header">
            <a href="/" class="logo">
                <span>⚡ ShadowBoard</span>
            </a>
            <div class="nav-links">
                <a href="/forum" class="nav-link">Discussions</a>
                {user_nav}
            </div>
        </div>
        <div class="container">
            {content}
        </div>
    </body>
    </html>
    """

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================
def render_login_page(error=None):
    error_html = ""
    if error:
        error_html = f'<div style="background:#7f1d1d; color:#fca5a5; padding:10px; border-radius:6px; margin-bottom:14px; font-size:0.9rem;">{error}</div>'

    accounts_table = ""
    for i in range(1, 11):
        uname = f"user{i:02d}"
        accounts_table += f"<code style='background:#1e293b; padding:2px 6px; border-radius:4px; margin:2px; font-size:0.85rem;'>{uname} / {DEFAULT_PASSWORD}</code> "

    content = f"""
    <div style="max-width: 480px; margin: 40px auto;" class="card">
        <h2 style="margin-top:0; color:var(--accent-cyan); font-size:1.5rem;">🔒 ShadowBoard Authentication</h2>
        <p style="color:var(--text-secondary); font-size:0.9rem;">GHOST Protocol Controlled Research Lab — Session Login Required</p>
        {error_html}
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control" placeholder="e.g. user01" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control" placeholder="Enter password" required>
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%; padding:10px; font-size:1rem;">Authenticate Session</button>
        </form>
        <div style="margin-top:20px; border-top:1px solid var(--border-color); padding-top:14px;">
            <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:6px;"><strong>Pre-Provisioned Test Accounts:</strong></div>
            <div style="line-height:1.8;">{accounts_table}</div>
        </div>
    </div>
    """
    return render_page("Login Required", content, user=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user = get_current_user()
        if user:
            return redirect(url_for('forum_feed'))
        return render_login_page()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cursor.fetchone()

    if not user_row or not check_password_hash(user_row["password_hash"], password):
        conn.close()
        return render_login_page(error="Invalid username or password.")

    # Create new session token
    token = f"sb_sess_{uuid.uuid4().hex}"
    cursor.execute(
        "INSERT INTO sessions (session_token, user_id) VALUES (?, ?)",
        (token, user_row["id"])
    )
    conn.commit()
    conn.close()

    log_activity(
        user_id=user_row["id"],
        event_type="login",
        details="Successful session authentication",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )

    resp = make_response(redirect(url_for('forum_feed')))
    resp.set_cookie("session_token", token, max_age=86400, httponly=True)
    return resp

@app.route('/register', methods=['GET'])
def register():
    content = f"""
    <div class="card" style="max-width:600px; margin:40px auto;">
        <h2 style="color:var(--accent-cyan); margin-top:0;">ℹ️ ShadowBoard Test Accounts</h2>
        <p style="color:var(--text-secondary);">This controlled laboratory uses pre-seeded test accounts to simulate multi-user continuous threat conversations and alias tracking.</p>
        <p style="color:var(--text-secondary);">External registration, email verification, and password resets are intentionally disabled for lab consistency.</p>
        <div style="background:#0b1324; border:1px solid #1e293b; padding:15px; border-radius:6px; margin:15px 0;">
            <strong>Test Accounts:</strong> <code>user01</code> through <code>user10</code><br>
            <strong>Default Password:</strong> <code>{DEFAULT_PASSWORD}</code>
        </div>
        <a href="/login" class="btn btn-primary">Proceed to Login</a>
    </div>
    """
    return render_page("Registration Info", content, user=get_current_user())

@app.route('/logout')
def logout():
    user = get_current_user()
    token = request.cookies.get("session_token")
    if user and token:
        log_activity(
            user_id=user["id"],
            event_type="logout",
            details="User logged out",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent")
        )
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_token = ?", (token,))
        conn.commit()
        conn.close()

    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie("session_token")
    return resp

# ============================================================================
# FORUM & DISCUSSION ROUTES
# ============================================================================
@app.route('/')
@app.route('/forum')
def forum_feed():
    user = get_current_user()
    if not user:
        return login_required_response()

    sort_order = request.args.get("sort", "newest")

    conn = get_db_connection()
    cursor = conn.cursor()

    if sort_order == "activity":
        query = """
            SELECT p.*, u.username as author_name,
                   COUNT(r.id) as reply_count,
                   MAX(COALESCE(r.created_at, p.created_at)) as last_activity
            FROM posts p
            JOIN users u ON p.author_id = u.id
            LEFT JOIN replies r ON p.id = r.post_id
            GROUP BY p.id
            ORDER BY last_activity DESC
        """
    else:
        query = """
            SELECT p.*, u.username as author_name,
                   COUNT(r.id) as reply_count
            FROM posts p
            JOIN users u ON p.author_id = u.id
            LEFT JOIN replies r ON p.id = r.post_id
            GROUP BY p.id
            ORDER BY p.created_at DESC
        """

    cursor.execute(query)
    posts = cursor.fetchall()
    conn.close()

    log_activity(
        user_id=user["id"],
        event_type="page_nav",
        details=f"Viewed forum feed (sort={sort_order})",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )

    posts_html = ""
    for p in posts:
        excerpt = p["content"][:200] + ("..." if len(p["content"]) > 200 else "")
        posts_html += f"""
        <div class="post-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <span class="meta-tag">{p['category']}</span>
                <span style="font-size:0.8rem; color:var(--text-muted);">{p['created_at']}</span>
            </div>
            <h3 class="post-title"><a href="/post/{p['id']}">{p['title']}</a></h3>
            <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:10px;">
                Posted by <a href="/user/{p['author_name']}" class="user-badge">{p['author_name']}</a> &bull; {p['reply_count']} replies
            </div>
            <div style="font-size:0.95rem; color:#cbd5e1; line-height:1.5;">{excerpt}</div>
            <div style="margin-top:12px;">
                <a href="/post/{p['id']}" class="btn btn-secondary" style="font-size:0.8rem; padding:4px 10px;">Open Discussion ({p['reply_count']})</a>
            </div>
        </div>
        """

    content = f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <div>
            <h1 style="margin:0; color:var(--text-primary); font-size:1.75rem;">🌐 ShadowBoard Discussions</h1>
            <p style="margin:4px 0 0 0; color:var(--text-secondary); font-size:0.9rem;">Synthetic Cybersecurity & Threat Research Forum</p>
        </div>
        <a href="#create-post" class="btn btn-primary">+ Create Post</a>
    </div>

    <div style="display:flex; gap:12px; margin-bottom:16px;">
        <a href="/forum?sort=newest" class="btn {'btn-primary' if sort_order == 'newest' else 'btn-secondary'}" style="font-size:0.8rem;">Newest Posts</a>
        <a href="/forum?sort=activity" class="btn {'btn-primary' if sort_order == 'activity' else 'btn-secondary'}" style="font-size:0.8rem;">Recent Activity</a>
    </div>

    {posts_html}

    <div class="card" id="create-post" style="margin-top:30px;">
        <h3 style="margin-top:0; color:var(--accent-cyan);">Start a New Discussion</h3>
        <form method="POST" action="/post/create">
            <div class="form-group">
                <label>Title</label>
                <input type="text" name="title" class="form-control" placeholder="Enter topic title" required>
            </div>
            <div class="form-group">
                <label>Category</label>
                <select name="category" class="form-control">
                    <option value="Security Audit">Security Audit</option>
                    <option value="Telemetry Analysis">Telemetry Analysis</option>
                    <option value="Threat Intelligence">Threat Intelligence</option>
                    <option value="Vulnerability Research">Vulnerability Research</option>
                    <option value="General">General</option>
                </select>
            </div>
            <div class="form-group">
                <label>Discussion Content</label>
                <textarea name="content" class="form-control" placeholder="Write your post content..." required></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Publish Post</button>
        </form>
    </div>
    """
    return render_page("Forum Feed", content, user=user)

@app.route('/post/<int:post_id>', methods=['GET'])
def post_detail(post_id):
    user = get_current_user()
    if not user:
        return login_required_response()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.*, u.username as author_name
        FROM posts p
        JOIN users u ON p.author_id = u.id
        WHERE p.id = ?
    """, (post_id,))
    post = cursor.fetchone()

    if not post:
        conn.close()
        return render_page("Post Not Found", "<div class='card'><h2>404 Post Not Found</h2></div>", user=user), 404

    cursor.execute("""
        SELECT r.*, u.username as author_name
        FROM replies r
        JOIN users u ON r.author_id = u.id
        WHERE r.post_id = ?
        ORDER BY r.created_at ASC
    """, (post_id,))
    all_replies = cursor.fetchall()
    conn.close()

    log_activity(
        user_id=user["id"],
        event_type="view_post",
        details=f"Viewed post ID {post_id} ('{post['title']}')",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )

    # Build recursive nested reply tree structure
    reply_tree = {}
    for r in all_replies:
        pid = r["parent_reply_id"]
        if pid not in reply_tree:
            reply_tree[pid] = []
        reply_tree[pid].append(r)

    def render_reply_node(reply, current_user):
        r_id = reply["id"]
        author = reply["author_name"]
        is_author = (current_user["id"] == reply["author_id"])
        
        edit_button_html = ""
        if is_author:
            edit_button_html = f"""
            <button onclick="document.getElementById('edit-reply-{r_id}').style.display='block'" class="btn btn-secondary" style="font-size:0.75rem; padding:2px 6px;">Edit</button>
            """

        children_html = ""
        if r_id in reply_tree:
            for child in reply_tree[r_id]:
                children_html += render_reply_node(child, current_user)

        return f"""
        <div class="nested-comment" id="reply-{r_id}">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-size:0.85rem;">
                    <a href="/user/{author}" class="user-badge">{author}</a> &bull;
                    <span style="color:var(--text-muted);">{reply['created_at']}</span>
                </span>
                <div>{edit_button_html}</div>
            </div>
            <div style="margin:8px 0; color:#e2e8f0; white-space:pre-line;">{reply['content']}</div>
            
            <div style="margin-top:6px;">
                <button onclick="toggleReplyForm({r_id})" class="btn btn-secondary" style="font-size:0.75rem; padding:2px 8px;">Reply</button>
            </div>

            <!-- Inline Reply Form -->
            <div id="reply-form-{r_id}" style="display:none; margin-top:10px; background:#090d16; padding:10px; border-radius:6px; border:1px solid #1e293b;">
                <form method="POST" action="/post/{post_id}/reply">
                    <input type="hidden" name="parent_reply_id" value="{r_id}">
                    <textarea name="content" class="form-control" style="min-height:60px;" placeholder="Replying to {author}..." required></textarea>
                    <div style="margin-top:6px; display:flex; gap:6px;">
                        <button type="submit" class="btn btn-primary" style="font-size:0.8rem; padding:4px 10px;">Post Reply</button>
                        <button type="button" onclick="toggleReplyForm({r_id})" class="btn btn-secondary" style="font-size:0.8rem; padding:4px 10px;">Cancel</button>
                    </div>
                </form>
            </div>

            <!-- Inline Edit Form -->
            <div id="edit-reply-{r_id}" style="display:none; margin-top:10px; background:#090d16; padding:10px; border-radius:6px; border:1px solid #eab308;">
                <form method="POST" action="/reply/{r_id}/edit">
                    <textarea name="content" class="form-control" style="min-height:60px;" required>{reply['content']}</textarea>
                    <div style="margin-top:6px; display:flex; gap:6px;">
                        <button type="submit" class="btn btn-primary" style="font-size:0.8rem; padding:4px 10px;">Save Edit</button>
                        <button type="button" onclick="document.getElementById('edit-reply-{r_id}').style.display='none'" class="btn btn-secondary" style="font-size:0.8rem; padding:4px 10px;">Cancel</button>
                    </div>
                </form>
            </div>

            <div class="comment-tree">
                {children_html}
            </div>
        </div>
        """

    top_replies_html = ""
    if None in reply_tree:
        for r in reply_tree[None]:
            top_replies_html += render_reply_node(r, user)

    post_is_author = (user["id"] == post["author_id"])
    edit_post_button = ""
    if post_is_author:
        edit_post_button = f"""
        <button onclick="document.getElementById('edit-post-box').style.display='block'" class="btn btn-secondary" style="font-size:0.8rem;">Edit Post</button>
        """

    content = f"""
    <div style="margin-bottom:14px;">
        <a href="/forum" class="nav-link">← Back to Discussions</a>
    </div>

    <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="meta-tag">{post['category']}</span>
            <span style="font-size:0.85rem; color:var(--text-muted);">{post['created_at']}</span>
        </div>
        <h1 style="color:var(--accent-cyan); margin:10px 0 6px 0;">{post['title']}</h1>
        <div style="font-size:0.9rem; color:var(--text-secondary); margin-bottom:14px;">
            Author: <a href="/user/{post['author_name']}" class="user-badge">{post['author_name']}</a>
        </div>
        <div style="font-size:1.05rem; color:#f1f5f9; line-height:1.6; white-space:pre-line;">{post['content']}</div>
        <div style="margin-top:16px;">
            {edit_post_button}
        </div>

        <!-- Inline Edit Post Box -->
        <div id="edit-post-box" style="display:none; margin-top:14px; background:#090d16; padding:15px; border-radius:6px; border:1px solid var(--accent-cyan);">
            <h4 style="margin-top:0; color:var(--accent-cyan);">Edit Discussion Post</h4>
            <form method="POST" action="/post/{post['id']}/edit">
                <div class="form-group">
                    <label>Title</label>
                    <input type="text" name="title" value="{post['title']}" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Content</label>
                    <textarea name="content" class="form-control" required>{post['content']}</textarea>
                </div>
                <button type="submit" class="btn btn-primary">Save Post</button>
                <button type="button" onclick="document.getElementById('edit-post-box').style.display='none'" class="btn btn-secondary">Cancel</button>
            </form>
        </div>
    </div>

    <h3 style="color:var(--text-primary); margin-top:24px;">Discussion Replies (<span id="reply-count">{len(all_replies)}</span>)</h3>

    <!-- Main Reply Box -->
    <div class="card">
        <h4 style="margin-top:0; color:var(--accent-green);">Add a Reply</h4>
        <form method="POST" action="/post/{post['id']}/reply">
            <textarea name="content" class="form-control" placeholder="Join the discussion..." required></textarea>
            <button type="submit" class="btn btn-primary" style="margin-top:10px;">Post Reply</button>
        </form>
    </div>

    <div id="replies-container">
        {top_replies_html if top_replies_html else "<p style='color:var(--text-muted);'>No replies yet. Be the first to join this discussion!</p>"}
    </div>

    <script>
    function toggleReplyForm(replyId) {{
        var el = document.getElementById('reply-form-' + replyId);
        if (el) {{
            el.style.display = (el.style.display === 'none') ? 'block' : 'none';
        }}
    }}

    // Real-time polling script to fetch updates automatically
    setInterval(function() {{
        fetch('/api/post/{post_id}/replies')
            .then(response => response.json())
            .then(data => {{
                if (data.success && data.reply_count !== undefined) {{
                    var countEl = document.getElementById('reply-count');
                    if (countEl && parseInt(countEl.innerText) !== data.reply_count) {{
                        location.reload();
                    }}
                }}
            }})
            .catch(err => console.log('Polling status:', err));
    }}, 4000);
    </script>
    """
    return render_page(f"Post #{post_id}", content, user=user)

@app.route('/post/create', methods=['POST'])
def create_post():
    user = get_current_user()
    if not user:
        return login_required_response(is_api=True)

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    category = request.form.get("category", "General").strip()

    if not title or not content:
        return redirect(url_for('forum_feed'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO posts (author_id, title, content, category)
        VALUES (?, ?, ?, ?)
    """, (user["id"], title, content, category))
    post_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_activity(
        user_id=user["id"],
        event_type="create_post",
        details=f"Created post ID {post_id} ('{title}')",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )

    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/post/<int:post_id>/reply', methods=['POST'])
def create_reply(post_id):
    user = get_current_user()
    if not user:
        return login_required_response(is_api=True)

    content = request.form.get("content", "").strip()
    parent_reply_id = request.form.get("parent_reply_id", "").strip()
    if not parent_reply_id or parent_reply_id == "None":
        parent_reply_id = None
    else:
        parent_reply_id = int(parent_reply_id)

    if not content:
        return redirect(url_for('post_detail', post_id=post_id))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO replies (post_id, author_id, parent_reply_id, content)
        VALUES (?, ?, ?, ?)
    """, (post_id, user["id"], parent_reply_id, content))
    reply_id = cursor.lastrowid

    cursor.execute("UPDATE posts SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()

    log_activity(
        user_id=user["id"],
        event_type="create_reply",
        details=f"Created reply ID {reply_id} on post {post_id} (parent={parent_reply_id})",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )

    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/post/<int:post_id>/edit', methods=['POST'])
def edit_post(post_id):
    user = get_current_user()
    if not user:
        return login_required_response(is_api=True)

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT author_id FROM posts WHERE id = ?", (post_id,))
    row = cursor.fetchone()

    if not row or row["author_id"] != user["id"]:
        conn.close()
        return "Unauthorized", 403

    cursor.execute("""
        UPDATE posts SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    """, (title, content, post_id))
    conn.commit()
    conn.close()

    log_activity(
        user_id=user["id"],
        event_type="edit_post",
        details=f"Edited post ID {post_id}",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )

    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/reply/<int:reply_id>/edit', methods=['POST'])
def edit_reply(reply_id):
    user = get_current_user()
    if not user:
        return login_required_response(is_api=True)

    content = request.form.get("content", "").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT author_id, post_id FROM replies WHERE id = ?", (reply_id,))
    row = cursor.fetchone()

    if not row or row["author_id"] != user["id"]:
        conn.close()
        return "Unauthorized", 403

    post_id = row["post_id"]
    cursor.execute("""
        UPDATE replies SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    """, (content, reply_id))
    conn.commit()
    conn.close()

    log_activity(
        user_id=user["id"],
        event_type="edit_reply",
        details=f"Edited reply ID {reply_id} on post {post_id}",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )

    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/user/<username>')
def user_profile(username):
    user = get_current_user()
    if not user:
        return login_required_response()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    target_user = cursor.fetchone()

    if not target_user:
        conn.close()
        return render_page("User Not Found", "<div class='card'><h2>User Not Found</h2></div>", user=user), 404

    cursor.execute("SELECT p.*, COUNT(r.id) as reply_count FROM posts p LEFT JOIN replies r ON p.id = r.post_id WHERE p.author_id = ? GROUP BY p.id ORDER BY p.created_at DESC", (target_user["id"],))
    user_posts = cursor.fetchall()

    cursor.execute("SELECT r.*, p.title as post_title FROM replies r JOIN posts p ON r.post_id = p.id WHERE r.author_id = ? ORDER BY r.created_at DESC", (target_user["id"],))
    user_replies = cursor.fetchall()

    cursor.execute("SELECT * FROM activity_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 20", (target_user["id"],))
    activities = cursor.fetchall()

    conn.close()

    log_activity(
        user_id=user["id"],
        event_type="view_profile",
        details=f"Viewed profile of {username}",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )

    posts_html = ""
    for p in user_posts:
        posts_html += f"<li><a href='/post/{p['id']}'>{p['title']}</a> <span style='font-size:0.8rem; color:var(--text-muted);'>({p['created_at']})</span></li>"

    replies_html = ""
    for r in user_replies:
        replies_html += f"<li>On <a href='/post/{r['post_id']}'>{r['post_title']}</a>: <em>{r['content'][:80]}...</em> <span style='font-size:0.8rem; color:var(--text-muted);'>({r['created_at']})</span></li>"

    act_html = ""
    for a in activities:
        act_html += f"<tr><td>{a['timestamp']}</td><td><code style='color:var(--accent-cyan);'>{a['event_type']}</code></td><td>{a['details']}</td></tr>"

    content = f"""
    <div class="card">
        <h2 style="color:var(--accent-cyan); margin-top:0;">👤 User Profile: {target_user['username']}</h2>
        <p style="color:var(--text-secondary);">Member Since: {target_user['created_at']}</p>
        <div style="display:flex; gap:20px; margin:16px 0;">
            <div style="background:#0b1324; padding:12px 20px; border-radius:6px; border:1px solid #1e293b;">
                <div style="font-size:1.5rem; font-weight:bold; color:var(--accent-green);">{len(user_posts)}</div>
                <div style="font-size:0.8rem; color:var(--text-secondary);">Posts Authored</div>
            </div>
            <div style="background:#0b1324; padding:12px 20px; border-radius:6px; border:1px solid #1e293b;">
                <div style="font-size:1.5rem; font-weight:bold; color:var(--accent-cyan);">{len(user_replies)}</div>
                <div style="font-size:0.8rem; color:var(--text-secondary);">Replies Posted</div>
            </div>
        </div>
    </div>

    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
        <div class="card">
            <h3 style="margin-top:0; color:var(--text-primary);">Authored Discussions</h3>
            <ul>{posts_html if posts_html else '<li>No posts created yet.</li>'}</ul>
        </div>
        <div class="card">
            <h3 style="margin-top:0; color:var(--text-primary);">Recent Replies</h3>
            <ul>{replies_html if replies_html else '<li>No replies posted yet.</li>'}</ul>
        </div>
    </div>

    <div class="card">
        <h3 style="margin-top:0; color:var(--text-primary);">Activity History Log</h3>
        <table style="width:100%; border-collapse:collapse; font-size:0.85rem;">
            <thead>
                <tr style="border-bottom:1px solid var(--border-color); text-align:left; color:var(--text-secondary);">
                    <th style="padding:6px;">Timestamp</th>
                    <th style="padding:6px;">Event</th>
                    <th style="padding:6px;">Details</th>
                </tr>
            </thead>
            <tbody>
                {act_html if act_html else '<tr><td colspan="3">No activity logged.</td></tr>'}
            </tbody>
        </table>
    </div>
    """
    return render_page(f"User Profile - {username}", content, user=user)

# ============================================================================
# REAL-TIME / DYNAMIC UPDATES REST & SSE API
# ============================================================================
@app.route('/api/post/<int:post_id>/replies')
def api_post_replies(post_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM replies WHERE post_id = ?", (post_id,))
    cnt = cursor.fetchone()["cnt"]
    conn.close()
    return jsonify({"success": True, "post_id": post_id, "reply_count": cnt})

@app.route('/api/posts')
def api_posts():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT p.id, p.title, p.category, p.created_at, u.username as author_name FROM posts p JOIN users u ON p.author_id = u.id ORDER BY p.created_at DESC")
    posts = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "posts": posts})

@app.route('/api/stream')
def api_stream():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    def event_stream():
        last_log_id = 0
        while True:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM activity_logs WHERE id > ? ORDER BY id ASC", (last_log_id,))
            logs = cursor.fetchall()
            for log in logs:
                last_log_id = log["id"]
                data = json.dumps(dict(log))
                yield f"data: {data}\n\n"
            conn.close()
            time.sleep(2)

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

# ============================================================================
# LAB ADMIN / RESET ENDPOINT
# ============================================================================
@app.route('/admin', methods=['GET'])
def admin_panel():
    user = get_current_user()
    if not user:
        return login_required_response()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM posts")
    posts_cnt = cursor.fetchone()["cnt"]
    cursor.execute("SELECT COUNT(*) as cnt FROM replies")
    replies_cnt = cursor.fetchone()["cnt"]
    cursor.execute("SELECT COUNT(*) as cnt FROM activity_logs")
    activity_cnt = cursor.fetchone()["cnt"]
    conn.close()

    content = f"""
    <div class="card" style="max-width:640px; margin:20px auto;">
        <h2 style="color:#eab308; margin-top:0;">⚙️ ShadowBoard Controlled Lab Admin</h2>
        <p style="color:var(--text-secondary);">Manage synthetic discussions, clear test session states, and reseed baseline cybersecurity threads.</p>

        <div style="background:#0b1324; border:1px solid #1e293b; padding:15px; border-radius:6px; margin:16px 0;">
            <h4 style="margin-top:0; color:var(--text-primary);">Current Database Statistics</h4>
            <ul style="color:var(--text-secondary); margin-bottom:0;">
                <li>Total Posts: <strong style="color:var(--accent-green);">{posts_cnt}</strong></li>
                <li>Total Replies: <strong style="color:var(--accent-cyan);">{replies_cnt}</strong></li>
                <li>Activity Logs: <strong style="color:var(--accent-purple);">{activity_cnt}</strong></li>
            </ul>
        </div>

        <form method="POST" action="/admin/reset">
            <p style="font-size:0.85rem; color:#fca5a5;">
                ⚠️ <strong>Reset Notice:</strong> Resetting will clear all user-created posts, replies, and activities, while preserving pre-provisioned user accounts (user01-user10) and reseeding default synthetic discussions.
            </p>
            <button type="submit" class="btn btn-danger" onclick="return confirm('Reset all laboratory posts and activity logs?');">Reset Forum Lab Data</button>
        </form>
    </div>
    """
    return render_page("Lab Admin", content, user=user)

@app.route('/admin/reset', methods=['POST'])
def admin_reset():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    token = request.cookies.get("session_token")
    reset_db(reseed=True, preserve_token=token)
    log_activity(
        user_id=user["id"],
        event_type="admin_reset",
        details="Lab data reset and re-seeded",
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent")
    )
    return redirect(url_for('admin_panel'))

# ============================================================================
# LEGACY ENDPOINTS COMPATIBILITY
# ============================================================================
def get_service_for_request():
    raw_host = (request.headers.get("Host") or request.host or "").lower().split(":")[0]
    path = request.path.lower()

    if raw_host in ONION_HOSTS:
        return ONION_HOSTS[raw_host]

    if "shadowforum" in raw_host or "t2cra" in raw_host or path.startswith("/shadowforum"):
        return "shadowforum"
    elif "dreadlab" in raw_host or "mgbpg" in raw_host or path.startswith("/dreadlab"):
        return "dreadlab"
    elif "pastevault" in raw_host or "nto5k" in raw_host or path.startswith("/pastevault"):
        return "pastevault"
    elif "leaklocker" in raw_host or "ransom" in raw_host or path.startswith("/leaklocker"):
        return "leaklocker"

    if raw_host in ("127.0.0.1", "localhost") and path == "/":
        return "shadowforum"

    return None

@app.route('/scenario/day/<int:day>', methods=['GET', 'POST'])
def set_scenario_day(day):
    global scenario_day
    if 1 <= day <= 4:
        scenario_day = day
        return jsonify({"success": True, "scenario_day": scenario_day, "message": f"Lab scenario updated to Day {day}"})
    return jsonify({"success": False, "error": "Day must be between 1 and 4"}), 400

@app.route('/scenario/status', methods=['GET'])
def get_scenario_status():
    return jsonify({"success": True, "scenario_day": scenario_day})

@app.route('/shadowforum', methods=['GET', 'POST'])
def shadowforum():
    global scenario_day
    status_msg = ""
    
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        content = (request.form.get('content') or '').strip()
        category = (request.form.get('category') or 'Breach Reports').strip()
        author_name = (request.form.get('author') or '').strip()
        
        user = get_current_user()
        if not author_name:
            if user:
                author_name = user['username']
            else:
                author_name = "ShadowUser"

        if title and content:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = ?", (author_name,))
                u_row = cursor.fetchone()
                if u_row:
                    author_id = u_row['id']
                else:
                    cursor.execute(
                        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                        (author_name, generate_password_hash("labpass123"), "user")
                    )
                    author_id = cursor.lastrowid
                
                cursor.execute(
                    "INSERT INTO posts (author_id, title, content, category) VALUES (?, ?, ?, ?)",
                    (author_id, title, content, category)
                )
                conn.commit()
                conn.close()
                status_msg = '<div style="background: #064e3b; border: 1px solid #10b981; color: #34d399; padding: 12px; border-radius: 6px; margin-bottom: 20px; font-weight: bold;">✅ Threat Post Published Successfully! View details below.</div>'
            except Exception as e:
                status_msg = f'<div style="background: #7f1d1d; border: 1px solid #ef4444; color: #fca5a5; padding: 12px; border-radius: 6px; margin-bottom: 20px;">❌ Error publishing post: {str(e)}</div>'

    if scenario_day < 4:
        viper_post = {
            "id": 101,
            "category": "Breach Reports",
            "author": "ViperSec",
            "title": "Database Leak & Exfiltration: ApexGlobal Financial",
            "content": "Database leak discussion: Exfiltrated database dump containing 500,000 customer records from ApexGlobal Financial. Database credentials and internal server details exposed for sale.",
            "timestamp": "2026-10-01 10:00:00 UTC"
        }
    else:
        viper_post = {
            "id": 101,
            "category": "Breach Reports",
            "author": "ViperSec",
            "title": "UPDATE: Access Closed — ApexGlobal Financial / BioHealth Dynamics",
            "content": "UPDATE: ApexGlobal Financial access closed/sold. Now offering exclusive access and database leak for BioHealth Dynamics.",
            "timestamp": "2026-10-04 14:00:00 UTC"
        }

    benign_post_1 = {
        "id": 102,
        "category": "General",
        "author": "DevOps_Dan",
        "title": "PostgreSQL Server Configuration & Performance Tuning",
        "content": "PostgreSQL performance tuning question: What are the recommended settings for shared_buffers and max_connections on a PostgreSQL 15 server running on Linux?",
        "timestamp": "2026-10-01 11:30:00 UTC"
    }

    benign_post_2 = {
        "id": 103,
        "category": "Security Advisories",
        "author": "SecurityNerd99",
        "title": "Enterprise Cybersecurity Awareness & MFA Best Practices",
        "content": "Cybersecurity awareness weekly digest: Best practices for implementing multi-factor authentication and security patch management across enterprise servers.",
        "timestamp": "2026-10-01 12:15:00 UTC"
    }

    # Retrieve dynamic user posts from DB
    db_posts = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.id, p.title, p.content, p.category, p.created_at as timestamp, u.username as author
            FROM posts p
            JOIN users u ON p.author_id = u.id
            ORDER BY p.id DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        for r in rows:
            db_posts.append({
                "id": r["id"],
                "category": r["category"],
                "author": r["author"],
                "title": r["title"],
                "content": r["content"],
                "timestamp": str(r["timestamp"])
            })
    except Exception:
        pass

    all_posts = db_posts + [viper_post, benign_post_1, benign_post_2]

    posts_html = ""
    for p in all_posts:
        posts_html += f"""
        <div class="post" style="border: 1px solid #1e293b; background: #0f172a; padding: 15px; margin-bottom: 15px; border-radius: 6px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="background: #00ff66; color: #000; font-weight: bold; font-size: 0.75em; padding: 2px 8px; border-radius: 4px;">{p['category']}</span>
                <span style="color: #64748b; font-size: 0.8em;">ID #{p['id']} &bull; {p['timestamp']}</span>
            </div>
            <h3 style="color: #00ff66; margin: 8px 0 4px 0;">{p['title']}</h3>
            <div style="font-size: 0.9em; color: #94a3b8; margin-bottom: 8px;"><strong>Author:</strong> <span style="color: #38bdf8;">{p['author']}</span></div>
            <div style="color: #f1f5f9; font-size: 0.95em; line-height: 1.5; white-space: pre-line;">{p['content']}</div>
        </div>
        """

    curr_user = get_current_user()
    default_author = curr_user["username"] if curr_user else "ShadowUser"

    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>ShadowForum — Public Threat Discussion Board</title></head>
    <body style="font-family: monospace; background-color: #020617; color: #e2e8f0; padding: 20px;">
        <div style="max-width: 900px; margin: 0 auto;">
            <h1 style="color: #00ff66; border-bottom: 2px solid #00ff66; padding-bottom: 8px;">🌐 ShadowForum (Synthetic Threat Forum)</h1>
            <p style="color: #94a3b8;">Public / Unauthenticated Synthetic Threat Discussion Forum &bull; Day {scenario_day} Timeline Active</p>
            
            {status_msg}

            <div style="background: #0f172a; border: 1px solid #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 25px;">
                <h3 style="color: #00ff66; margin-top: 0;">➕ Create New Threat Thread / Post</h3>
                <form method="POST" action="">
                    <div style="margin-bottom: 12px;">
                        <label style="display: block; color: #94a3b8; font-size: 0.85em; margin-bottom: 4px;">Author Username</label>
                        <input type="text" name="author" value="{default_author}" placeholder="e.g. ThreatActor_99" style="width: 100%; padding: 8px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px; box-sizing: border-box;">
                    </div>
                    <div style="margin-bottom: 12px;">
                        <label style="display: block; color: #94a3b8; font-size: 0.85em; margin-bottom: 4px;">Category</label>
                        <select name="category" style="width: 100%; padding: 8px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px; box-sizing: border-box;">
                            <option value="Breach Reports">Breach Reports</option>
                            <option value="Vulnerability Research">Vulnerability Research</option>
                            <option value="Exploit Proof-of-Concept">Exploit Proof-of-Concept</option>
                            <option value="Credential Access">Credential Access</option>
                            <option value="General">General</option>
                        </select>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <label style="display: block; color: #94a3b8; font-size: 0.85em; margin-bottom: 4px;">Thread Title</label>
                        <input type="text" name="title" placeholder="Enter thread title..." required style="width: 100%; padding: 8px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px; box-sizing: border-box;">
                    </div>
                    <div style="margin-bottom: 12px;">
                        <label style="display: block; color: #94a3b8; font-size: 0.85em; margin-bottom: 4px;">Post Content / Threat Intel Details</label>
                        <textarea name="content" rows="4" placeholder="Write threat details, vulnerability descriptions, or breach claims..." required style="width: 100%; padding: 8px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px; box-sizing: border-box;"></textarea>
                    </div>
                    <button type="submit" style="background: #00ff66; color: #000; font-weight: bold; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer;">Publish Thread to ShadowForum</button>
                </form>
            </div>

            <h2>Discussion Threads ({len(all_posts)})</h2>
            {posts_html}
        </div>
    </body>
    </html>
    """, 200

@app.route('/dreadlab', methods=['GET', 'POST'])
@app.route('/session_gated', methods=['GET', 'POST'])
def dreadlab():
    session_cookie = request.cookies.get('session_token')
    auth_header = request.headers.get('Authorization')

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if code in ('123456', 'AUTH_OK', 'verified'):
            resp = Response(render_dreadlab_authenticated(), status=200, mimetype='text/html')
            resp.set_cookie('session_token', 'valid_lab_session')
            return resp

    if session_cookie == 'valid_lab_session' or auth_header == 'Bearer valid_lab_session':
        return render_dreadlab_authenticated(), 200
    else:
        post_target = request.path if request.path else '/'
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>DreadLab — 2-Step Verification Required</title></head>
        <body style="font-family: monospace; background-color: #020617; color: #e2e8f0; padding: 20px;">
            <div style="max-width: 600px; margin: 50px auto; background: #0f172a; padding: 25px; border: 1px solid #e11d48; border-radius: 8px;">
                <h1 style="color: #f43f5e; margin-top: 0;">🔒 DreadLab Member Portal</h1>
                <h2>2-Step Verification Required</h2>
                <p style="color: #cbd5e1;">This is a session-gated dark web forum. Authentication required to access private threads.</p>
                <form method="POST" action="{post_target}">
                    <div style="margin-bottom: 15px;">
                        <input type="text" name="code" placeholder="Enter 2FA Verification Code (123456)" style="width: 100%; padding: 10px; background: #1e293b; border: 1px solid #475569; color: #fff; border-radius: 4px; box-sizing: border-box;">
                    </div>
                    <button type="submit" style="background: #f43f5e; color: #fff; font-weight: bold; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer;">Authenticate Session</button>
                </form>
            </div>
        </body>
        </html>
        """, 401

def render_dreadlab_authenticated():
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>DreadLab — Authenticated Session Lounge</title></head>
    <body style="font-family: monospace; background-color: #020617; color: #e2e8f0; padding: 20px;">
        <div style="max-width: 900px; margin: 0 auto;">
            <h1 style="color: #38bdf8; border-bottom: 2px solid #38bdf8; padding-bottom: 8px;">🔒 DreadLab (Authenticated Member Portal)</h1>
            <div style="background: #1e293b; padding: 10px 15px; border-radius: 6px; margin-bottom: 20px; color: #00ff66;">
                <strong>Authenticated Profile:</strong> <span style="color: #f43f5e; font-size: 1.1em; font-weight: bold;">User Profile: Viper_X</span> (Authenticated Member &bull; Session Active)
            </div>
            <h2>Protected Private Threads</h2>
            <div class="post" style="border: 1px solid #1e293b; background: #0f172a; padding: 15px; margin-bottom: 15px; border-radius: 6px;">
                <div style="color: #f43f5e; font-weight: bold; margin-bottom: 6px;">[ACCESS SALE] ApexGlobal Financial Internal Credentials</div>
                <div style="font-size: 0.9em; color: #94a3b8; margin-bottom: 8px;">Author: <span style="color: #f43f5e;">Viper_X</span> &bull; 2026-10-02 09:00:00 UTC</div>
                <div style="color: #f1f5f9;">Selling initial RDP and SSH access credentials to ApexGlobal Financial internal network domain controller.</div>
                <div style="margin-left: 25px; padding: 10px; border-left: 3px solid #a855f7; margin-top: 12px; background: #121b24;">
                    <div style="font-size: 0.85em; color: #a855f7;">Author: <strong>CrypticGhost</strong> &bull; 2026-10-02 10:15:00 UTC</div>
                    <div style="color: #e2e8f0; margin-top: 4px;">Confirmed access works. Deploying PhantomLocker ransomware payload to target C2 infrastructure phantom-c2.lab.onion.</div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/pastevault', methods=['GET'])
@app.route('/paste', methods=['GET'])
def pastevault():
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>PasteVault — Code & Text Repository</title></head>
    <body style="font-family: monospace; background-color: #020617; color: #e2e8f0; padding: 20px;">
        <div style="max-width: 900px; margin: 0 auto;">
            <h1 style="color: #eab308; border-bottom: 2px solid #eab308; padding-bottom: 8px;">📋 PasteVault (Public Paste Service)</h1>
            <p style="color: #94a3b8;">Public Paste & Code Storage Service</p>
            <div style="border: 1px solid #334155; background: #0f172a; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                <h3 style="color: #eab308; margin-top: 0;">Paste Title: ApexGlobal Financial DB Schema & Sample Query</h3>
                <div style="color: #94a3b8; font-size: 0.85em;">Author: <span style="color: #38bdf8;">ViperSec</span> &bull; Timestamp: 2026-10-03 08:30:00 UTC</div>
                <pre style="background: #1e293b; padding: 12px; border-radius: 4px; color: #00ff66; white-space: pre-wrap;">SELECT customer_id, account_balance, hashed_password FROM apex_global_customers WHERE account_status='ACTIVE'; -- Synthetic database sample exfiltrated from ApexGlobal Financial.</pre>
            </div>
            <div style="border: 1px solid #334155; background: #0f172a; padding: 15px; border-radius: 6px;">
                <h3 style="color: #eab308; margin-top: 0;">Paste Title: ApexGlobal Financial DB Schema Mirror</h3>
                <div style="color: #94a3b8; font-size: 0.85em;">Author: <span style="color: #38bdf8;">ViperSec</span> &bull; Timestamp: 2026-10-03 08:35:00 UTC</div>
                <pre style="background: #1e293b; padding: 12px; border-radius: 4px; color: #00ff66; white-space: pre-wrap;">SELECT customer_id, account_balance, hashed_password FROM apex_global_customers WHERE account_status='ACTIVE'; -- Synthetic database sample mirror exfiltrated from ApexGlobal Financial.</pre>
            </div>
        </div>
    </body>
    </html>
    """, 200

@app.route('/leaklocker', methods=['GET'])
@app.route('/leak', methods=['GET'])
def leaklocker():
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>LeakLocker — Extortion Portal</title></head>
    <body style="font-family: monospace; background-color: #020617; color: #e2e8f0; padding: 20px;">
        <div style="max-width: 900px; margin: 0 auto;">
            <h1 style="color: #ef4444; border-bottom: 2px solid #ef4444; padding-bottom: 8px;">☣️ LeakLocker Ransomware Portal</h1>
            <p style="color: #94a3b8;">Synthetic Threat Group Ransomware & Extortion Disclosures</p>
            <div style="border: 2px solid #ef4444; background: #0f172a; padding: 20px; border-radius: 8px;">
                <h2 style="color: #ef4444; margin-top: 0;">VICTIM ANNOUNCEMENT: ApexGlobal Financial</h2>
                <div style="color: #94a3b8; font-size: 0.9em; margin-bottom: 12px;">
                    Threat Group: <strong style="color: #f97316;">PhantomLocker</strong> &bull; Published: 2026-10-03 06:00:00 UTC
                </div>
                <div style="background: #1e293b; padding: 12px; border-radius: 4px; color: #f87171; margin-bottom: 15px;">
                    Status: Countdown active (48 hours remaining until complete data publish). 500GB financial data encrypted.
                </div>
                <div style="color: #cbd5e1; line-height: 1.5;">
                    Sample references and C2 verification details hosted at: <span style="color: #38bdf8;">phantom-c2.lab.onion</span>
                </div>
            </div>
        </div>
    </body>
    </html>
    """, 200

@app.route('/market')
def market():
    return shadowforum()

@app.route('/dynamic_forum')
def dynamic_forum():
    global post_counter
    post_counter += 1
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
    return f"""
    <!DOCTYPE html>
    <html><head><title>Dynamic Underground Threat Forum</title></head>
    <body style="font-family: monospace; background: #020617; color: #e2e8f0; padding: 20px;">
        <h1>Live Breach Discussions (Dynamic Feed)</h1>
        <div class="post">User1: Selling admin credentials for enterprise network.</div>
        <div class="post dynamic">Post #{post_counter}: New activity appended at {current_time} UTC.</div>
    </body></html>
    """, 200

@app.route('/barrier')
def barrier():
    return """
    <html><head><title>503 Service Unavailable - CAPTCHA Challenge</title></head>
    <body><h1>DDoS Protection</h1><p>Please complete the CAPTCHA challenge below to proceed.</p></body></html>
    """, 503

@app.route('/session_gated/update', methods=['GET', 'POST'])
def session_gated_update():
    return jsonify({"success": True, "updates_count": 1, "added_content": "Updated"})

if __name__ == '__main__':
    load_onion_hosts()
    app.run(host='0.0.0.0', port=8080)
