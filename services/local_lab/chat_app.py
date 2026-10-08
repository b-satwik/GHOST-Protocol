"""
DarkWatch Local Test Lab Controlled Web Applications (Revised Architecture)
Serves 5 realistic community chat/forum services on ports 8001, 8002, 8003, 8004, and 8005.
Provides strict access gatekeeping (Tor/VPN/2FA verification) while running DarkWatch threat analysis invisibly in the background.
"""

import os
import sys
import random
import uuid
from datetime import datetime
from functools import wraps
from jinja2 import DictLoader
from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify, flash

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from services.local_lab.db import (
    verify_user, create_user, get_threads, get_thread_detail,
    create_thread, add_reply, get_post_by_id
)
from src.collector.local_lab_adapter import LocalLabAdapter

SERVICE_CONFIGS = {
    "8001": {
        "port": 8001,
        "service_id": "DIRECT_CHAT",
        "label": "Service A — Direct Chat",
        "network_path": "DIRECT",
        "auth_method": "PASSWORD_ONLY",
        "theme_color": "#2563eb",
        "requires_tor": False,
        "requires_vpn": False,
        "requires_2fa": False
    },
    "8002": {
        "port": 8002,
        "service_id": "TOR_CHAT",
        "label": "Service B — Tor Chat",
        "network_path": "TOR",
        "auth_method": "PASSWORD_ONLY",
        "theme_color": "#a855f7",
        "requires_tor": True,
        "requires_vpn": False,
        "requires_2fa": False
    },
    "8003": {
        "port": 8003,
        "service_id": "VPN_CHAT",
        "label": "Service C — VPN Chat",
        "network_path": "VPN",
        "auth_method": "PASSWORD_ONLY",
        "theme_color": "#06b6d4",
        "requires_tor": False,
        "requires_vpn": True,
        "requires_2fa": False
    },
    "8004": {
        "port": 8004,
        "service_id": "TWOFA_CHAT",
        "label": "Service D — 2FA Chat",
        "network_path": "DIRECT",
        "auth_method": "PASSWORD_PLUS_2FA",
        "theme_color": "#10b981",
        "requires_tor": False,
        "requires_vpn": False,
        "requires_2fa": True
    },
    "8005": {
        "port": 8005,
        "service_id": "NO2FA_CHAT",
        "label": "Service E — No-2FA Chat",
        "network_path": "DIRECT",
        "auth_method": "PASSWORD_ONLY",
        "theme_color": "#f59e0b",
        "requires_tor": False,
        "requires_vpn": False,
        "requires_2fa": False
    }
}

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ cfg.label }} | Community Chat</title>
    <style>
        :root {
            --primary: {{ cfg.theme_color }};
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: rgba(255,255,255,0.1);
        }
        body {
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
        }
        header {
            background-color: rgba(0,0,0,0.4);
            border-bottom: 2px solid var(--primary);
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .brand h1 {
            margin: 0;
            font-size: 1.3rem;
            color: var(--text);
        }
        nav a {
            color: var(--text);
            text-decoration: none;
            margin-left: 16px;
            font-size: 0.95rem;
        }
        nav a:hover { color: var(--primary); }
        .container {
            max-width: 900px;
            margin: 28px auto;
            padding: 0 16px;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 20px;
        }
        .btn {
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 10px 18px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover { opacity: 0.9; }
        .btn-secondary {
            background-color: rgba(255,255,255,0.1);
            color: var(--text);
        }
        .auth-box {
            max-width: 440px;
            margin: 40px auto;
        }
        .form-group {
            margin-bottom: 16px;
        }
        .form-group label {
            display: block;
            margin-bottom: 6px;
            font-size: 0.9rem;
            color: var(--muted);
        }
        .form-group input, .form-group textarea {
            width: 100%;
            padding: 10px;
            background-color: rgba(0,0,0,0.3);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            box-sizing: border-box;
            font-size: 0.95rem;
        }
        .message-bubble {
            background-color: rgba(0,0,0,0.2);
            border-left: 3px solid var(--primary);
            padding: 12px 16px;
            border-radius: 0 8px 8px 0;
            margin-bottom: 12px;
        }
        .message-meta {
            font-size: 0.8rem;
            color: var(--muted);
            margin-bottom: 4px;
            display: flex;
            justify-content: space-between;
        }
        footer {
            text-align: center;
            padding: 24px;
            color: var(--muted);
            font-size: 0.85rem;
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <h1>💬 {{ cfg.label }}</h1>
        </div>
        <nav>
            {% if session.get('authenticated') %}
                <span>Logged in as: <strong>{{ session.get('username') }}</strong></span>
                <a href="/chat">Chat Index</a>
                <a href="/new-chat" class="btn" style="padding: 6px 12px; margin-left: 12px;">+ New Conversation</a>
                <a href="/logout">Logout</a>
            {% else %}
                <a href="/login">Login</a>
                <a href="/register">Register</a>
            {% endif %}
        </nav>
    </header>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="card" style="border-color: var(--primary); padding: 12px; margin-bottom: 16px;">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <footer>
        Community Discussion Service | Port: {{ cfg.port }} | Identity: {{ cfg.service_id }}
    </footer>
</body>
</html>
"""

DENIED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ACCESS DENIED</title>
    <style>
        body {
            background-color: #0f172a;
            color: #ff5252;
            font-family: system-ui, -apple-system, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }
        .box {
            background: #1e293b;
            border: 2px solid #ff5252;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            max-width: 500px;
            box-shadow: 0 4px 20px rgba(255,82,82,0.2);
        }
        h1 { margin-top: 0; font-size: 2rem; }
        p { color: #94a3b8; line-height: 1.6; }
        .code-box {
            background: rgba(0,0,0,0.4);
            color: #ff8080;
            padding: 10px;
            font-family: monospace;
            border-radius: 6px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="box">
        <h1>⛔ ACCESS DENIED</h1>
        <p>{{ reason }}</p>
        <div class="code-box">ERROR 403: RESTRICTED NETWORK PATH</div>
    </div>
</body>
</html>
"""

def verify_network_access(cfg):
    """Verifies whether request arrives through required Tor or VPN connection path."""
    if cfg["requires_tor"]:
        # Tor verification check: Header 'X-Tor-Verified: true', param '?tor=1', or header 'X-Tor-Exit-IP'
        tor_header = request.headers.get("X-Tor-Verified", "").lower() == "true"
        tor_param = request.args.get("tor") == "1"
        tor_ip = request.headers.get("X-Tor-Exit-IP")
        if not (tor_header or tor_param or tor_ip):
            return False, "TOR CONNECTION REQUIRED. Direct access to this underground chat service is rejected."
    elif cfg["requires_vpn"]:
        # VPN verification check: Header 'X-VPN-Verified: true', param '?vpn=1', or header 'X-VPN-IP'
        vpn_header = request.headers.get("X-VPN-Verified", "").lower() == "true"
        vpn_param = request.args.get("vpn") == "1"
        vpn_ip = request.headers.get("X-VPN-IP")
        if not (vpn_header or vpn_param or vpn_ip):
            return False, "VPN TUNNEL REQUIRED. Direct connection to this service is rejected."
    return True, ""

def create_chat_app(service_id: str = "8001") -> Flask:
    cfg = SERVICE_CONFIGS.get(service_id, SERVICE_CONFIGS["8001"])
    app = Flask(f"chat_{service_id}")
    app.secret_key = f"darkwatch_chat_secret_{service_id}_key"
    app.jinja_loader = DictLoader({'base.html': BASE_TEMPLATE, 'denied.html': DENIED_TEMPLATE})

    # Network Gatekeeper Middleware
    @app.before_request
    def gatekeeper():
        # Allow static / health / circuit test without blocking
        if request.endpoint in ['health', 'tor_circuit_test']:
            return None
        allowed, reason = verify_network_access(cfg)
        if not allowed:
            return render_template_string(DENIED_TEMPLATE, reason=reason), 403

    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("authenticated"):
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated

    # --- ROUTES ---

    @app.route("/")
    def index():
        if session.get("authenticated"):
            return redirect(url_for("chat"))

        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card" style="text-align: center; padding: 40px;">
            <h2 style="color: var(--primary); font-size: 1.8rem;">Welcome to {{ cfg.label }}</h2>
            <p style="color: var(--muted); max-width: 600px; margin: 0 auto 24px auto;">
                Controlled community discussion portal. Join conversations and share messages.
            </p>
            <div>
                <a href="/login" class="btn">Login to Chat</a>
                <a href="/register" class="btn btn-secondary">Register Account</a>
            </div>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            user = verify_user(username, password)
            if user:
                session["username"] = user["username"]
                session["session_id"] = f"sess_{cfg['service_id']}_{uuid.uuid4().hex[:8]}"
                session["pwd_verified"] = True

                if cfg["requires_2fa"]:
                    session["demo_2fa_code"] = "123456"
                    session["authenticated"] = False
                    return redirect(url_for("verify_2fa"))
                else:
                    session["authenticated"] = True
                    flash(f"Welcome back, {username}!", "info")
                    return redirect(url_for("chat"))
            else:
                flash("Invalid username or password.", "error")

        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card auth-box">
            <h3 style="margin-top: 0; color: var(--primary);">Login to Community Chat</h3>
            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required placeholder="user1 or analyst">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Login</button>
            </form>
            <div style="margin-top: 16px; font-size: 0.85rem; color: var(--muted); text-align: center;">
                Test Accounts: <code>user1</code> / <code>password123</code> or <code>analyst</code> / <code>analyst123</code>
            </div>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg)

    @app.route("/verify-2fa", methods=["GET", "POST"])
    def verify_2fa():
        if not session.get("pwd_verified"):
            return redirect(url_for("login"))

        demo_code = session.get("demo_2fa_code", "123456")

        if request.method == "POST":
            code = request.form.get("code", "").strip()
            if code == demo_code:
                session["authenticated"] = True
                session["2fa_verified"] = True
                flash("2-Step Verification Successful!", "info")
                return redirect(url_for("chat"))
            else:
                flash("Invalid verification code.", "error")

        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card auth-box">
            <h3 style="margin-top: 0; color: var(--primary);">🔐 2-Step Verification</h3>
            <p style="font-size: 0.9rem; color: var(--muted);">
                Enter the 6-digit one-time code to complete login:
            </p>
            <div style="background: rgba(16,185,129,0.15); border: 1px solid var(--primary); padding: 10px; border-radius: 6px; font-weight: bold; text-align: center; margin-bottom: 16px;">
                DEMO 2FA CODE: <code>{{ demo_code }}</code>
            </div>
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="code" required placeholder="123456" style="letter-spacing: 4px; font-size: 1.2rem; text-align: center;">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Verify & Enter Chat</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg, demo_code=demo_code)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            if create_user(username, password):
                flash("Registration successful! Please login.", "info")
                return redirect(url_for("login"))
            else:
                flash("Username already exists.", "error")
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card auth-box">
            <h3 style="margin-top: 0; color: var(--primary);">Register Account</h3>
            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required placeholder="username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Register</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg)

    @app.route("/chat")
    @login_required
    def chat():
        threads = get_threads(service_id=cfg["service_id"])
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <div>
                <h2 style="margin: 0; color: var(--primary);">Conversations & Channels</h2>
                <span style="font-size: 0.9rem; color: var(--muted);">Channel Service: {{ cfg.service_id }}</span>
            </div>
            <a href="/new-chat" class="btn">+ Start New Conversation</a>
        </div>

        {% if threads %}
            {% for t in threads %}
                <div class="card" style="padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h3 style="margin: 0 0 4px 0; font-size: 1.1rem;">
                            <a href="/chat/{{ t.id }}" style="color: var(--text); text-decoration: none;">{{ t.title }}</a>
                        </h3>
                        <span style="font-size: 0.85rem; color: var(--muted);">
                            Started by <strong>{{ t.author_handle }}</strong> on {{ t.created_at[:19].replace('T', ' ') }}
                        </span>
                    </div>
                    <a href="/chat/{{ t.id }}" class="btn btn-secondary" style="font-size: 0.85rem;">View {{ t.reply_count }} Messages</a>
                </div>
            {% endfor %}
        {% else %}
            <div class="card" style="text-align: center; padding: 30px; color: var(--muted);">
                No active conversations yet. Click "+ Start New Conversation" to post!
            </div>
        {% endif %}
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg, threads=threads)

    @app.route("/chat/<int:thread_id>")
    @login_required
    def chat_detail(thread_id):
        detail = get_thread_detail(thread_id)
        if not detail:
            flash("Conversation not found.", "error")
            return redirect(url_for("chat"))

        content = """
        {% extends "base.html" %}
        {% block content %}
        <div style="margin-bottom: 16px;">
            <a href="/chat" style="color: var(--muted); text-decoration: none;">← Back to Conversations</a>
        </div>

        <div class="card" style="border-left: 4px solid var(--primary);">
            <h2 style="margin: 0;">{{ detail.title }}</h2>
            <span style="font-size: 0.85rem; color: var(--muted);">Channel ID: #{{ detail.id }}</span>
        </div>

        <h3 style="color: var(--primary); margin-top: 24px;">Messages</h3>

        {% for p in detail.posts %}
            <div class="message-bubble">
                <div class="message-meta">
                    <span><strong>{{ p.author_handle }}</strong></span>
                    <span>{{ p.timestamp[:19].replace('T', ' ') }}</span>
                </div>
                <div style="white-space: pre-wrap; font-size: 0.95rem;">{{ p.text }}</div>
            </div>
        {% endfor %}

        <div class="card" style="margin-top: 24px;">
            <h4 style="margin-top: 0; color: var(--primary);">Send Message</h4>
            <form action="/chat/{{ detail.id }}/reply" method="POST">
                <div class="form-group">
                    <textarea name="message_text" rows="3" required placeholder="Type your message..."></textarea>
                </div>
                <button type="submit" class="btn">SEND MESSAGE</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg, detail=detail)

    @app.route("/new-chat", methods=["GET", "POST"])
    @login_required
    def new_chat():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            text = request.form.get("text", "").strip()
            author_handle = session.get("username", "user1")

            if title and text:
                res = create_thread(
                    service_id=cfg["service_id"],
                    network_path=cfg["network_path"],
                    title=title,
                    author_handle=author_handle,
                    initial_text=text
                )
                thread_id = res["thread_id"]
                post_id = res["post_id"]

                # SILENT BACKGROUND OBSERVATION DISPATCH (Invisible to user)
                session_id = session.get("session_id", "sess_unknown")
                exit_ip = request.headers.get("X-Tor-Exit-IP", request.headers.get("X-VPN-IP", "192.0.2.105" if cfg["requires_tor"] else "127.0.0.1"))
                LocalLabAdapter.process_message(
                    post_id=post_id,
                    session_id=session_id,
                    network_path=cfg["network_path"],
                    tor_verified=cfg["requires_tor"],
                    vpn_verified=cfg["requires_vpn"],
                    observed_exit_ip=exit_ip
                )

                flash("Message sent!", "info")
                return redirect(url_for("chat_detail", thread_id=thread_id))

        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card">
            <h3 style="margin-top: 0; color: var(--primary);">Start New Conversation</h3>
            <form method="POST">
                <div class="form-group">
                    <label>Conversation Title / Topic</label>
                    <input type="text" name="title" required placeholder="e.g. Question about vulnerability testing">
                </div>
                <div class="form-group">
                    <label>Message Content</label>
                    <textarea name="text" rows="5" required placeholder="Type your message content..."></textarea>
                </div>
                <button type="submit" class="btn">START CONVERSATION</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg)

    @app.route("/chat/<int:thread_id>/reply", methods=["POST"])
    @login_required
    def reply(thread_id):
        text = request.form.get("message_text", "").strip()
        author_handle = session.get("username", "user1")
        if text:
            post_id = add_reply(
                thread_id=thread_id,
                service_id=cfg["service_id"],
                network_path=cfg["network_path"],
                author_handle=author_handle,
                text=text
            )

            # SILENT BACKGROUND OBSERVATION DISPATCH (Invisible to user)
            session_id = session.get("session_id", "sess_unknown")
            exit_ip = request.headers.get("X-Tor-Exit-IP", request.headers.get("X-VPN-IP", "192.0.2.105" if cfg["requires_tor"] else "127.0.0.1"))
            LocalLabAdapter.process_message(
                post_id=post_id,
                session_id=session_id,
                network_path=cfg["network_path"],
                tor_verified=cfg["requires_tor"],
                vpn_verified=cfg["requires_vpn"],
                observed_exit_ip=exit_ip
            )

            flash("Message posted!", "info")
        return redirect(url_for("chat_detail", thread_id=thread_id))

    @app.route("/tor-circuit-test")
    def tor_circuit_test():
        """Research mechanism to observe Tor circuit exit IP changes."""
        initial_ip = session.get("initial_exit_ip", "192.0.2.105")
        current_ip = request.headers.get("X-Tor-Exit-IP", request.args.get("exit_ip", initial_ip))
        
        status = "EXIT_IP_UNCHANGED"
        if "initial_exit_ip" in session and session["initial_exit_ip"] != current_ip:
            status = "CIRCUIT_CHANGED"
        else:
            session["initial_exit_ip"] = current_ip
            
        return jsonify({
            "service_id": cfg["service_id"],
            "network_path": cfg["network_path"],
            "initial_exit_ip": session.get("initial_exit_ip"),
            "current_exit_ip": current_ip,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out successfully.", "info")
        return redirect(url_for("index"))

    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service_id": cfg["service_id"],
            "port": cfg["port"],
            "network_path": cfg["network_path"],
            "auth_method": cfg["auth_method"]
        })

    return app
