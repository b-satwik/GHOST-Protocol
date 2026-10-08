"""
DarkWatch Local Test Lab Forum Web Application Factory
Serves full browser-based underground forum/chat sites on ports 8001, 8002, 8003, and 8004.
"""

import os
import sys
import json
import random
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
        "service_id": "8001",
        "access_mode": "DIRECT",
        "domain_identity": "darkwatch-direct.local",
        "label": "DIRECT LOCAL SERVICE",
        "auth_method": "PASSWORD_ONLY",
        "theme_color": "#2563eb", # Blue
        "bg_color": "#0f172a",
        "card_bg": "#1e293b",
        "banner_text": "DIRECT LOCAL SERVICE — LOCAL SYNTHETIC RESEARCH LAB",
        "requires_2fa": False,
        "requires_captcha": False
    },
    "8002": {
        "port": 8002,
        "service_id": "8002",
        "access_mode": "TOR_SIMULATED",
        "domain_identity": "shadowforum.lab.onion",
        "label": "TOR-LIKE LOCAL SIMULATION",
        "auth_method": "PASSWORD_ONLY",
        "theme_color": "#a855f7", # Purple
        "bg_color": "#0b0f19",
        "card_bg": "#181825",
        "banner_text": "TOR-LIKE LOCAL SIMULATION — This is NOT a real .onion service and does not connect to Tor.",
        "requires_2fa": False,
        "requires_captcha": False
    },
    "8003": {
        "port": 8003,
        "service_id": "8003",
        "access_mode": "VPN_SIMULATED",
        "domain_identity": "darkwatch-vpn-sim.local",
        "label": "VPN-LIKE LOCAL SIMULATION",
        "auth_method": "PASSWORD_PLUS_2FA",
        "theme_color": "#06b6d4", # Cyan
        "bg_color": "#062026",
        "card_bg": "#0e3a43",
        "banner_text": "VPN-LIKE LOCAL SIMULATION — 2-STEP VERIFICATION ENABLED",
        "requires_2fa": True,
        "requires_captcha": False
    },
    "8004": {
        "port": 8004,
        "service_id": "8004",
        "access_mode": "CAPTCHA_PROTECTED",
        "domain_identity": "darkwatch-captcha.local",
        "label": "CAPTCHA-PROTECTED LOCAL SIMULATION",
        "auth_method": "PASSWORD_PLUS_CAPTCHA",
        "theme_color": "#f59e0b", # Amber
        "bg_color": "#1c1002",
        "card_bg": "#2e1a04",
        "banner_text": "CAPTCHA-PROTECTED LOCAL SIMULATION — LOGIN + CAPTCHA REQUIRED",
        "requires_2fa": False,
        "requires_captcha": True
    }
}

# --- HTML TEMPLATE ---
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ cfg.label }} | DarkWatch Research Forum</title>
    <style>
        :root {
            --primary: {{ cfg.theme_color }};
            --bg: {{ cfg.bg_color }};
            --card-bg: {{ cfg.card_bg }};
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
        .simulation-banner {
            background-color: var(--primary);
            color: #ffffff;
            padding: 8px 16px;
            font-weight: 700;
            text-align: center;
            font-size: 0.88rem;
            letter-spacing: 0.5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        header {
            background-color: rgba(0,0,0,0.4);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .brand h1 {
            margin: 0;
            font-size: 1.3rem;
            color: var(--text);
        }
        .onion-badge {
            background-color: rgba(255,255,255,0.1);
            color: var(--primary);
            border: 1px solid var(--primary);
            padding: 4px 10px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85rem;
        }
        nav a {
            color: var(--text);
            text-decoration: none;
            margin-left: 16px;
            font-size: 0.95rem;
            opacity: 0.9;
            transition: opacity 0.2s;
        }
        nav a:hover { opacity: 1; color: var(--primary); }
        .container {
            max-width: 1100px;
            margin: 24px auto;
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
        .form-group input, .form-group textarea, .form-group select {
            width: 100%;
            padding: 10px;
            background-color: rgba(0,0,0,0.3);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            box-sizing: border-box;
            font-size: 0.95rem;
        }
        .post-card {
            border-left: 4px solid var(--primary);
            margin-bottom: 16px;
            padding: 16px;
            background-color: rgba(0,0,0,0.2);
            border-radius: 0 8px 8px 0;
        }
        .post-meta {
            font-size: 0.85rem;
            color: var(--muted);
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
        }
        .darkwatch-analysis {
            background-color: rgba(15, 23, 42, 0.9);
            border: 1px solid #00e676;
            border-radius: 8px;
            padding: 16px;
            margin-top: 14px;
            font-size: 0.9rem;
        }
        .darkwatch-analysis h4 {
            margin: 0 0 10px 0;
            color: #00e676;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .severity-HIGH { color: #ff5252; font-weight: bold; }
        .severity-ELEVATED { color: #ff9100; font-weight: bold; }
        .severity-MODERATE { color: #ffd600; font-weight: bold; }
        .severity-LOW { color: #00e676; font-weight: bold; }
        .indicator-tag {
            background: rgba(255,255,255,0.1);
            padding: 2px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8rem;
            margin-right: 4px;
        }
        .cat-badge {
            background-color: rgba(255,255,255,0.1);
            color: var(--primary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
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
    <div class="simulation-banner">
        ⚠️ {{ cfg.banner_text }}
    </div>
    <header>
        <div class="brand">
            <h1>🛡️ DARKWATCH FORUM</h1>
            <span class="onion-badge">Address: {{ cfg.domain_identity }}</span>
        </div>
        <nav>
            {% if session.get('authenticated') %}
                <span>Logged in as: <strong>{{ session.get('username') }}</strong></span>
                <a href="/forum">Forum Home</a>
                <a href="/new-thread" class="btn" style="padding: 6px 12px; margin-left: 12px;">+ New Thread</a>
                <a href="/profile">Profile</a>
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
        DarkWatch Local Synthetic Research Lab | Mode: {{ cfg.access_mode }} | Auth: {{ cfg.auth_method }} | Port: {{ cfg.port }}
    </footer>
</body>
</html>
"""

def create_forum_app(service_id: str = "8001") -> Flask:
    cfg = SERVICE_CONFIGS.get(service_id, SERVICE_CONFIGS["8001"])
    app = Flask(f"forum_{service_id}")
    app.secret_key = f"darkwatch_secret_{service_id}_key_2026"
    app.jinja_loader = DictLoader({'base.html': BASE_TEMPLATE})
    
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
            return redirect(url_for("forum"))
        
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card" style="text-align: center; padding: 40px;">
            <h2 style="color: var(--primary); font-size: 2rem;">Welcome to DARKWATCH FORUM</h2>
            <p style="color: var(--muted); max-width: 600px; margin: 0 auto 24px auto;">
                Local synthetic demonstration network for testing DarkWatch access modes, threat categorization, CTI extraction, and XAI explanations.
            </p>
            <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border); padding: 16px; border-radius: 8px; display: inline-block; margin-bottom: 24px; text-align: left;">
                <div><strong>Visual Identity:</strong> {{ cfg.domain_identity }}</div>
                <div><strong>Simulated Access Mode:</strong> {{ cfg.access_mode }}</div>
                <div><strong>Authentication Method:</strong> {{ cfg.auth_method }}</div>
                <div><strong>Real Connection:</strong> <code>http://127.0.0.1:{{ cfg.port }}</code></div>
            </div>
            <div>
                <a href="/login" class="btn">Login to Synthetic Forum</a>
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
                session["pwd_verified"] = True
                
                # Check multi-factor requirements
                if cfg["requires_2fa"]:
                    # Generate 6-digit TOTP/demo 2FA code
                    code = "123456" # Simple predictable demo 2FA code
                    session["demo_2fa_code"] = code
                    session["authenticated"] = False
                    return redirect(url_for("verify_2fa"))
                elif cfg["requires_captcha"]:
                    # Generate simple math captcha
                    n1 = random.randint(3, 9)
                    n2 = random.randint(2, 9)
                    session["captcha_ans"] = str(n1 + n2)
                    session["captcha_q"] = f"What is {n1} + {n2}?"
                    session["authenticated"] = False
                    return redirect(url_for("captcha"))
                else:
                    session["authenticated"] = True
                    flash(f"Welcome back, {username}! Access mode: {cfg['label']}", "info")
                    return redirect(url_for("forum"))
            else:
                flash("Invalid username or password.", "error")
                
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card auth-box">
            <h3 style="margin-top: 0; color: var(--primary);">Login — {{ cfg.label }}</h3>
            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required placeholder="e.g. analyst or user1">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Continue to Login</button>
            </form>
            <div style="margin-top: 16px; font-size: 0.85rem; color: var(--muted); text-align: center;">
                Test Credentials: <code>analyst</code> / <code>analyst123</code> or <code>user1</code> / <code>password123</code>
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
            user_code = request.form.get("code", "").strip()
            if user_code == demo_code:
                session["authenticated"] = True
                session["2fa_verified"] = True
                flash(f"2-Step Verification Successful! Welcome {session.get('username')}.", "info")
                return redirect(url_for("forum"))
            else:
                flash("Invalid verification code. Try again.", "error")
                
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card auth-box">
            <h3 style="margin-top: 0; color: var(--primary);">🔐 2-Step Verification</h3>
            <p style="font-size: 0.9rem; color: var(--muted);">
                Port 8003 requires two-step verification. Enter the 6-digit one-time code below:
            </p>
            <div style="background: rgba(6,182,212,0.15); border: 1px solid var(--primary); padding: 12px; border-radius: 6px; font-weight: bold; text-align: center; font-size: 1.1rem; margin-bottom: 16px;">
                DEMO 2FA CODE: <code>{{ demo_code }}</code>
            </div>
            <form method="POST">
                <div class="form-group">
                    <label>Enter 6-Digit Code</label>
                    <input type="text" name="code" required placeholder="123456" style="letter-spacing: 4px; font-size: 1.2rem; text-align: center;">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Verify 2FA & Enter Forum</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg, demo_code=demo_code)

    @app.route("/captcha", methods=["GET", "POST"])
    def captcha():
        if not session.get("pwd_verified"):
            return redirect(url_for("login"))
            
        question = session.get("captcha_q", "What is 5 + 3?")
        expected = session.get("captcha_ans", "8")
        
        if request.method == "POST":
            answer = request.form.get("captcha_answer", "").strip()
            if answer == expected:
                session["authenticated"] = True
                session["captcha_verified"] = True
                flash(f"CAPTCHA Solved! Welcome {session.get('username')}.", "info")
                return redirect(url_for("forum"))
            else:
                flash("Incorrect CAPTCHA answer. Try again.", "error")
                
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card auth-box">
            <h3 style="margin-top: 0; color: var(--primary);">🤖 Local CAPTCHA Challenge</h3>
            <p style="font-size: 0.9rem; color: var(--muted);">
                Port 8004 requires a simple CAPTCHA verification step after password authentication.
            </p>
            <form method="POST">
                <div class="form-group">
                    <label style="font-size: 1.1rem; color: var(--primary); font-weight: bold;">{{ question }}</label>
                    <input type="text" name="captcha_answer" required placeholder="Enter number..." style="font-size: 1.1rem;">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Submit Answer & Enter Forum</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg, question=question)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            if create_user(username, password):
                flash("Registration successful! You may now login.", "info")
                return redirect(url_for("login"))
            else:
                flash("Username already exists.", "error")
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card auth-box">
            <h3 style="margin-top: 0; color: var(--primary);">Register Synthetic Account</h3>
            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required placeholder="synthetic_user_01">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Create Account</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg)

    @app.route("/forum")
    @login_required
    def forum():
        category = request.args.get("category")
        threads = get_threads(service_id=cfg["service_id"], category=category)
        categories = ["Security", "Marketplace", "Malware", "Leaks", "Exploit Discussion", "Ransomware", "Research", "General"]
        
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <div>
                <h2 style="margin: 0; color: var(--primary);">Underground Discussion Board</h2>
                <span style="font-size: 0.9rem; color: var(--muted);">Access Mode: {{ cfg.label }} | Logged in: <strong>{{ session.get('username') }}</strong></span>
            </div>
            <a href="/new-thread" class="btn">+ Create New Thread</a>
        </div>

        <div style="display: grid; grid-template-columns: 240px 1fr; gap: 20px;">
            <div class="card" style="padding: 16px;">
                <h4 style="margin-top: 0; color: var(--primary);">Categories</h4>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <a href="/forum" style="color: var(--text); text-decoration: none; font-weight: bold;">All Discussions</a>
                    {% for cat in categories %}
                        <a href="/forum?category={{ cat }}" style="color: var(--muted); text-decoration: none; font-size: 0.95rem;">• {{ cat }}</a>
                    {% endfor %}
                </div>
            </div>

            <div>
                {% if threads %}
                    {% for t in threads %}
                        <div class="card" style="padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <span class="cat-badge">{{ t.category }}</span>
                                <h3 style="margin: 6px 0; font-size: 1.1rem;">
                                    <a href="/thread/{{ t.id }}" style="color: var(--text); text-decoration: none;">{{ t.title }}</a>
                                </h3>
                                <span style="font-size: 0.85rem; color: var(--muted);">
                                    Posted by <strong>{{ t.author_handle }}</strong> on {{ t.created_at[:19].replace('T', ' ') }}
                                </span>
                            </div>
                            <div style="text-align: right;">
                                <span class="btn btn-secondary" style="font-size: 0.85rem; padding: 4px 10px;">{{ t.reply_count }} Posts</span>
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    <div class="card" style="text-align: center; padding: 30px; color: var(--muted);">
                        No threads found in this category. Click "+ Create New Thread" to start one!
                    </div>
                {% endif %}
            </div>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg, threads=threads, categories=categories)

    @app.route("/thread/<int:thread_id>")
    @login_required
    def thread_detail(thread_id):
        detail = get_thread_detail(thread_id)
        if not detail:
            flash("Thread not found.", "error")
            return redirect(url_for("forum"))
            
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div style="margin-bottom: 16px;">
            <a href="/forum" style="color: var(--muted); text-decoration: none;">← Back to Forum Index</a>
        </div>

        <div class="card" style="border-left: 4px solid var(--primary);">
            <span class="cat-badge">{{ detail.category }}</span>
            <h2 style="margin: 8px 0 16px 0;">{{ detail.title }}</h2>
            <div style="font-size: 0.85rem; color: var(--muted);">
                Thread ID: #{{ detail.id }} | Service: {{ cfg.domain_identity }}
            </div>
        </div>

        <h3 style="color: var(--primary); margin-top: 24px;">Posts & Replies</h3>

        {% for p in detail.posts %}
            <div class="post-card">
                <div class="post-meta">
                    <span><strong>Author:</strong> {{ p.author_handle }}</span>
                    <span>{{ p.timestamp[:19].replace('T', ' ') }}</span>
                </div>
                <div style="font-size: 1rem; white-space: pre-wrap; margin-bottom: 12px;">{{ p.text }}</div>
                
                {% if p.predicted_class %}
                    <div class="darkwatch-analysis">
                        <h4>🛡️ DARKWATCH LIVE PIPELINE ANALYSIS</h4>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 10px;">
                            <div><strong>Category:</strong> <span style="color: var(--primary);">{{ p.predicted_class }}</span></div>
                            <div><strong>Risk Score:</strong> <span class="severity-{{ p.risk_severity }}">{{ p.risk_score }} / 1.0</span></div>
                            <div><strong>Severity:</strong> <span class="severity-{{ p.risk_severity }}">{{ p.risk_severity }}</span></div>
                        </div>
                        
                        {% if p.extracted_indicators %}
                            <div style="margin-bottom: 8px;">
                                <strong>Extracted CTI Indicators:</strong>
                                {% for ind in p.extracted_indicators if ind is string %}
                                    <span class="indicator-tag">{{ ind }}</span>
                                {% endfor %}
                            </div>
                        {% endif %}

                        {% if p.mitre_techniques %}
                            <div style="margin-bottom: 8px;">
                                <strong>MITRE ATT&CK Mappings:</strong>
                                {% for m in p.mitre_techniques if m is string %}
                                    <span class="indicator-tag" style="border-color: #00e676;">{{ m }}</span>
                                {% endfor %}
                            </div>
                        {% endif %}

                        <div style="margin-top: 8px; font-size: 0.85rem; color: var(--muted); border-top: 1px dashed var(--border); padding-top: 6px;">
                            <strong>XAI Explanation:</strong> {{ p.xai_explanation }}
                        </div>
                    </div>
                {% else %}
                    <div class="darkwatch-analysis" style="border-color: var(--muted); color: var(--muted);">
                        🛡️ DarkWatch Analysis pending...
                    </div>
                {% endif %}
            </div>
        {% endfor %}

        <div class="card" style="margin-top: 30px;">
            <h4 style="margin-top: 0; color: var(--primary);">Write a Reply</h4>
            <form action="/reply/{{ detail.id }}" method="POST">
                <div class="form-group">
                    <textarea name="reply_text" rows="4" required placeholder="Type your discussion post here (e.g. discussing a test vulnerability or IOC)..."></textarea>
                </div>
                <button type="submit" class="btn">Submit Reply</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg, detail=detail)

    @app.route("/new-thread", methods=["GET", "POST"])
    @login_required
    def new_thread():
        if request.method == "POST":
            category = request.form.get("category", "General")
            title = request.form.get("title", "").strip()
            text = request.form.get("text", "").strip()
            author_handle = session.get("username", "user1")
            
            if title and text:
                post_id = create_thread(
                    service_id=cfg["service_id"],
                    access_mode=cfg["access_mode"],
                    category=category,
                    title=title,
                    author_handle=author_handle,
                    initial_text=text
                )
                # Immediately process through DarkWatch Pipeline!
                LocalLabAdapter.process_post(post_id)
                
                # Retrieve thread_id to redirect
                post = get_post_by_id(post_id)
                flash("New thread posted! DarkWatch analyzed your message.", "info")
                return redirect(url_for("thread_detail", thread_id=post["thread_id"]))
                
        categories = ["Security", "Marketplace", "Malware", "Leaks", "Exploit Discussion", "Ransomware", "Research", "General"]
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card">
            <h3 style="margin-top: 0; color: var(--primary);">Create New Thread</h3>
            <form method="POST">
                <div class="form-group">
                    <label>Category</label>
                    <select name="category">
                        {% for c in categories %}
                            <option value="{{ c }}">{{ c }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                    <label>Thread Title</label>
                    <input type="text" name="title" required placeholder="e.g. Synthetic vulnerability discussion on example.local">
                </div>
                <div class="form-group">
                    <label>Message Content (User Input for DarkWatch NLP Analysis)</label>
                    <textarea name="text" rows="6" required placeholder="Type your synthetic threat or security text here..."></textarea>
                </div>
                <button type="submit" class="btn">POST THREAD & ANALYZE</button>
            </form>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg, categories=categories)

    @app.route("/reply/<int:thread_id>", methods=["POST"])
    @login_required
    def reply(thread_id):
        text = request.form.get("reply_text", "").strip()
        author_handle = session.get("username", "user1")
        if text:
            post_id = add_reply(
                thread_id=thread_id,
                service_id=cfg["service_id"],
                access_mode=cfg["access_mode"],
                author_handle=author_handle,
                text=text
            )
            # Immediately process through DarkWatch Pipeline!
            LocalLabAdapter.process_post(post_id)
            flash("Reply submitted and analyzed by DarkWatch!", "info")
        return redirect(url_for("thread_detail", thread_id=thread_id))

    @app.route("/profile")
    @login_required
    def profile():
        content = """
        {% extends "base.html" %}
        {% block content %}
        <div class="card" style="max-width: 500px; margin: 0 auto;">
            <h3 style="margin-top: 0; color: var(--primary);">User Profile</h3>
            <div style="line-height: 2;">
                <div><strong>Username:</strong> {{ session.get('username') }}</div>
                <div><strong>Current Service Port:</strong> {{ cfg.port }}</div>
                <div><strong>Simulated Access Mode:</strong> {{ cfg.access_mode }}</div>
                <div><strong>Auth Method:</strong> {{ cfg.auth_method }}</div>
                <div><strong>Session Status:</strong> Authenticated</div>
            </div>
            <div style="margin-top: 20px;">
                <a href="/logout" class="btn btn-secondary">Logout</a>
            </div>
        </div>
        {% endblock %}
        """
        return render_template_string(content, cfg=cfg)

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out successfully.", "info")
        return redirect(url_for("index"))

    # --- API ENDPOINTS ---
    
    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service_id": cfg["service_id"],
            "port": cfg["port"],
            "access_mode": cfg["access_mode"]
        })

    @app.route("/api/access-info")
    def access_info():
        return jsonify({
            "service_id": cfg["service_id"],
            "access_mode": cfg["access_mode"],
            "authentication_method": cfg["auth_method"],
            "requires_2fa": cfg["requires_2fa"],
            "requires_captcha": cfg["requires_captcha"],
            "authenticated": bool(session.get("authenticated")),
            "session_user": session.get("username"),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

    @app.route("/api/posts", methods=["GET"])
    def api_posts():
        if not session.get("authenticated"):
            return jsonify({"error": "Unauthorized"}), 401
        threads = get_threads(service_id=cfg["service_id"])
        return jsonify({"service_id": cfg["service_id"], "threads": threads})

    return app
