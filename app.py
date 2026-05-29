import os
import re
import time
import requests
import bcrypt
from datetime import datetime
import pytz
from flask import (
    Flask, Response, render_template, request,
    redirect, url_for, flash, jsonify, abort
)
from flask_login import (
    login_user, logout_user,
    login_required, current_user
)
import traceback
import logging
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from dotenv import load_dotenv

from extensions import db, login_manager, limiter
from models import User, ActivityLog

load_dotenv()

app = Flask(__name__)

# ── CONFIG ─────────────────────────────────────────────
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
app.config['WTF_CSRF_TIME_LIMIT'] = None

database_url = os.getenv('DATABASE_URL', 'sqlite:///cctv.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url

# ── EXTENSIONS ─────────────────────────────────────────
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
limiter.init_app(app)
csrf = CSRFProtect(app)

# ── USER LOADER ────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── SECURITY HEADERS ───────────────────────────────────
Talisman(app,
    content_security_policy={
        'default-src': ["'self'"],
        'style-src': [
            "'self'",
            "'unsafe-inline'",
            "https://fonts.googleapis.com",
            "https://cdnjs.cloudflare.com"
        ],
        'font-src': [
            "'self'",
            "https://fonts.gstatic.com",
            "https://cdnjs.cloudflare.com"
        ],
        'script-src': [
            "'self'",
            "'unsafe-inline'",
            "https://cdn.jsdelivr.net"
        ],
        'connect-src': [
            "'self'",
            "blob:",
            "https://cdn.jsdelivr.net"
        ],
        'img-src': ["'self'", "data:"],
        'media-src': ["'self'", "blob:", "https://cdn.jsdelivr.net"]
    }
)

# ── HELPERS ────────────────────────────────────────────
def log_action(action, username="anonymous"):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ph_time = datetime.now(pytz.timezone('Asia/Manila'))
    entry = ActivityLog(
        ip_address=ip,
        username=username,
        action=action,
        timestamp=ph_time.replace(tzinfo=None)
    )
    db.session.add(entry)
    db.session.commit()

# ── HLS STREAM PROXY ───────────────────────────────────
@app.route('/stream_proxy/<path:filename>')
@login_required
def stream_proxy(filename):
    base_url = os.getenv('MEDIAMTX_HLS_URL')
    target_url = f"{base_url.rstrip('/')}/{filename}"

    session = requests.Session()
    session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/vnd.apple.mpegurl, application/x-mpegURL, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Authorization": "Bearer mysecret123",
})

    try:
        resp = session.get(target_url, timeout=10, stream=False, allow_redirects=True)
        
        if resp.status_code == 401 or 'cookieCheck' in resp.url:
            domain = base_url.split("//")[1].split("/")[0]
            session.cookies.set("cookieCheck", "1", domain=domain)
            session.cookies.set("hlsSession", "proxy-session", domain=domain)
            resp = session.get(target_url, timeout=10, stream=True, allow_redirects=True)
        
        resp.raise_for_status()

        if filename.endswith('.m3u8'):
            content = resp.text
            content = content.replace(base_url.rstrip('/'), '/stream_proxy')
            def rewrite(match):
                segment = match.group(0)
                if segment.startswith('http'):
                    return segment
                return f'/stream_proxy/{segment}'
            content = re.sub(r'(?m)^(?!#)(\S+)$', rewrite, content)
            return Response(content, status=200, content_type='application/vnd.apple.mpegurl')

        return Response(
            resp.iter_content(chunk_size=1024),
            status=resp.status_code,
            headers=dict(resp.headers)
        )
    except Exception:
        logging.error(f"Failed stream proxy: {target_url}\n{traceback.format_exc()}")
        return "Internal Proxy Error", 500

# ── AUTH ROUTES ────────────────────────────────────────
@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return redirect(url_for('signup'))

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(
            username=username,
            email=email,
            password=hashed.decode('utf-8')
        )
        db.session.add(user)
        db.session.commit()
        log_action(f"New account signed up: {username}")
        flash("Account created! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(
            password.encode('utf-8'),
            user.password.encode('utf-8')
        ):
            login_user(user)
            log_action("Logged in", username=username)
            return redirect(url_for('dashboard'))

        log_action(f"Failed login attempt for '{username}'")
        flash('Invalid credentials.', 'error')

    return render_template('login.html')


# ── DASHBOARD ──────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    log_action("Viewed dashboard", username=current_user.username)

    if current_user.is_admin:
        logs = ActivityLog.query.order_by(
            ActivityLog.timestamp.desc()
        ).limit(50).all()
        return render_template('dashboard.html', logs=logs)

    return render_template('user_dashboard.html', logs=[])


# ── LOGOUT ─────────────────────────────────────────────
@app.route('/logout')
@login_required
def logout():
    log_action("Logged out", username=current_user.username)
    logout_user()
    return redirect(url_for('login'))


# ── ADMIN / LOGS ───────────────────────────────────────
@app.route('/logs')
@login_required
def view_logs():
    if not current_user.is_admin:
        abort(403)
    logs = ActivityLog.query.order_by(
        ActivityLog.timestamp.desc()
    ).all()
    return render_template('logs.html', logs=logs)


@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.order_by(User.created_at.desc()).all()
    log_action("Viewed user list", username=current_user.username)
    return render_template('admin_users.html', users=users)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('admin_users'))
    user = User.query.get_or_404(user_id)
    username_deleted = user.username
    db.session.delete(user)
    db.session.commit()
    log_action(f"Deleted user '{username_deleted}'", username=current_user.username)
    flash(f"User '{username_deleted}' has been deleted.", "success")
    return redirect(url_for('admin_users'))


@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    log_action(f"Promoted '{user.username}' to admin", username=current_user.username)
    flash(f"'{user.username}' is now an admin.", "success")
    return redirect(url_for('admin_users'))


# ── STREAM URL ─────────────────────────────────────────
@app.route('/stream_url')
@login_required
def stream_url():
    return jsonify({
        "stream_url": "/stream_proxy/index.m3u8"
    })


# ── DB INIT ────────────────────────────────────────────
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=False)
