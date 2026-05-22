import os
import bcrypt
from datetime import datetime

import pytz
from flask import (Flask, render_template, redirect, url_for,
                   request, flash, abort, jsonify)
from flask_login import (login_user, logout_user,
                         login_required, current_user)
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from dotenv import load_dotenv
from extensions import db, login_manager, limiter
from models import User, ActivityLog

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY']            = os.getenv('SECRET_KEY')
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
app.config['WTF_CSRF_TIME_LIMIT']   = None   # tokens don't expire mid-session

database_url = os.getenv('DATABASE_URL', 'sqlite:///cctv.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

# ── Wire up extensions ──────────────────────────────────────────────
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
limiter.init_app(app)
csrf = CSRFProtect(app)

Talisman(app,
         force_https=False,
         content_security_policy={
             'default-src': "'self'",
             'style-src': [
                 "'self'",
                 "'unsafe-inline'",
                 "https://fonts.googleapis.com",
                 "https://cdnjs.cloudflare.com",
             ],
             'font-src': [
                 "'self'",
                 "https://fonts.gstatic.com",
                 "https://cdnjs.cloudflare.com",
             ],
             'script-src': [
                 "'self'",
                 "'unsafe-inline'",
                 # hls.js CDN
                 "https://cdn.jsdelivr.net",
             ],
             # Allow the browser to fetch HLS segments from MediaMTX.
             # MEDIAMTX_HLS_ORIGIN should be e.g. "https://xxxx.ngrok-free.app"
             'connect-src': [
                 "'self'",
                 os.getenv('MEDIAMTX_HLS_ORIGIN', ''),
             ],
             'img-src':   "'self' data:",
             'media-src': [
                 "'self'",
                 # HLS .ts segments are loaded as media by some browsers
                 os.getenv('MEDIAMTX_HLS_ORIGIN', ''),
             ],
         })


# ── Helper: write a log entry ───────────────────────────────────────
def log_action(action, username="anonymous"):
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    except RuntimeError:
        ip = "127.0.0.1"
    ph_time = datetime.now(pytz.timezone('Asia/Manila'))
    entry = ActivityLog(
        ip_address=ip,
        username=username,
        action=action,
        timestamp=ph_time.replace(tzinfo=None),
    )
    db.session.add(entry)
    db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ── SIGNUP ──────────────────────────────────────────────────────────
@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def signup():
    if request.method == 'POST':
        username         = request.form['username'].strip()
        email            = request.form['email'].strip().lower()
        password         = request.form['password']
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
        user = User(username=username, email=email,
                    password=hashed.decode('utf-8'))
        db.session.add(user)
        db.session.commit()
        log_action(f"New account signed up: {username}")
        flash("Account created! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')


# ── LOGIN ───────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'),
                                   user.password.encode('utf-8')):
            login_user(user)
            log_action("Logged in", username=username)
            return redirect(url_for('dashboard'))
        else:
            log_action(f"Failed login attempt for '{username}'")
            flash('Invalid credentials.', 'error')

    return render_template('login.html')


# ── LOGOUT ──────────────────────────────────────────────────────────
@app.route('/logout')
@login_required
def logout():
    log_action("Logged out", username=current_user.username)
    logout_user()
    return redirect(url_for('login'))


# ── HLS STREAM URL ──────────────────────────────────────────────────
# MediaMTX serves the HLS playlist directly to the browser.
# This endpoint just hands the authenticated client the URL so
# the template can pass it to hls.js — the video data never touches Flask.
#
# Set MEDIAMTX_HLS_URL in your .env, e.g.:
#   MEDIAMTX_HLS_URL=https://xxxx.ngrok-free.app/cam/index.m3u8
@app.route('/stream_url')
@login_required
def stream_url():
    hls_url = os.getenv('MEDIAMTX_HLS_URL')
    if not hls_url:
        return jsonify({'error': 'Stream not configured'}), 503
    log_action("Fetched stream URL", username=current_user.username)
    return jsonify({'url': hls_url})


# ── DASHBOARD ───────────────────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    log_action("Viewed dashboard", username=current_user.username)
    if current_user.is_admin:
        logs = ActivityLog.query.order_by(
            ActivityLog.timestamp.desc()).limit(50).all()
        return render_template('dashboard.html', logs=logs)
    return render_template('user_dashboard.html')


# ── LOGS PAGE ────────────────────────────────────────────────────────
@app.route('/logs')
@login_required
def view_logs():
    if not current_user.is_admin:
        abort(403)
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template('logs.html', logs=logs)


# ── ADMIN: View all users ────────────────────────────────────────────
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.order_by(User.created_at.desc()).all()
    log_action("Viewed user list", username=current_user.username)
    return render_template('admin_users.html', users=users)


# ── ADMIN: Delete a user ─────────────────────────────────────────────
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('admin_users'))
    user = db.get_or_404(User, user_id)
    username_deleted = user.username
    db.session.delete(user)
    db.session.commit()
    log_action(f"Deleted user '{username_deleted}'",
               username=current_user.username)
    flash(f"User '{username_deleted}' has been deleted.", "success")
    return redirect(url_for('admin_users'))


# ── ADMIN: Promote a user to admin ──────────────────────────────────
@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = db.get_or_404(User, user_id)
    user.is_admin = True
    db.session.commit()
    log_action(f"Promoted '{user.username}' to admin",
               username=current_user.username)
    flash(f"'{user.username}' is now an admin.", "success")
    return redirect(url_for('admin_users'))


# ── INIT DB AND RUN ──────────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False)
