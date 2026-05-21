import cv2, bcrypt, os
from datetime import datetime
import pytz
from flask import (Flask, render_template, redirect, url_for,
                   request, flash, Response, abort)
from flask_login import (login_user, logout_user,
                         login_required, current_user)
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from extensions import db, login_manager, limiter
from models import User, ActivityLog

load_dotenv()

app = Flask(__name__)

# ── Secure Session Cookie Configurations ────────────────────────────
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents scripts from reading cookies
app.config['SESSION_COOKIE_SECURE'] = True    # Forces cookies to only be sent over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Mitigates Cross-Site Request Forgery (CSRF)

# ── Reverse Proxy Security ──────────────────────────────────────────
# If deploying on a cloud platform like Railway, this tells Flask to trust 
# the upstream proxy headers safely. Adjust x_for numbers based on your proxy setup.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

database_url = os.getenv('DATABASE_URL', 'sqlite:///cctv.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

# ── Wire up extensions ──────────────────────────────────────────────
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
limiter.init_app(app)

# Force HTTPS based on the environment (True in production, False for local testing)
IS_PRODUCTION = os.getenv('FLASK_ENV') == 'production'

Talisman(app, 
         force_https=IS_PRODUCTION,
         content_security_policy={
             'default-src': "'self'",
             'img-src':     "'self' data:", # Restricted from '*' to prevent external image exfiltration
             'media-src':   "'self'"
         })

# ── Helper: Safe Logger ─────────────────────────────────────────────
def log_action(action, username="anonymous"):
    # ProxyFix handles parsing the real client IP into request.remote_addr safely.
    # This completely mitigates manual X-Forwarded-For header injection.
    ip = request.remote_addr or "Unknown"
    
    ph_time = datetime.now(pytz.timezone('Asia/Manila'))
    entry = ActivityLog(ip_address=ip, username=username, action=action,
                        timestamp=ph_time.replace(tzinfo=None))
    db.session.add(entry)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

        log_action(f"New account signed up", username=username) # Don't rely heavily on string formatting user inputs
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

        # Constant-time comparison via bcrypt helps protect against timing attacks
        if user and bcrypt.checkpw(password.encode('utf-8'),
                                   user.password.encode('utf-8')):
            login_user(user)
            log_action("Logged in", username=username)
            return redirect(url_for('dashboard'))
        else:
            log_action("Failed login attempt", username=username)
            flash('Invalid credentials.', 'error')

    return render_template('login.html')

# ── LOGOUT ──────────────────────────────────────────────────────────
@app.route('/logout')
@login_required
def logout():
    log_action("Logged out", username=current_user.username)
    logout_user()
    return redirect(url_for('login'))

# ── DASHBOARD ───────────────────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    log_action("Viewed dashboard", username=current_user.username)
    # FIX: Logs removed entirely from the public dashboard to stop standard user information leaks.
    return render_template('dashboard.html')

# ── CAMERA STREAM ───────────────────────────────────────────────────
def generate_frames():
    rtsp_url = os.getenv('RTSP_URL')
    if not rtsp_url:
        return
    cap = cv2.VideoCapture(rtsp_url)
    if not cap.isOpened():
        return
    while True:
        success, frame = cap.read()
        if not success:
            break
        _, buffer = cv2.imencode('.jpg', frame)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' +
               buffer.tobytes() + b'\r\n')

@app.route('/video_feed')
@login_required
def video_feed():
    log_action("Accessed video feed", username=current_user.username)
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# ── LOGS PAGE ───────────────────────────────────────────────────────
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

    user = User.query.get_or_404(user_id)
    username_deleted = user.username
    db.session.delete(user)
    db.session.commit()

    log_action(f"Deleted user", username=current_user.username)
    flash(f"User '{username_deleted}' has been deleted.", "success")
    return redirect(url_for('admin_users'))

# ── ADMIN: Promote a user to admin ──────────────────────────────────
@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()

    log_action(f"Promoted user to admin", username=current_user.username)
    flash(f"'{user.username}' is now an admin.", "success")
    return redirect(url_for('admin_users'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Never leave debug=True in production code, handled cleanly here
    app.run(debug=False)
