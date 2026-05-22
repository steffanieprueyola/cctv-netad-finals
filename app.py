import cv2, bcrypt, os, time
from datetime import datetime
import pytz
from flask import (Flask, render_template, redirect, url_for,
                   request, flash, Response, abort)
from flask_login import (login_user, logout_user,
                         login_required, current_user)
from flask_talisman import Talisman
from dotenv import load_dotenv
from extensions import db, login_manager, limiter
from models import User, ActivityLog

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY']              = os.getenv('SECRET_KEY')
app.config['RATELIMIT_STORAGE_URI']   = 'memory://'

database_url = os.getenv('DATABASE_URL', 'sqlite:///cctv.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

# ── Wire up extensions ──────────────────────────────────────────────
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
limiter.init_app(app)

Talisman(app,
         force_https=False,
         content_security_policy={
             'default-src': "'self'",
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
                 "'unsafe-inline'"
             ],
             'img-src':   "'self' data:",
             'media-src': "'self'"
         })

# ── Helper: write a log entry ───────────────────────────────────────
def log_action(action, username="anonymous"):
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    except RuntimeError:
        ip = "127.0.0.1"
        
    ph_time = datetime.now(pytz.timezone('Asia/Manila'))
    entry = ActivityLog(ip_address=ip, username=username, action=action,
                        timestamp=ph_time.replace(tzinfo=None))
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

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
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

# ── DASHBOARD ───────────────────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    log_action("Viewed dashboard", username=current_user.username)

    if current_user.is_admin:
        logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()
        return render_template('dashboard.html', logs=logs)

    return render_template('user_dashboard.html')

# ── CAMERA STREAM GENERATOR ─────────────────────────────────────────
def generate_frames():
    rtsp_url = os.getenv('RTSP_URL')
    if not rtsp_url:
        return

    cap = cv2.VideoCapture(rtsp_url)
    
    while True:
        if cap is None or not cap.isOpened():
            time.sleep(2)
            cap = cv2.VideoCapture(rtsp_url)
            continue

        for _ in range(5):
            if cap.isOpened():
                cap.grab()
            
        success, frame = cap.read()
        if not success:
            continue

        frame = cv2.resize(frame, (854, 480), interpolation=cv2.INTER_AREA)
        _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
        
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' +
               buffer.tobytes() + b'\r\n')

# ── THE ENDPOINT ROUTE ──────────────────────────────────────────────
@app.route('/video_feed')
@login_required
def video_feed():
    log_action("Accessed video feed", username=current_user.username)
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# ── ADMIN PAGES ─────────────────────────────────────────────────────
@app.route('/logs')
@login_required
def view_logs():
    if not current_user.is_admin:
        abort(403)
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
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

# ── INITIAL SEED ROUTE ─────────────────────────────────────────────────
@app.route('/create_admin')
def create_admin():
    try:
        db.create_all()
        existing = User.query.filter_by(username='hotmariaclara').first()
        if existing:
            return "Admin already exists."
            
        hashed = bcrypt.hashpw(b'likekotsengmagaradontneedamekaniko', bcrypt.gensalt())
        admin = User(
            username='hotmariaclara',
            email='kotsengmagara@netad.com',
            password=hashed.decode('utf-8'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        return "Admin created successfully!"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=False)
