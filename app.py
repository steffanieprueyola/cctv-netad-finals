import cv2, bcrypt, os
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
app.config['SECRET_KEY']        = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cctv.db')
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'

# ── Wire up extensions ──────────────────────────────────────────────
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'   # redirect here if not logged in
limiter.init_app(app)

# Talisman adds security headers (forces HTTPS, XSS protection, etc.)
# force_https=False during local dev; set True on Railway
Talisman(app, force_https=False,
         content_security_policy={
             'default-src': "'self'",
             'img-src':     '*',
             'media-src':   "'self'"
         })

# ── Helper: write a log entry ───────────────────────────────────────
def log_action(action, username="anonymous"):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    entry = ActivityLog(ip_address=ip, username=username, action=action)
    db.session.add(entry)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── SIGNUP ──────────────────────────────────────────────────────────
@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("10 per hour")        # stops mass account creation from one IP
def signup():
    if request.method == 'POST':
        username         = request.form['username'].strip()
        email            = request.form['email'].strip().lower()
        password         = request.form['password']
        confirm_password = request.form['confirm_password']

        # ── Basic validation ─────────────────────────────────────────
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

        # ── Hash and save ────────────────────────────────────────────
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(username=username, email=email,
                    password=hashed.decode('utf-8'))
        db.session.add(user)
        db.session.commit()

        log_action(f"New account signed up: {username}")
        flash("Account created! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

# ── LOGIN — limited to 5 attempts per minute per IP ────────────────
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

# ── DASHBOARD ───────────────────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    log_action("Viewed dashboard", username=current_user.username)
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(50).all()
    return render_template('dashboard.html', logs=logs)

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

# ── LOGS PAGE (admin only) ───────────────────────────────────────────
@app.route('/logs')
@login_required
def view_logs():
    if not current_user.is_admin:
        abort(403)
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template('logs.html', logs=logs)

# ── INIT DB AND RUN ──────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)


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

        # Admins cannot delete themselves
        if user_id == current_user.id:
            flash("You cannot delete your own account.", "error")
            return redirect(url_for('admin_users'))

        user = User.query.get_or_404(user_id)
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

        user = User.query.get_or_404(user_id)
        user.is_admin = True
        db.session.commit()

        log_action(f"Promoted '{user.username}' to admin",
                   username=current_user.username)
        flash(f"'{user.username}' is now an admin.", "success")
        return redirect(url_for('admin_users'))

app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
