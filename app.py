import os
import bcrypt
import requests
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
app.config['WTF_CSRF_TIME_LIMIT']   = None 

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

# Updated Talisman configuration
Talisman(app,
         force_https=False,
         content_security_policy={
             'default-src': ["'self'"],
             'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
             'font-src': ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
             'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
             'connect-src': ["'self'", "blob:"],
             'img-src': ["'self'", "data:"],
             'media-src': ["'self'", "blob:"],
         })

# ── HLS PROXY ROUTE ─────────────────────────────────────────────────
@app.route('/stream_proxy/<path:filename>')
@login_required
def stream_proxy(filename):
    hls_url = os.getenv('MEDIAMTX_HLS_URL', 'http://localhost:8888/cam/index.m3u8')
    base_url = hls_url.replace('index.m3u8', '')
    url = f"{base_url}{filename}"
    try:
        resp = requests.get(url, timeout=5)
        content_type = 'application/x-mpegURL' if filename.endswith('.m3u8') else 'video/MP2T'
        return resp.content, resp.status_code, {'Content-Type': content_type}
    except Exception as e:
        return f"Proxy Error", 500

# ... (Keep all your existing helper and admin route functions below) ...

# ── INIT DB AND RUN ──────────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False)
