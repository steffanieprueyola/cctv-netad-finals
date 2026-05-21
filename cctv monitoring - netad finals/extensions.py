from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()

# Rate limiter — uses the visitor's IP address as the key
limiter = Limiter(key_func=get_remote_address)
