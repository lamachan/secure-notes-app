from datetime import datetime
from flask_login import UserMixin
import pyotp

from app import db

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    salt = db.Column(db.String(10), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    two_fa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    two_fa_secret = db.Column(db.String, unique=True)

    def __init__(self, username, password, salt):
        self.username = username
        self.password = password
        self.salt = salt
        self.creation_date = datetime.now()
        self.two_fa_secret = pyotp.random_base32()

    def get_two_fa_uri(self):
        return pyotp.totp.TOTP(self.two_fa_secret).provisioning_uri(
            name=self.username, issuer_name='Secure Notes App'
        )
    
    def is_totp_valid(self, user_totp):
        totp = pyotp.parse_uri(self.get_two_fa_uri())
        return totp.verify(user_totp)
    
    def __repr__(self):
        return f'<user {self.username}>'