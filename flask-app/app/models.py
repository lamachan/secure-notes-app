from datetime import datetime
from flask_login import UserMixin
import pyotp

from app.app import db

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    salt = db.Column(db.String(16), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)

    login_tries = db.Column(db.Integer, nullable=False, default=0)
    disabled_until = db.Column(db.DateTime, nullable=True)

    two_fa_secret = db.Column(db.String(32), unique=True)
    two_fa_enabled = db.Column(db.Boolean, nullable=False, default=False)

    notes = db.relationship('Note', backref='user', lazy=True)

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
    
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

    public = db.Column(db.Boolean, default=False)
    encrypted = db.Column(db.Boolean, default=False)
    salt = db.Column(db.String(24), nullable=True)
    iv = db.Column(db.String(24), nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)