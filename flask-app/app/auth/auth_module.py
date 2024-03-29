import os
from dotenv import load_dotenv
import secrets
from passlib.hash import pbkdf2_sha256

load_dotenv()
pepper = os.getenv('PEPPER')

def hash_password(password):
    salt = secrets.token_bytes(8).hex()
    combined_password = salt + pepper + password

    # default rounds = 29000
    password_hash = pbkdf2_sha256.hash(combined_password)

    return password_hash, salt

def verify_password(db_password_hash, user_password, salt):
    combined_user_password = salt + pepper + user_password

    return pbkdf2_sha256.verify(combined_user_password, db_password_hash)