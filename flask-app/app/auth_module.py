import os
from dotenv import load_dotenv
import secrets
from passlib.hash import pbkdf2_sha256

load_dotenv()
pepper = os.getenv('PEPPER')

def hash_password(password):
    salt = secrets.token_bytes(8).hex()
    combined_salt = salt + pepper

    hasher = pbkdf2_sha256.using(salt=combined_salt.encode('utf-8'), rounds=1000)
    password_hash = hasher.hash(password)

    return password_hash, salt

def verify_password(db_password_hash, user_password, salt):
    combined_salt = salt + pepper
    hasher = pbkdf2_sha256.using(salt=combined_salt.encode('utf-8'), rounds=1000)

    return hasher.verify(user_password, db_password_hash)