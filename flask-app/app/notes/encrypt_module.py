from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_note(content, note_password):
    salt = get_random_bytes(16)
    key = PBKDF2(note_password, salt, dkLen=32, count=1000000)
    
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_content = pad(content.encode('utf-8'), 16)
    encrypted_content = cipher.encrypt(padded_content)

    db_salt = base64.b64encode(salt).decode('utf-8')
    db_iv = base64.b64encode(iv).decode('utf-8')
    db_encrypted_content = base64.b64encode(encrypted_content).decode('utf-8')

    return db_salt, db_iv, db_encrypted_content

def decrypt_note(db_encrypted_content, db_salt, db_iv, note_password):
    try:
        salt = base64.b64decode(db_salt)
        key = PBKDF2(note_password, salt, dkLen=32, count=1000000)

        iv = base64.b64decode(db_iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        encrypted_content = base64.b64decode(db_encrypted_content)
        decrypted_content = cipher.decrypt(encrypted_content)
        unpadded_content = unpad(decrypted_content, 16).decode('utf-8')

        return unpadded_content
    except Exception as e:
        print(f'Decryption failed: {e}')
        return None