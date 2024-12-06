from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import sqlite3
import uuid
import base64
import os

# Initialize Flask app and rate limiter
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per second"])

# Load encryption key from environment variable
AES_KEY = os.getenv('NOT_MY_KEY', 'default_key_for_dev').ljust(32)[:32]

# Initialize Argon2 password hasher
ph = PasswordHasher()

# Database initialization
DATABASE = 'database.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )''')
        # Create auth_logs table
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        conn.commit()

# AES Encryption and Decryption Functions
def aes_encrypt(key, plaintext):
    """Encrypts plaintext using AES encryption."""
    iv = get_random_bytes(16)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(key, encrypted_text):
    """Decrypts AES-encrypted text."""
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv)
    return cipher.decrypt(ciphertext).decode('utf-8')

# User Registration Endpoint
@app.route('/register', methods=['POST'])
def register_user():
    """Registers a new user with a unique username and email."""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = str(uuid.uuid4())  # Generate a secure password
    password_hash = ph.hash(password)  # Hash the password using Argon2

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO users (username, email, password_hash) 
                              VALUES (?, ?, ?)''', (username, email, password_hash))
            conn.commit()
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409

# Authentication Endpoint with Logging
@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def authenticate_user():
    """Authenticates a user and logs the request details."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Invalid username or password"}), 401

        user_id, password_hash = user
        try:
            # Verify password
            ph.verify(password_hash, password)
            # Log authentication request
            cursor.execute('''INSERT INTO auth_logs (request_ip, user_id) 
                              VALUES (?, ?)''', (request.remote_addr, user_id))
            conn.commit()
            return jsonify({"message": "Authenticated"}), 200
        except Exception:
            return jsonify({"error": "Invalid username or password"}), 401

# AES Encryption Test Endpoint (Optional)
@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    """Encrypts data using AES for testing purposes."""
    data = request.get_json().get('data')
    encrypted = aes_encrypt(AES_KEY, data)
    return jsonify({"encrypted": encrypted}), 200

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    """Decrypts AES-encrypted data for testing purposes."""
    encrypted_data = request.get_json().get('encrypted')
    decrypted = aes_decrypt(AES_KEY, encrypted_data)
    return jsonify({"decrypted": decrypted}), 200

# Run the Flask app
if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)
