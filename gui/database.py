#!/usr/bin/env python3
"""
Vulnix Database Manager.
Handles SQLite interactions for user authentication and scan logging.
"""

import sqlite3
import hashlib
import os
from datetime import datetime

DB_NAME = "vulnix.db"

def get_db_connection():
    """Establish connection to SQLite database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    """Initialize database schema for user management and scan logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table schema
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    );
    """)
    
    # Scans table schema with foreign key constraint
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        report_path TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)
    
    conn.commit()
    conn.close()

def hash_password(password, salt):
    """Generate SHA-256 hash for password verification."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    return hashlib.sha256(salted_password).hexdigest()

def add_user(username, password):
    """Register a new user with secure password hashing."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Username already exists."

    try:
        salt = os.urandom(16).hex()
        password_hash = hash_password(password, salt)
        
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt)
        )
        conn.commit()
        conn.close()
        return True, "User created successfully."
        
    except Exception as e:
        conn.close()
        return False, f"Error: {e}"

def check_user(username, password):
    """Validate user credentials against stored hash."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cursor.fetchone()
    
    if not user_row:
        conn.close()
        return False, None
        
    salt = user_row['salt']
    stored_hash = user_row['password_hash']
    user_id = user_row['id']
    
    password_hash_to_check = hash_password(password, salt)
    
    if password_hash_to_check == stored_hash:
        conn.close()
        return True, user_id
    else:
        conn.close()
        return False, None

def get_user_id(username):
    """Retrieve ID for a given username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cursor.fetchone()
    conn.close()
    if user_row:
        return user_row['id']
    return None

def log_scan(user_id, target, scan_type, report_path):
    """Persist scan metadata to database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO scans (user_id, target, scan_type, report_path, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_id, target, scan_type, report_path, timestamp)
        )
        conn.commit()
    except Exception as e:
        print(f"Error logging scan: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    print("Initializing Vulnix database...")
    create_tables()
    print("Database schema initialized.")
