#!/usr/bin/env python3
"""
Vulnix Database Manager (database.py)
This file handles all SQLite database and user authentication logic.
"""

import sqlite3
import hashlib
import os # We need 'os' to generate a secure random salt
from datetime import datetime

# This is the name of our database file.
DB_NAME = "vulnix.db"

def get_db_connection():
    """
    Helper function to connect to our SQLite database.
    It will create the 'vulnix.db' file if it doesn't exist.
    """
    conn = sqlite3.connect(DB_NAME)
    # This line makes the database return rows as dictionaries,
    # which is a bit easier to work with (e.g., row['username'])
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    """
    This function will create our 'users' and 'scans' tables
    if they don't already exist. We run this once.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # --- Create the 'users' table ---
    # We use "IF NOT EXISTS" so it doesn't crash if the table is already there.
    # - password_hash: The securely hashed password.
    # - salt: The unique salt used for that password.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    );
    """)
    
    # --- Create the 'scans' table ---
    # This table will log every scan run by a user.
    # - user_id: This is a "Foreign Key" that links to the 'id' in the 'users' table.
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
    
    conn.commit() # Save the changes to the database
    conn.close()

def hash_password(password, salt):
    """
    Hashes a password with a given salt using SHA-256.
    """
    # We combine the password and salt, then hash them together.
    # 'b' prefixes convert the strings to bytes, which hashing requires.
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    
    # 'hexdigest()' converts the hash to a readable string of hex characters.
    return hashlib.sha256(salted_password).hexdigest()

def add_user(username, password):
    """
    Adds a new user to the database.
    This is our "Sign Up" function.
    """
    # First, let's check if the user already exists.
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Username already exists." # Return False and a message

    # If the user is new, let's create their account.
    try:
        # 1. Generate a secure, random salt (16 bytes, converted to hex string)
        salt = os.urandom(16).hex()
        
        # 2. Hash the password using our new salt
        password_hash = hash_password(password, salt)
        
        # 3. Insert the new user into the 'users' table
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt)
        )
        conn.commit() # Save the new user
        conn.close()
        return True, "User created successfully." # Return True and a message
        
    except Exception as e:
        conn.close()
        return False, f"Error: {e}"

def check_user(username, password):
    """
    Checks if a user's login is valid.
    This is our "Login" function.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Find the user by their username
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cursor.fetchone()
    
    if not user_row:
        conn.close()
        return False, None # User not found
        
    # 2. If we found the user, get their salt and stored hash
    salt = user_row['salt']
    stored_hash = user_row['password_hash']
    user_id = user_row['id']
    
    # 3. Hash the password the user *just typed in* using the *stored salt*
    password_hash_to_check = hash_password(password, salt)
    
    # 4. Compare the hashes!
    if password_hash_to_check == stored_hash:
        conn.close()
        return True, user_id # Success! Return True and the user's ID
    else:
        conn.close()
        return False, None # Invalid password

def get_user_id(username):
    """A helper to get a user's ID from their username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cursor.fetchone()
    conn.close()
    if user_row:
        return user_row['id']
    return None

def log_scan(user_id, target, scan_type, report_path):
    """
    Logs a completed scan into the 'scans' table.
    """
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
        print(f"Error logging scan: {e}") # We can just print this error
    finally:
        conn.close()

# --- One-time setup ---
# This part runs *only* when you execute this file directly.
# We'll use it to create the tables for the first time.
if __name__ == "__main__":
    print("Initializing Vulnix database...")
    create_tables()
    print("Database tables created successfully (if they didn't exist).")
    print("You can now run the main GUI application.")

def check_user_credentials_only(user_id, password):
    """Verifies password for a specific user ID (used for deletion confirmation)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE id=?", (user_id,))
    res = c.fetchone()
    conn.close()
    
    if res:
        stored_hash = res[0]
        return hash_password(password) == stored_hash
    return False
