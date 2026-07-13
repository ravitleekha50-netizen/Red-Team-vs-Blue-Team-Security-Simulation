import sqlite3
import bcrypt
import time
import re
from backend.config import Config

def get_db_connection():
    connection = sqlite3.connect(Config.DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection

def login_vulnerable(username, password):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password_plain = '{password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return dict(user)
    except Exception as e:
        raise e
    finally:
        connection.close()
    
    return None

def login_secure(username, password):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    query = "SELECT id, username, password_hash, role, email, full_name, failed_attempts, lockout_time FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    
    if not user:
        connection.close()
        return None
        
    user_dict = dict(user)
    current_time = time.time()
    
    if user_dict["failed_attempts"] >= 3:
        lock_time = user_dict["lockout_time"]
        if lock_time:
            elapsed = current_time - float(lock_time)
            if elapsed < 30:
                connection.close()
                return ("LOCKED", int(30 - elapsed))
            else:
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE id = ?",
                    (user_dict["id"],)
                )
                connection.commit()
                user_dict["failed_attempts"] = 0
                
    hashed_password = user_dict["password_hash"].encode("utf-8")
    if bcrypt.checkpw(password.encode("utf-8"), hashed_password):
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE id = ?",
            (user_dict["id"],)
        )
        connection.commit()
        connection.close()
        user_dict.pop("password_hash")
        return user_dict
    else:
        new_attempts = user_dict["failed_attempts"] + 1
        if new_attempts >= 3:
            cursor.execute(
                "UPDATE users SET failed_attempts = ?, lockout_time = ? WHERE id = ?",
                (new_attempts, str(current_time), user_dict["id"])
            )
        else:
            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (new_attempts, user_dict["id"])
            )
        connection.commit()
        connection.close()
        return None

def register_vulnerable(username, password, email, full_name):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    check_query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(check_query)
        if cursor.fetchone():
            connection.close()
            return "Username already exists."
            
        insert_query = f"INSERT INTO users (username, password_plain, password_hash, role, email, full_name) VALUES ('{username}', '{password}', '', 'user', '{email}', '{full_name}')"
        cursor.execute(insert_query)
        connection.commit()
    except Exception as e:
        connection.close()
        return str(e)
        
    connection.close()
    return None

def register_secure(username, password, email, full_name):
    if not username or not password or not email or not full_name:
        return "All fields are required."
        
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
        
    email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    if not re.match(email_regex, email):
        return "Invalid email address format."
        
    connection = get_db_connection()
    cursor = connection.cursor()
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        connection.close()
        return "Username already exists."
        
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password_plain, password_hash, role, email, full_name) VALUES (?, ?, ?, ?, ?, ?)",
            (username, "[SECURED]", hashed_password, "user", email, full_name)
        )
        connection.commit()
    except Exception as e:
        connection.close()
        return "Database error during registration."
        
    connection.close()
    return None

def get_user_by_id_vulnerable(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    query = f"SELECT id, username, role, email, full_name FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    connection.close()
    
    if user:
        return dict(user)
    return None

def get_user_by_id_secure(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    query = "SELECT id, username, role, email, full_name FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    connection.close()
    
    if user:
        return dict(user)
    return None
