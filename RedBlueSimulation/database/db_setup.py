import os
import sqlite3
import bcrypt

def init_db():
    db_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(db_dir, "simulation.db")
    schema_path = os.path.join(db_dir, "schema.sql")

    if os.path.exists(db_path):
        os.remove(db_path)

    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    with open(schema_path, "r") as f:
        schema_sql = f.read()
    
    cursor.executescript(schema_sql)

    admin_pass_plain = "admin123"
    admin_pass_hash = bcrypt.hashpw(admin_pass_plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    user_pass_plain = "password123"
    user_pass_hash = bcrypt.hashpw(user_pass_plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    guest_pass_plain = "guest123"
    guest_pass_hash = bcrypt.hashpw(guest_pass_plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    users_data = [
        ("admin", admin_pass_plain, admin_pass_hash, "administrator", "admin@simulation.local", "System Administrator"),
        ("john_doe", user_pass_plain, user_pass_hash, "user", "john@simulation.local", "John Doe"),
        ("guest", guest_pass_plain, guest_pass_hash, "guest", "guest@simulation.local", "Guest User")
    ]

    cursor.executemany(
        "INSERT INTO users (username, password_plain, password_hash, role, email, full_name) VALUES (?, ?, ?, ?, ?, ?)",
        users_data
    )

    feedback_data = [
        ("Alice", "This system works well!"),
        ("Bob", "Found a small bug in search input, will report later.")
    ]
    cursor.executemany(
        "INSERT INTO feedback (name, message) VALUES (?, ?)",
        feedback_data
    )

    connection.commit()
    connection.close()

if __name__ == "__main__":
    init_db()
