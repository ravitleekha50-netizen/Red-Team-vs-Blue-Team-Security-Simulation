import os
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, make_response, session, abort
from backend.config import Config
from backend.auth import login_vulnerable, login_secure, register_vulnerable, register_secure, get_user_by_id_vulnerable, get_user_by_id_secure, get_db_connection

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)
app.config.from_object(Config)

@app.context_processor
def inject_security_status():
    return {
        "security_enabled": Config.SECURITY_ENABLED,
        "current_user": get_session_user()
    }

def get_session_user():
    if Config.SECURITY_ENABLED:
        if "user_id" in session:
            return {
                "id": session.get("user_id"),
                "username": session.get("username"),
                "role": session.get("role")
            }
    else:
        user_id = request.cookies.get("user_id")
        username = request.cookies.get("username")
        role = request.cookies.get("role")
        if user_id and username:
            return {
                "id": user_id,
                "username": username,
                "role": role
            }
    return None

@app.after_request
def apply_security_headers(response):
    if Config.SECURITY_ENABLED:
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net;"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/toggle-security", methods=["POST"])
def toggle_security():
    Config.SECURITY_ENABLED = not Config.SECURITY_ENABLED
    session.clear()
    response = make_response(redirect(url_for("index")))
    response.set_cookie("user_id", "", expires=0)
    response.set_cookie("username", "", expires=0)
    response.set_cookie("role", "", expires=0)
    return response

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if Config.SECURITY_ENABLED:
            if not username or not password:
                error = "Username and password are required."
            else:
                user = login_secure(username, password)
                if isinstance(user, tuple) and user[0] == "LOCKED":
                    error = f"Account locked. Try again in {user[1]} seconds."
                elif user:
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    return redirect(url_for("index"))
                else:
                    error = "Invalid credentials."
        else:
            try:
                user = login_vulnerable(username, password)
                if user:
                    response = make_response(redirect(url_for("index")))
                    response.set_cookie("user_id", str(user["id"]))
                    response.set_cookie("username", user["username"])
                    response.set_cookie("role", user["role"])
                    return response
                else:
                    error = "Invalid credentials."
            except Exception as e:
                if not Config.SECURITY_ENABLED:
                    return f"Database Error: {str(e)}", 500
                error = "An error occurred."
                
    return render_template("login.html", error=error, active_tab="login")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")
    full_name = request.form.get("full_name")
    
    if Config.SECURITY_ENABLED:
        reg_error = register_secure(username, password, email, full_name)
    else:
        try:
            reg_error = register_vulnerable(username, password, email, full_name)
        except Exception as e:
            if not Config.SECURITY_ENABLED:
                return f"Database Error: {str(e)}", 500
            reg_error = "An error occurred."
            
    if reg_error:
        return render_template("login.html", error=reg_error, active_tab="register")
        
    return render_template("login.html", success="Registration successful! Please login.", active_tab="login")

@app.route("/logout")
def logout():
    session.clear()
    response = make_response(redirect(url_for("index")))
    response.set_cookie("user_id", "", expires=0)
    response.set_cookie("username", "", expires=0)
    response.set_cookie("role", "", expires=0)
    return response

@app.route("/profile")
def profile():
    user_id = request.args.get("id")
    current_user = get_session_user()
    
    if not current_user:
        return redirect(url_for("login"))
        
    if Config.SECURITY_ENABLED:
        if not user_id:
            user_id = str(current_user["id"])
        if str(current_user["id"]) != str(user_id) and current_user["role"] != "administrator":
            abort(403)
        user = get_user_by_id_secure(user_id)
    else:
        if not user_id:
            user_id = str(current_user["id"])
        user = get_user_by_id_vulnerable(user_id)
        
    if not user:
        abort(404)
        
    return render_template("profile.html", user=user)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    results = []
    error = None
    
    if query:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        if Config.SECURITY_ENABLED:
            sql_query = "SELECT username, role, email, full_name FROM users WHERE username LIKE ? OR full_name LIKE ?"
            like_query = f"%{query}%"
            cursor.execute(sql_query, (like_query, like_query))
            results = [dict(row) for row in cursor.fetchall()]
        else:
            sql_query = f"SELECT username, role, email, full_name FROM users WHERE username LIKE '%{query}%' OR full_name LIKE '%{query}%'"
            try:
                cursor.execute(sql_query)
                results = [dict(row) for row in cursor.fetchall()]
            except Exception as e:
                error = str(e)
                if Config.SECURITY_ENABLED:
                    error = "An error occurred processing search request."
                    
        connection.close()
        
    return render_template("search.html", query=query, results=results, error=error)

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    connection = get_db_connection()
    cursor = connection.cursor()
    
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        
        if Config.SECURITY_ENABLED:
            csrf_token = request.form.get("csrf_token")
            if not csrf_token or csrf_token != session.get("csrf_token"):
                connection.close()
                abort(403)
                
            if not name or not message:
                pass
            else:
                cursor.execute("INSERT INTO feedback (name, message) VALUES (?, ?)", (name, message))
                connection.commit()
        else:
            cursor.execute(f"INSERT INTO feedback (name, message) VALUES ('{name}', '{message}')")
            connection.commit()
            
    cursor.execute("SELECT name, message, created_at FROM feedback ORDER BY id DESC")
    feedbacks = [dict(row) for row in cursor.fetchall()]
    connection.close()
    
    import secrets
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
        
    return render_template("feedback.html", feedbacks=feedbacks, csrf_token=session.get("csrf_token"))

@app.route("/debug")
def debug():
    if Config.SECURITY_ENABLED:
        abort(403)
        
    debug_info = {
        "DEBUG_MODE": app.debug,
        "SECRET_KEY": app.config.get("SECRET_KEY"),
        "DB_PATH": app.config.get("DB_PATH"),
        "FLASK_ENV": os.environ.get("FLASK_ENV", "development"),
        "SYSTEM_PATH": os.environ.get("PATH", ""),
        "DB_DRIVER": "sqlite3"
    }
    return render_template("debug.html", info=debug_info)

@app.errorhandler(403)
def forbidden_error(e):
    return render_template("error.html", title="Forbidden", message="You do not have permission to view this resource.", code=403), 403

@app.errorhandler(404)
def not_found_error(e):
    return render_template("error.html", title="Not Found", message="The requested resource could not be found.", code=404), 404

@app.errorhandler(500)
def internal_error(e):
    if not Config.SECURITY_ENABLED:
        import traceback
        return render_template("error_debug.html", traceback=traceback.format_exc()), 500
    return render_template("error.html", title="Internal Server Error", message="An unexpected error occurred.", code=500), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
