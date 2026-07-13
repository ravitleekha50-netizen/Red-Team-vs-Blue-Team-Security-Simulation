# Blue Team Mitigation & Defense Report

## 1. Executive Summary
This report outlines the patches and configuration improvements implemented to secure the application. When the security toggle is active (`SECURITY_ENABLED = True`), the application runs defensive checks that successfully mitigate all Red Team exploits.

---

## 2. Mitigation Breakdown

### Issue 1: SQL Injection (SQLi)
* **Problem:** The search page accepted query parameters and added them directly into the SQL query string.
* **Root Cause:** String concatenation in SQL statements allows input parameters to be interpreted as database commands.
* **Fix:** I replaced raw string formatting with parameterized queries using SQLite placeholder markers (`?`).
* **Code Improvement:**

```python
# Vulnerable Implementation
sql_query = f"SELECT username, role, email, full_name FROM users WHERE username LIKE '%{query}%' OR full_name LIKE '%{query}%'"
cursor.execute(sql_query)

# Secured Implementation
sql_query = "SELECT username, role, email, full_name FROM users WHERE username LIKE ? OR full_name LIKE ?"
like_query = f"%{query}%"
cursor.execute(sql_query, (like_query, like_query))
```
* **Security Benefits:** The database engine treats input values strictly as text parameters, preventing SQL command execution.
* **Testing:** Injecting `' OR '1'='1` in secure mode searches for the literal string, yielding zero results instead of dumping the database.

---

### Issue 2: Stored Cross-Site Scripting (XSS)
* **Problem:** The feedback form saved messages containing script tags directly, and the template rendered them raw using the `| safe` filter.
* **Root Cause:** Bypassing template escaping filters allows the browser to render and run user-supplied HTML/JavaScript.
* **Fix:** I removed the `| safe` filter and implemented Content Security Policy (CSP) headers.
* **Code Improvement:**

```html
<!-- Vulnerable Implementation -->
<p class="card-text">{{ item.message | safe }}</p>

<!-- Secured Implementation -->
<p class="card-text">{{ item.message }}</p>
```
* **Security Benefits:** HTML characters like `<` and `>` are escaped to `&lt;` and `&gt;`. The browser renders the tags as text instead of executing them.
* **Testing:** Submitting `<script>alert(1)</script>` displays the raw script code safely on the feedback wall.

---

### Issue 3: Insecure Direct Object References (IDOR)
* **Problem:** The profile page displayed details for any profile request id passed via the URL query string.
* **Root Cause:** Lack of object-level authorization checks before retrieving and serving private records.
* **Fix:** I added session authorization checks. Users can only view their own profile, unless they have the administrator role.
* **Code Improvement:**

```python
# Vulnerable Implementation
user = get_user_by_id_vulnerable(user_id)

# Secured Implementation
if str(current_user["id"]) != str(user_id) and current_user["role"] != "administrator":
    abort(403)
user = get_user_by_id_secure(user_id)
```
* **Security Benefits:** Prevents horizontal and vertical privilege escalation by validating access rights for every record request.
* **Testing:** Navigating to `/profile?id=1` as a regular user returns a `403 Forbidden` error.

---

### Issue 4: Broken Authentication (Session Manipulation)
* **Problem:** The application trusted identity parameters stored in plain browser cookies, which could be modified by users.
* **Root Cause:** Storing critical authentication state in client-modifiable, unsigned cookies.
* **Fix:** Replaced plain cookies with Flask's cryptographically signed session object. Set HSTS and cookie security attributes.
* **Code Improvement:**

```python
# Vulnerable Implementation
response = make_response(redirect(url_for("index")))
response.set_cookie("user_id", str(user["id"]))
response.set_cookie("role", user["role"])

# Secured Implementation
session["user_id"] = user["id"]
session["username"] = user["username"]
session["role"] = user["role"]
```
* **Security Benefits:** Signed session cookies prevent tampering. If a user modifies the cookie contents, the signature check fails, and Flask resets the session.
* **Testing:** Changing cookie values in developer tools results in the application rejecting the session and logging the user out.

---

### Issue 5: Security Misconfiguration
* **Problem:** Detailed Python error traces were sent to the browser when the database query failed.
* **Root Cause:** Running Flask with debug enabled and without customized error-handling templates.
* **Fix:** Configured custom `errorhandler` routes to catch exceptions and render simple messages.
* **Code Improvement:**

```python
# Vulnerable Implementation
@app.errorhandler(500)
def internal_error(e):
    return render_template("error_debug.html", traceback=traceback.format_exc()), 500

# Secured Implementation
@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", title="Internal Server Error", message="An unexpected error occurred.", code=500), 500
```
* **Security Benefits:** Diagnostic files and folder locations remain hidden from public users.
* **Testing:** Causing an error returns a clean 500 page instead of revealing database paths or code logic.

---

### Issue 6: Sensitive Data Exposure & CSRF Protection
* **Problem:** Configuration settings were publicly exposed on `/debug`, and the feedback form lacked Cross-Site Request Forgery protections.
* **Root Cause:** Exposing debug endpoints in production and accepting POST actions without verifying authenticity tokens.
* **Fix:** Blocked `/debug` under secure mode and implemented session-based CSRF tokens on feedback forms.
* **Code Improvement:**

```python
# Secured CSRF verification inside /feedback POST handler
csrf_token = request.form.get("csrf_token")
if not csrf_token or csrf_token != session.get("csrf_token"):
    abort(403)
```
* **Security Benefits:** Protects settings and limits form actions to requests made directly from within the session.
* **Testing:** POST requests to `/feedback` without a valid CSRF token return a `403 Forbidden` error.

---

## 3. Defense Validation Matrix

| Vulnerability Vector | Attack Payload (Red Team) | Mitigated Status (Blue Team) | Defensive Control Used |
| --- | --- | --- | --- |
| SQL Injection | `' OR '1'='1` | Resolved | Parameterized SQL Binding |
| Stored XSS | `<script>alert(1)</script>` | Resolved | HTML Entity Output Escaping |
| IDOR | URL modification `?id=1` | Resolved | Session Owner Verification |
| Privilege Escalation | Changing cookie `role` | Resolved | Cryptographically Signed Sessions |
| Misconfiguration | Query forcing 500 status | Resolved | Generic Error Route Masking |
| Data Leakage | Inspecting `/debug` | Resolved | Restricted Path Access controls |
| CSRF | Automated external forms | Resolved | Session Anti-CSRF Token Match |

---

## 4. Lessons Learned
* Security should be considered from the start, not added on at the end. Writing parameterized SQL queries from the beginning prevents SQL injection completely.
* Trusting user input or client-side parameters like cookies is a major risk. Always validate data on the server side.
* Detailed error messages help developers but also help attackers. Production environments should always hide debug stacks.
