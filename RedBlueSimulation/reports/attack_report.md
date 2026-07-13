# Red Team Penetration Testing & Attack Report

## 1. Introduction
This report documents the security assessment and penetration testing phase of the web application. The testing was carried out to discover, demonstrate, and document vulnerabilities in the system. The targets were evaluated for common web application issues listed in the OWASP Top 10 guidelines.

## 2. Objective
The goal was to ethically exploit security weaknesses in the application to understand their impact. Demonstrating these attacks shows why strong defenses are necessary and helps the development team understand the risks.

## 3. Environment & Tools Used
The testing was done in a local development environment. The targets were hosted locally at `http://127.0.0.1:5000/`.
The following tools were used during the assessment:
* **OWASP ZAP & Burp Suite:** For capturing, analyzing, and modifying HTTP requests.
* **SQLMap:** To automate finding and exploiting SQL injection.
* **Mozilla Firefox Developer Tools:** For editing cookies, inspecting HTML elements, and debugging JavaScript execution.
* **Python Scripts:** Custom request scripts for testing rate limits and authentication.

## 4. Methodology
I used a black-box and gray-box testing approach. The process went through the following stages:
1. **Reconnaissance:** Mapping paths, inspecting headers, and looking for exposed files.
2. **Vulnerability Assessment:** Inputting test strings to check for errors or reflective behavior.
3. **Exploitation:** Executing payloads to confirm the vulnerabilities.
4. **Impact Assessment:** Figuring out what data could be accessed or modified.

---

## 5. Vulnerability Analysis

### Vulnerability 1: SQL Injection (SQLi)
* **Description:** The search functionality on the `/search` page takes input from the user and builds a raw database query using string formatting.
* **Risk:** Critical
* **CVSS Score:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
* **Steps to Reproduce:**
  1. Open the browser and go to the Catalog Search page (`http://127.0.0.1:5000/search`).
  2. In the search input box, enter the following payload: `' OR '1'='1`
  3. Click the Search button.
  4. The page will return the records of all users in the system, bypassing any intended search filters.
* **Payload:** `' OR '1'='1`
* **Screenshot:**
  [Insert Screenshot Here - Search page showing all records after injecting ' OR '1'='1]
* **Impact:** An attacker can read, modify, or delete any data in the SQLite database, including usernames, hashed and plaintext passwords, and emails.
* **Recommendation:** Use parameterized queries (prepared statements) to separate query logic from user data.

| Vulnerability Field | Details |
| --- | --- |
| Vulnerability Type | SQL Injection (Search Form) |
| Remediation Priority | Critical |
| Target Endpoint | `/search` |

---

### Vulnerability 2: Stored Cross-Site Scripting (XSS)
* **Description:** The feedback submission on `/feedback` allows users to submit messages. The application saves the message directly to the database and displays it on the feedback list using Jinja's `| safe` filter without escaping HTML characters.
* **Risk:** High
* **CVSS Score:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)
* **Steps to Reproduce:**
  1. Go to the Feedback Bulletin page (`http://127.0.0.1:5000/feedback`).
  2. In the Message field, enter the XSS script payload.
  3. Enter any name and click "Submit Feedback".
  4. Refresh the page or view it as another user. The browser runs the script immediately.
* **Payload:** `<script>alert('Stored XSS Executed')</script>`
* **Screenshot:**
  [Insert Screenshot Here - JavaScript alert dialog showing Stored XSS Executed on feedback page]
* **Impact:** Attackers can run JavaScript in the browsers of users who visit the feedback page. This can be used to steal session cookies, redirect users to phishing sites, or modify the page content.
* **Recommendation:** Remove the `| safe` filter in Flask templates so the framework automatically HTML-escapes outputs.

---

### Vulnerability 3: Insecure Direct Object References (IDOR)
* **Description:** The profile page `/profile` uses a query parameter `id` to fetch user details. The application does not check if the logged-in user has permission to view the requested profile ID.
* **Risk:** High
* **CVSS Score:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
* **Steps to Reproduce:**
  1. Log in as a regular user (e.g., `john_doe` with ID `2`).
  2. Navigate to the profile page. The URL is `http://127.0.0.1:5000/profile?id=2`.
  3. Manually change the parameter in the address bar to `id=1` (the admin's ID).
  4. The page loads the administrator's profile information, revealing their email and full name.
* **Payload:** Changing `?id=2` to `?id=1` in the URL.
* **Screenshot:**
  [Insert Screenshot Here - Profile page displaying Administrator details while logged in as a normal user]
* **Impact:** Unauthorized access to personal user data (emails, full names, roles, etc.) of all registered accounts in the database.
* **Recommendation:** Verify that the logged-in session user's ID matches the requested profile ID before returning the data, or fetch the user profile directly from session state.

---

### Vulnerability 4: Broken Authentication (Session Manipulation)
* **Description:** When security is disabled, the login process sets identity credentials directly in plain cookies (`user_id`, `username`, `role`) instead of a signed server session. There is also no rate-limiting on the login form.
* **Risk:** Critical
* **CVSS Score:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
* **Steps to Reproduce:**
  1. Go to the login page and authenticate with any user account.
  2. Open the browser's developer console and view active cookies.
  3. Find the cookie named `role` and change its value from `user` to `administrator`.
  4. Modify the `user_id` cookie value to `1`.
  5. Reload the dashboard or profile page. The application now treats the user as the administrator.
* **Payload:** Changing browser cookies `role=administrator` and `user_id=1`.
* **Screenshot:**
  [Insert Screenshot Here - Browser cookie inspector displaying manually modified role and user_id values]
* **Impact:** Attackers can impersonate any registered user or escalate their privileges to administrator by editing client-side cookie values.
* **Recommendation:** Use cryptographically signed session cookies (like Flask's default session) and set attributes like `HttpOnly` and `SameSite` to prevent client tampering.

---

### Vulnerability 5: Security Misconfiguration
* **Description:** Flask runs with debug mode enabled (`debug=True`). When an unhandled error happens, the application displays a detailed Python traceback with code snippets and variables.
* **Risk:** Medium
* **CVSS Score:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
* **Steps to Reproduce:**
  1. Visit the search page.
  2. Input a single single-quote `'` to cause a syntax error in the SQL search query.
  3. Submit the search.
  4. The page crashes and returns a detailed traceback screen showing the database file path and python call stacks.
* **Payload:** `'`
* **Screenshot:**
  [Insert Screenshot Here - Flask debugger page showing python stack traces and database paths]
* **Impact:** Attackers learn the internal folder structure, database engines, configuration keys, and module versions, which helps them plan further attacks.
* **Recommendation:** Disable debug mode in production, handle errors gracefully with general error templates, and log the detailed stack trace to secure server files.

---

### Vulnerability 6: Sensitive Data Exposure (Bonus)
* **Description:** The system exposes configuration settings and backend environment details on `/debug`. Plaintext passwords (`admin123`, `password123`) were also found stored in the `users` table under the `password_plain` column.
* **Risk:** High
* **CVSS Score:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
* **Steps to Reproduce:**
  1. Open a browser and navigate to `http://127.0.0.1:5000/debug`.
  2. The page loads a table displaying the Flask `SECRET_KEY`, environment variable paths, and the exact database folder paths.
* **Payload:** Accessing `/debug` endpoint directly.
* **Screenshot:**
  [Insert Screenshot Here - Debug page exposing SECRET_KEY and DB_PATH values in a table]
* **Impact:** Leakage of secret keys allows attackers to sign session cookies, bypass authentication, and view system files. Plaintext password storage means a database leak immediately compromises all user credentials.
* **Recommendation:** Restrict access to diagnostic interfaces, use environment files to store configurations, and hash passwords using bcrypt before saving.

---

## 6. Summary of Red Team Findings
The testing revealed critical flaws in data validation, session security, error handling, and configuration access control. These vulnerabilities let us view all database records, run malicious scripts, steal accounts, and escalate privileges.

| Ref ID | Vulnerability | Severity | CVSS v3.1 | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | SQL Injection | Critical | 9.8 | Exploited |
| SEC-02 | Stored XSS | High | 8.2 | Exploited |
| SEC-03 | IDOR | High | 7.5 | Exploited |
| SEC-04 | Broken Authentication | Critical | 9.1 | Exploited |
| SEC-05 | Security Misconfiguration | Medium | 5.3 | Exploited |
| SEC-06 | Sensitive Data Exposure | High | 7.5 | Exploited |
