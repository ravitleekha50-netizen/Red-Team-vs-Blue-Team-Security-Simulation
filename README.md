# Red Team vs Blue Team Security Simulation

An interactive security simulation application and analyzer tool suite designed to demonstrate and defend against common web application vulnerabilities (OWASP Top 10).

## Features
* **Dual Security Operations:** Toggle the application configuration between Vulnerable (Red Team targets) and Secure (Blue Team patched) states instantly.
* **Core Vulnerabilities Covered:**
  * **SQL Injection (SQLi):** Parameter bypass on catalog search.
  * **Stored Cross-Site Scripting (XSS):** Form payload injection on feedback forum.
  * **Insecure Direct Object Reference (IDOR):** Direct page queries via parameters.
  * **Broken Authentication:** Plain cookie user impersonation.
  * **Security Misconfigurations:** Flask traceback output leakage.
  * **Sensitive Data Exposure:** Diagnostic parameter panel display.
* **Security Suite Analysis Tool:**
  * **Option A:** Active Vulnerability Scanner.
  * **Option B:** Security Header Response Analyzer.
  * **Option C:** Web Access Log Analyzer.
  * **Option D:** Bruteforce Intrusion Detector.
  * **Option E:** Heuristic Phishing URL Detector.
  * **Report Generation:** Automatic HTML report builder with design formatting.

## Technology Stack
* **Frontend:** HTML, CSS, Bootstrap, JavaScript
* **Backend:** Python Flask
* **Database:** SQLite
* **Security Suite:** Python

## Folder Structure
```text
RedBlueSimulation/
├── backend/
│   ├── app.py (Flask Server)
│   ├── auth.py (Authentication & DB Helpers)
│   └── config.py (Toggle Configuration)
├── database/
│   ├── db_setup.py (SQLite Seeding Script)
│   ├── schema.sql (SQL Schema Statements)
│   └── simulation.db (Generated SQLite Instance)
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css (Custom Animations/Styling)
│   │   └── js/
│   │       └── main.js (Interactive UI Logic)
│   └── templates/ (Jinja templates)
├── scanner/
│   ├── payloads.json (SQLi & XSS payload lists)
│   ├── sample_logs.txt (Mock access log strings)
│   └── security_tool.py (Python Integrated Security Tool)
├── reports/
│   ├── attack_report.md (Red Team Exploit Walkthroughs)
│   ├── defense_report.md (Blue Team Patch Verification)
│   ├── tool_documentation.md (Suite Execution Guide)
│   ├── final_report.md (Exhaustive Academic Documentation)
│   └── security_analysis_report.html (Generated HTML Log/Scan output)
├── requirements.txt (Dependencies list)
└── README.md
```

## Requirements
* Python 3.8 or higher
* Pip Package Manager

## Installation
Clone the repository and install the Python dependencies:
```bash
pip install -r requirements.txt
```

Initialize the database:
```bash
python database/db_setup.py
```

## Running the Project

### Running the Web Server
Launch the Flask development server:
```bash
python backend/app.py
```
Access the application dashboard by navigating to `http://127.0.0.1:5000/` in your browser.

### Running the Integrated Security Tool
With the Flask server running, open another terminal window and run the analyzer script:
```bash
python scanner/security_tool.py
```

## Screenshots
* **Vulnerable Dashboard View:**
  [Insert Screenshot Here - Home Dashboard indicating Red Team Vulnerable Mode is active]
* **Security Scan Output:**
  [Insert Screenshot Here - Terminal output showing security_tool.py execution results]

## Future Improvements
* Build an interactive terminal dashboard within the CLI using `urwid` or `curses`.
* Implement defensive rate limiting on authentication routes using Flask-Limiter.
* Support scanning multiple target hosts concurrently.

## License
MIT License.
