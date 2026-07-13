import os
import sys
import re
import json
import requests
import urllib.parse
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style

init(autoreset=True)

class SecurityTool:
    def __init__(self):
        self.payloads = {"sqli": [], "xss": []}
        self.load_payloads()

    def load_payloads(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        payload_path = os.path.join(script_dir, "payloads.json")
        if os.path.exists(payload_path):
            try:
                with open(payload_path, "r") as f:
                    self.payloads = json.load(f)
            except Exception:
                pass

    def run_vulnerability_scanner(self, target_url):
        print(f"\n{Fore.BLUE}=== [1] Active Vulnerability Scanner ==={Style.RESET_ALL}")
        results = {
            "files": [],
            "sqli": [],
            "xss": []
        }
        
        print(f"[*] Probing exposed files on {target_url}...")
        sensitive_paths = [
            ".env",
            "database/simulation.db",
            ".git/config",
            "db_setup.py",
            "config.py"
        ]
        
        for path in sensitive_paths:
            test_url = urljoin(target_url, path)
            try:
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                if response.status_code == 200 and len(response.content) > 0:
                    results["files"].append({
                        "url": test_url,
                        "status": 200,
                        "severity": "High",
                        "description": f"Exposed sensitive file found: {path}"
                    })
                    print(f"  {Fore.RED}[!] EXPOSED FILE FOUND: {test_url}{Style.RESET_ALL}")
            except requests.RequestException:
                pass

        print(f"[*] Scanning SQL Injection on search forms...")
        search_endpoint = urljoin(target_url, "search")
        for payload in self.payloads.get("sqli", []):
            try:
                params = {"q": payload}
                response = requests.get(search_endpoint, params=params, timeout=5)
                
                sqlite_errors = [
                    "unrecognized token",
                    "operationalerror",
                    "database error",
                    "syntax error",
                    "near"
                ]
                
                found_err = False
                for err in sqlite_errors:
                    if err.lower() in response.text.lower():
                        found_err = True
                        break
                        
                if found_err or response.status_code == 500:
                    results["sqli"].append({
                        "payload": payload,
                        "endpoint": search_endpoint,
                        "type": "Error-based SQLi",
                        "severity": "Critical"
                    })
                    print(f"  {Fore.RED}[!] SQLi Vulnerability detected with payload: {payload}{Style.RESET_ALL}")
            except requests.RequestException:
                pass

        print(f"[*] Scanning Reflected XSS on search endpoints...")
        for payload in self.payloads.get("xss", []):
            try:
                params = {"q": payload}
                response = requests.get(search_endpoint, params=params, timeout=5)
                if payload in response.text and "text-danger" in response.text:
                    results["xss"].append({
                        "payload": payload,
                        "endpoint": search_endpoint,
                        "severity": "High"
                    })
                    print(f"  {Fore.RED}[!] XSS Vulnerability detected with payload: {payload}{Style.RESET_ALL}")
            except requests.RequestException:
                pass

        return results

    def analyze_security_headers(self, target_url):
        print(f"\n{Fore.BLUE}=== [2] Security Headers Analyzer ==={Style.RESET_ALL}")
        results = {}
        
        try:
            response = requests.get(target_url, timeout=5)
            headers = response.headers
            
            security_headers = {
                "Content-Security-Policy": "CSP protects against XSS, clickjacking, and code injection attacks.",
                "Strict-Transport-Security": "HSTS forces browsers to connect using secure HTTPS only.",
                "X-Frame-Options": "Protects users against clickjacking attacks by controlling site nesting.",
                "X-Content-Type-Options": "Prevents MIME-sniffing and forces matching resource content-types.",
                "X-XSS-Protection": "Filters basic reflected XSS attacks in older browsers."
            }
            
            score = 100
            missing_penalty = 20
            
            for header, desc in security_headers.items():
                val = headers.get(header)
                if val:
                    results[header] = {
                        "present": True,
                        "value": val,
                        "description": desc
                    }
                    print(f"  {Fore.GREEN}[+] {header}: {val}{Style.RESET_ALL}")
                else:
                    results[header] = {
                        "present": False,
                        "value": None,
                        "description": desc
                    }
                    score -= missing_penalty
                    print(f"  {Fore.RED}[-] MISSING: {header} ({desc}){Style.RESET_ALL}")
            
            results["score"] = score
            print(f"\n[*] Total Security Headers Score: {Fore.YELLOW}{score}/100{Style.RESET_ALL}")
            
        except requests.RequestException as e:
            print(f"{Fore.RED}[-] Could not connect to target: {e}{Style.RESET_ALL}")
            results["error"] = str(e)
            
        return results

    def analyze_logs(self, log_file_path):
        print(f"\n{Fore.BLUE}=== [3] Log Analyzer ==={Style.RESET_ALL}")
        results = {
            "sqli_attempts": 0,
            "xss_attempts": 0,
            "traversal_attempts": 0,
            "details": []
        }
        
        if not os.path.exists(log_file_path):
            print(f"{Fore.RED}[-] Log file not found: {log_file_path}{Style.RESET_ALL}")
            return results
            
        sqli_patterns = [
            r"(?i)union\s+select",
            r"(?i)select\s+.*\s+from",
            r"(?i)'\s+or\s+1\s*=\s*1",
            r"(?i)'\s+or\s+'.*'\s*=\s*'.*",
            r"(?i)admin'\s*--"
        ]
        
        xss_patterns = [
            r"(?i)<script>",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)javascript:"
        ]
        
        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"(?i)/etc/passwd",
            r"(?i)boot\.ini"
        ]
        
        with open(log_file_path, "r") as f:
            for index, line in enumerate(f, 1):
                decoded_line = urllib.parse.unquote_plus(line)
                sqli_found = any(re.search(pat, decoded_line) for pat in sqli_patterns)
                xss_found = any(re.search(pat, decoded_line) for pat in xss_patterns)
                traversal_found = any(re.search(pat, decoded_line) for pat in traversal_patterns)
                
                if sqli_found:
                    results["sqli_attempts"] += 1
                    results["details"].append({
                        "line": index,
                        "type": "SQLi Attempt",
                        "content": line.strip()
                    })
                if xss_found:
                    results["xss_attempts"] += 1
                    results["details"].append({
                        "line": index,
                        "type": "XSS Attempt",
                        "content": line.strip()
                    })
                if traversal_found:
                    results["traversal_attempts"] += 1
                    results["details"].append({
                        "line": index,
                        "type": "Path Traversal",
                        "content": line.strip()
                    })
                    
        print(f"[*] Analysis Summary for: {log_file_path}")
        print(f"  SQLi Attempts flagged: {Fore.YELLOW}{results['sqli_attempts']}{Style.RESET_ALL}")
        print(f"  XSS Attempts flagged: {Fore.YELLOW}{results['xss_attempts']}{Style.RESET_ALL}")
        print(f"  Directory Traversal flagged: {Fore.YELLOW}{results['traversal_attempts']}{Style.RESET_ALL}")
        
        return results

    def detect_brute_force(self, log_file_path, limit=5):
        print(f"\n{Fore.BLUE}=== [4] Brute Force Detector ==={Style.RESET_ALL}")
        results = {}
        
        if not os.path.exists(log_file_path):
            print(f"{Fore.RED}[-] Log file not found: {log_file_path}{Style.RESET_ALL}")
            return results
            
        failures = {}
        
        with open(log_file_path, "r") as f:
            for line in f:
                parts = line.split(" ")
                if len(parts) < 9:
                    continue
                    
                ip = parts[0]
                method = parts[5].replace('"', '')
                path = parts[6]
                status = parts[8]
                
                if method == "POST" and path == "/login" and status in ["401", "403"]:
                    failures[ip] = failures.get(ip, 0) + 1
                    
        for ip, count in failures.items():
            if count >= limit:
                results[ip] = {
                    "failed_attempts": count,
                    "risk": "High (Potential Brute Force)"
                }
                print(f"  {Fore.RED}[!] WARNING: IP {ip} flagged with {count} failed login attempts!{Style.RESET_ALL}")
                
        if not results:
            print("  [+] No brute force activities identified in the log file.")
            
        return results

    def detect_phishing_url(self, test_url):
        print(f"\n{Fore.BLUE}=== [5] Phishing URL Detector ==={Style.RESET_ALL}")
        results = {
            "is_suspicious": False,
            "score": 0,
            "reasons": []
        }
        
        parsed = urlparse(test_url)
        hostname = parsed.hostname or parsed.path
        
        if not test_url.startswith("https://"):
            results["score"] += 25
            results["reasons"].append("Missing HTTPS protocol")
            
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, hostname):
            results["score"] += 35
            results["reasons"].append("Hostname is an IP address")
            
        keywords = ["login", "verify", "secure", "bank", "update", "signin", "account", "paypal", "netflix"]
        for kw in keywords:
            if kw in hostname.lower() or kw in parsed.path.lower():
                results["score"] += 15
                results["reasons"].append(f"Contains suspicious keyword: {kw}")
                
        if len(test_url) > 75:
            results["score"] += 15
            results["reasons"].append(f"URL length is excessive ({len(test_url)} chars)")
            
        subdomains = hostname.split(".")
        if len(subdomains) > 3:
            results["score"] += 20
            results["reasons"].append(f"Excessive number of subdomains ({len(subdomains)})")
            
        if results["score"] >= 40:
            results["is_suspicious"] = True
            
        print(f"[*] URL: {test_url}")
        print(f"  Phishing Score Index: {Fore.YELLOW}{results['score']}/100{Style.RESET_ALL}")
        if results["is_suspicious"]:
            print(f"  {Fore.RED}[!] STATUS: Suspicious URL detected!{Style.RESET_ALL}")
            for reason in results["reasons"]:
                print(f"    - {reason}")
        else:
            print(f"  {Fore.GREEN}[+] STATUS: Clear / Low Risk URL.{Style.RESET_ALL}")
            
        return results

    def generate_html_report(self, scanner_res, header_res, log_res, brute_res, phishing_res):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        report_dir = os.path.abspath(os.path.join(script_dir, "..", "reports"))
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            
        report_path = os.path.join(report_dir, "security_analysis_report.html")
        
        if "error" in header_res:
            header_table_rows = f"<tr><td colspan='4' class='text-danger'>Could not connect to target to analyze security headers. Error: {header_res['error']}</td></tr>"
            header_score = "N/A"
        else:
            header_table_rows = "".join([f"<tr><td>{h}</td><td><span class='badge {'bg-green' if details['present'] else 'bg-red'}'>{'Present' if details['present'] else 'Missing'}</span></td><td><code>{details['value'] if details['value'] else 'N/A'}</code></td><td>{details['description']}</td></tr>" for h, details in header_res.items() if h != 'score'])
            header_score = f"{header_res.get('score', 0)}/100"

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Integrated Security Suite Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 1100px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #1e3a8a; }}
        .header {{ border-bottom: 3px solid #1e3a8a; padding-bottom: 15px; margin-bottom: 25px; }}
        .section {{ margin-bottom: 40px; padding: 20px; border: 1px solid #e5e7eb; border-radius: 6px; }}
        .badge {{ display: inline-block; padding: 5px 10px; border-radius: 4px; font-weight: bold; color: white; }}
        .bg-red {{ background-color: #ef4444; }}
        .bg-green {{ background-color: #10b981; }}
        .bg-yellow {{ background-color: #f59e0b; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ border: 1px solid #e5e7eb; padding: 10px; text-align: left; }}
        th {{ background-color: #f3f4f6; }}
        pre {{ background-color: #1f2937; color: #10b981; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .text-danger {{ color: #ef4444; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Suite Comprehensive Report</h1>
            <p>Generated: Academic Internship Red/Blue Security Simulation Framework</p>
        </div>

        <div class="section">
            <h2>1. Active Vulnerability Scanner Results</h2>
            <h3>Exposed Files</h3>
            {f"<table><tr><th>URL</th><th>Severity</th><th>Issue</th></tr>" if scanner_res["files"] else "<p>No exposed sensitive files detected.</p>"}
            {"".join([f"<tr><td>{item['url']}</td><td><span class='badge bg-red'>{item['severity']}</span></td><td>{item['description']}</td></tr>" for item in scanner_res["files"]])}
            {f"</table>" if scanner_res["files"] else ""}

            <h3>SQL Injection Identifications</h3>
            {f"<table><tr><th>Endpoint</th><th>Payload</th><th>Severity</th></tr>" if scanner_res["sqli"] else "<p>No SQL Injection points verified.</p>"}
            {"".join([f"<tr><td>{item['endpoint']}</td><td><code>{item['payload']}</code></td><td><span class='badge bg-red'>{item['severity']}</span></td></tr>" for item in scanner_res["sqli"]])}
            {f"</table>" if scanner_res["sqli"] else ""}

            <h3>Reflected XSS Identifications</h3>
            {f"<table><tr><th>Endpoint</th><th>Payload</th><th>Severity</th></tr>" if scanner_res["xss"] else "<p>No Reflected XSS verified.</p>"}
            {"".join([f"<tr><td>{item['endpoint']}</td><td><code>{item['payload']}</code></td><td><span class='badge bg-red'>{item['severity']}</span></td></tr>" for item in scanner_res["xss"]])}
            {f"</table>" if scanner_res["xss"] else ""}
        </div>

        <div class="section">
            <h2>2. Security Headers Analysis Score: {header_score}</h2>
            <table>
                <tr>
                    <th>Header</th>
                    <th>Status</th>
                    <th>Configured Value</th>
                    <th>Impact Details</th>
                </tr>
                {header_table_rows}
            </table>
        </div>

        <div class="section">
            <h2>3. Log Analyzer Metrics</h2>
            <ul>
                <li>SQL Injection Attempts Identified: <strong>{log_res['sqli_attempts']}</strong></li>
                <li>XSS Injection Attempts Identified: <strong>{log_res['xss_attempts']}</strong></li>
                <li>Directory Traversal Attempts Identified: <strong>{log_res['traversal_attempts']}</strong></li>
            </ul>
            <h3>Detailed Attack Log Entries</h3>
            {f"<table><tr><th>Line</th><th>Class</th><th>Log Content</th></tr>" if log_res["details"] else "<p>No attack entries flagged.</p>"}
            {"".join([f"<tr><td>{item['line']}</td><td><span class='badge bg-yellow'>{item['type']}</span></td><td><code>{item['content']}</code></td></tr>" for item in log_res["details"]])}
            {f"</table>" if log_res["details"] else ""}
        </div>

        <div class="section">
            <h2>4. Brute Force Intrusion Detection</h2>
            {f"<table><tr><th>Source IP Address</th><th>Failed Login Counts</th><th>Action Recommendation</th></tr>" if brute_res else "<p>No brute force events tracked.</p>"}
            {"".join([f"<tr><td>{ip}</td><td><code>{details['failed_attempts']}</code></td><td><span class='badge bg-red'>{details['risk']}</span></td></tr>" for ip, details in brute_res.items()])}
            {f"</table>" if brute_res else ""}
        </div>

        <div class="section">
            <h2>5. Target URL Phishing Inspection Score: {phishing_res['score']}/100</h2>
            <p>Verdict: <strong><span class="badge {'bg-red' if phishing_res['is_suspicious'] else 'bg-green'}">{'SUSPICIOUS' if phishing_res['is_suspicious'] else 'CLEAN'}</span></strong></p>
            <h3>Flags Triggered</h3>
            <ul>
                {"".join([f"<li>{reason}</li>" for reason in phishing_res['reasons']])}
            </ul>
        </div>
    </div>
</body>
</html>
"""
        with open(report_path, "w") as f:
            f.write(html_content)
        print(f"\n{Fore.GREEN}[+] Comprehensive Report generated at: {report_path}{Style.RESET_ALL}")

def main():
    tool = SecurityTool()
    
    print(f"{Fore.GREEN}==================================================")
    print(f"{Fore.GREEN}    Red Team & Blue Team Security Suite Tool")
    print(f"{Fore.GREEN}=================================================={Style.RESET_ALL}")
    
    target_url = "http://127.0.0.1:5000/"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(script_dir, "sample_logs.txt")
    phishing_url = "http://192.168.1.1/secure-update/login.php?user=admin"
    
    scanner_res = tool.run_vulnerability_scanner(target_url)
    header_res = tool.analyze_security_headers(target_url)
    log_res = tool.analyze_logs(log_file)
    brute_res = tool.detect_brute_force(log_file)
    phishing_res = tool.detect_phishing_url(phishing_url)
    
    tool.generate_html_report(scanner_res, header_res, log_res, brute_res, phishing_res)

if __name__ == "__main__":
    main()
