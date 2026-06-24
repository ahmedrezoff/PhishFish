# vuln_scanner.py - OWASP TOP 10 SCANNER (SQLi & XSS)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Safe payloads that identify the bug without destroying the database
SQL_PAYLOADS = ["'", "\"", "' OR 1=1 --", "\" OR 1=1 --"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"]

def get_forms(url):
    """Extract all forms from a webpage"""
    try:
        # standard user-agent to avoid being blocked immediately
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except:
        return []

def scan_sql_injection(url):
    """Test forms for SQL Injection"""
    forms = get_forms(url)
    findings = []
    
    for form in forms:
        action = form.attrs.get("action")
        post_url = urljoin(url, action)
        method = form.attrs.get("method", "get").lower()
        inputs = form.find_all("input")
        data = {}
        
        for input_tag in inputs:
            if input_tag.attrs.get("type") in ["text", "search", "password", "email"]:
                name = input_tag.attrs.get("name")
                if name:
                    for payload in SQL_PAYLOADS:
                        data[name] = payload
                        try:
                            if method == "post":
                                res = requests.post(post_url, data=data, timeout=5)
                            else:
                                res = requests.get(post_url, params=data, timeout=5)
                            
                            # Check for common database error messages
                            lower_text = res.text.lower()
                            if "syntax error" in lower_text or "mysql" in lower_text or "ora-" in lower_text:
                                findings.append(f"SQL Injection detected in input '{name}'")
                                break
                        except:
                            pass
    return findings

def scan_xss(url):
    """Test forms for XSS"""
    forms = get_forms(url)
    findings = []
    
    for form in forms:
        action = form.attrs.get("action")
        post_url = urljoin(url, action)
        method = form.attrs.get("method", "get").lower()
        inputs = form.find_all("input")
        data = {}
        
        for input_tag in inputs:
            if input_tag.attrs.get("type") in ["text", "search", "email"]:
                name = input_tag.attrs.get("name")
                if name:
                    for payload in XSS_PAYLOADS:
                        data[name] = payload
                        try:
                            if method == "post":
                                res = requests.post(post_url, data=data, timeout=5)
                            else:
                                res = requests.get(post_url, params=data, timeout=5)
                            
                            # If our script tag comes back exactly as we sent it, it's vulnerable
                            if payload in res.text:
                                findings.append(f"Reflected XSS detected in input '{name}'")
                                break
                        except:
                            pass
    return findings

def perform_deep_scan(url):
    """Main entry point used by GUI/CLI"""
    report = {'sqli_found': [], 'xss_found': [], 'is_vulnerable': False}
    try:
        report['sqli_found'] = scan_sql_injection(url)
        report['xss_found'] = scan_xss(url)
        
        if report['sqli_found'] or report['xss_found']:
            report['is_vulnerable'] = True
    except Exception as e:
        print(f"Scan failed: {e}")
    return report
