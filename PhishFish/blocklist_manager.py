# blocklist_manager.py - COMPLETE
import os
import tldextract

BLOCKLIST_FILE = "blocklist.txt"

def load_blocklist():
    """Load blocklist from file"""
    if not os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, 'w') as f:
            f.write("# Phish Fish Blocklist\n")
            f.write("phishing-site.com\n")
    
    blocklist = []
    with open(BLOCKLIST_FILE, 'r') as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith('#'):
                blocklist.append(line)
    return blocklist

def is_blocked(url, blocklist):
    """Check if URL is in blocklist"""
    try:
        # Use tldextract to check exact domain matches
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}".lower()
        
        if domain in blocklist:
            return True
            
        # Check if any blocklist entry is a suffix (e.g. block 'evil.com', url is 'mail.evil.com')
        for blocked in blocklist:
            if domain.endswith(blocked):
                return True
    except:
        return False
    return False

def add_to_blocklist(url):
    """Add domain to blocklist"""
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}".lower()
    except:
        return False
    
    blocklist = load_blocklist()
    if domain in blocklist:
        return False
    
    with open(BLOCKLIST_FILE, 'a') as f:
        f.write(f"{domain}\n")
    return True
