# analyzer.py - FIXED LOGIC: Whitelist Priority & Hyphen Evasion
import re
import difflib
import ipaddress
import tldextract  # pip install tldextract

# --- CONFIGURATION ---

# High-Value Targets (Brands to protect)
PROTECTED_BRANDS = {
    'google': ['google.com', 'google.co.uk', 'google.co', 'google.org', 'google.net', 'blogspot.com', 'googleapis.com', 'gstatic.com'],
    'facebook': ['facebook.com', 'fb.com', 'messenger.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'ssl-images-amazon.com', 'media-amazon.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'azure.com', 'windows.net', 'azurewebsites.net', 'microsoftonline.com'],
    'apple': ['apple.com', 'icloud.com'],
    'netflix': ['netflix.com'],
    'paypal': ['paypal.com', 'paypal.me', 'paypalobjects.com'],
    'instagram': ['instagram.com'],
    'linkedin': ['linkedin.com', 'lnkd.in'],
    'youtube': ['youtube.com', 'youtu.be'],
    'twitter': ['twitter.com', 't.co', 'x.com'],
    'whatsapp': ['whatsapp.com'],
    'dropbox': ['dropbox.com', 'dropboxusercontent.com'],
    'adobe': ['adobe.com'],
    'hotmail': ['hotmail.com', 'outlook.com', 'live.com'],
    't-mobile': ['t-mobile.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com'],
    'citi': ['citi.com', 'citibank.com'],
    'ebay': ['ebay.com'],
    'walmart': ['walmart.com'],
    'target': ['target.com'],
    'irs': ['irs.gov']
}

RISKY_TLDS = [
    'xyz', 'top', 'gq', 'ml', 'tk', 'cf', 'ga', 'men', 'loan', 'win', 
    'bid', 'trade', 'online', 'shop', 'club', 'work', 'science', 
    'racing', 'stream', 'buzz', 'surf', 'monster', 'asia', 'ru', 'cn', 
    'cc', 'zip', 'mov', 'info'
]

def is_valid_url(url):
    """Global validator"""
    if not url or len(url) > 2048 or ' ' in url.strip():
        return False
    return True

def normalize_text(text):
    """
    Converts leetspeak/homoglyphs to standard text.
    """
    text = text.lower()
    replacements = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
        '6': 'g', '7': 't', '8': 'b', '9': 'g', 
        '@': 'a', '$': 's', '!': 'i', '|': 'l',
        'α': 'a', 'ρ': 'p', 'о': 'o', 'а': 'a', 'е': 'e'
    }
    res = ""
    for char in text:
        res += replacements.get(char, char)
    return res

def get_levenshtein_similarity(s1, s2):
    """Returns similarity ratio 0.0 to 1.0"""
    return difflib.SequenceMatcher(None, s1, s2).ratio()

def is_ip_address(domain_part):
    """Checks for IP addresses (Standard, Hex, Integer)"""
    try:
        ipaddress.ip_address(domain_part)
        return True
    except:
        pass
    # Integer/Hex check
    if domain_part.isdigit() or domain_part.startswith('0x'):
        try:
            val = int(domain_part, 0)
            ipaddress.IPv4Address(val)
            return True
        except:
            pass
    return False

def analyze_url(url):
    """
    MASTER ANALYSIS FUNCTION - FIXED LOGIC
    """
    result = {
        'url': url,
        'domain': '',           
        'suffix': '',          
        'subdomain': '',       
        'fqdn': '',            
        'keywords_found': [],
        'risk_factors': [],    # List of (CODE, DETAILED_EXPLANATION) tuples
        'is_whitelisted': False,
        'safe_tld': False,
        'url_length': len(url),
        'special_char_count': 0
    }
    
    # -----------------------------------------------------------
    # 1. PARSING & AUTHORITY SPLIT
    # -----------------------------------------------------------
    url_to_parse = url
    if '@' in url and 'mailto:' not in url:
        result['risk_factors'].append(('AUTHORITY_SPLIT', f"Malicious redirect detected. Hides real destination behind '@' symbol."))
        try:
            url_to_parse = "http://" + url.split('@')[-1]
        except:
            pass
    elif '://' not in url:
        url_to_parse = 'http://' + url

    try:
        extracted = tldextract.extract(url_to_parse)
        result['subdomain'] = extracted.subdomain.lower()
        result['domain'] = extracted.domain.lower()
        result['suffix'] = extracted.suffix.lower()
        result['fqdn'] = extracted.fqdn.lower()
    except:
        result['risk_factors'].append(('PARSE_ERROR', 'Could not parse domain structure'))
        return result

    # -----------------------------------------------------------
    # 2. WHITELIST CHECK (PRIORITY FIX)
    # -----------------------------------------------------------
    # Fix for google.co.uk: Check if FQDN *ends with* any official domain
    for brand, officials in PROTECTED_BRANDS.items():
        for official in officials:
            # Check exact match or subdomain match (e.g., maps.google.co.uk)
            if result['fqdn'] == official or result['fqdn'].endswith('.' + official):
                result['is_whitelisted'] = True
                return result

    # -----------------------------------------------------------
    # 3. IP ADDRESS CHECK
    # -----------------------------------------------------------
    if is_ip_address(result['domain']):
        result['risk_factors'].append(('IP_ADDRESS', f"Host '{result['domain']}' is a raw IP address, not a domain name."))
        return result

    # -----------------------------------------------------------
    # 4. TOKENIZATION & HYPHEN EVASION
    # -----------------------------------------------------------
    # Split the ENTIRE FQDN into tokens.
    # Fix: pay-pal-secure -> tokens: ['pay', 'pal', 'secure'] AND clean check
    
    # We create a list of parts to scan (domain parts + subdomain parts)
    parts_to_scan = re.split(r'[.-]', result['fqdn'])
    
    for token in parts_to_scan:
        if len(token) < 3: continue
        
        # 4a. Create CLEAN version (Remove hyphens from the token if any remain, though re.split handles most)
        # Also handles cases like "link-edin" where split might give "link", "edin"
        # But we also need to check the COMPOSITE domain "pay-pal" as "paypal"
        
        # Strategy: Check the token itself, AND check the normalized domain string
        
        clean_token = normalize_text(token.replace('-', ''))
        
        for brand in PROTECTED_BRANDS.keys():
            # Skip if token IS the brand (we handle impersonation in step 5)
            if clean_token == brand:
                continue
                
            # Fuzzy Match
            similarity = get_levenshtein_similarity(clean_token, brand)
            if similarity > 0.70: # Strict threshold
                match_percent = int(similarity * 100)
                result['risk_factors'].append((
                    'TYPOSQUATTING', 
                    f"Token '{token}' mimics brand '{brand}' ({match_percent}% match)"
                ))

    # -----------------------------------------------------------
    # 5. SUBDOMAIN & BRAND ABUSE (FIXED)
    # -----------------------------------------------------------
    # 5a. Check if "link-edin" (hyphenated) became "linkedin" and matched a brand
    # We check the full domain string (without dots) against brands
    clean_domain_str = result['domain'].replace('-', '')
    
    for brand in PROTECTED_BRANDS.keys():
        
        # Case A: Brand is in the subdomain (login.microsoftonline.com.validate.net)
        # Logic: Brand in subdomain AND main domain is NOT the brand's official site
        if brand in result['subdomain']:
             result['risk_factors'].append((
                'SUBDOMAIN_ABUSE', 
                f"Subdomain contains brand '{brand}' but points to unverified domain '{result['domain']}.{result['suffix']}'"
            ))
             break

        # Case B: Brand is in the main domain string (pay-pal-secure)
        if brand in clean_domain_str:
            # We already checked whitelist. If we are here, it's NOT authorized.
            result['risk_factors'].append((
                'BRAND_IMPERSONATION', 
                f"Domain '{result['domain']}' contains protected brand '{brand}'"
            ))
            break

    # -----------------------------------------------------------
    # 6. TLD ANALYSIS
    # -----------------------------------------------------------
    if result['suffix'] in RISKY_TLDS:
        result['risk_factors'].append(('RISKY_TLD', f"Suspicious Top-Level Domain: .{result['suffix']}"))
    
    if result['suffix'] in ['com', 'org', 'net', 'edu', 'gov']:
        result['safe_tld'] = True

    # -----------------------------------------------------------
    # 7. KEYWORDS
    # -----------------------------------------------------------
    suspicious_kws = ['verify', 'secure', 'account', 'login', 'update', 'banking', 'confirm']
    found_kws = []
    for kw in suspicious_kws:
        if kw in result['fqdn']:
            found_kws.append(kw)
    result['keywords_found'] = found_kws

    # -----------------------------------------------------------
    # 8. SPECIAL CHARS
    # -----------------------------------------------------------
    special = '@!$%&*()=+;?,'
    for char in url:
        if char in special:
            result['special_char_count'] += 1

    return result
