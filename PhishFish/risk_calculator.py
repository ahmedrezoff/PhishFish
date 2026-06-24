# risk_calculator.py - AGGRESSIVE SCORING
def calculate_risk(url_analysis, domain_info, is_blocked):
    """
    Calculate risk score (0-100)
    """
    if is_blocked: return 100
    if url_analysis.get('is_whitelisted', False): return 0
    
    # Get the list of triggered flags (Codes only)
    factors = [f[0] for f in url_analysis.get('risk_factors', [])]
    
    # --- LEVEL 1: IMMEDIATE BLOCK (Score 100) ---
    # These are definitive proof of malicious intent.
    critical_triggers = [
        'BRAND_IMPERSONATION', 
        'TYPOSQUATTING', 
        'AUTHORITY_SPLIT', 
        'IP_ADDRESS',
        'SUBDOMAIN_ABUSE'  # New Flag
    ]
    
    for trigger in critical_triggers:
        if trigger in factors:
            return 100
            
    # --- LEVEL 2: HIGH RISK (Score 80+) ---
    
    # Risky TLDs are heavily penalized
    score = 0
    if 'RISKY_TLD' in factors:
        score = 80
    
    # --- LEVEL 3: CUMULATIVE RISK ---
    
    # Keywords
    score += len(url_analysis.get('keywords_found', [])) * 15
    
    # Domain Age (New = Bad)
    if domain_info.get('is_new', False):
        score += 20
        
    # Hidden Registrar
    if domain_info.get('registrar') == 'Unknown':
        score += 10
        
    # Special Characters
    if url_analysis.get('special_char_count', 0) > 3:
        score += 15

    return max(0, min(score, 100))

def get_risk_level(score):
    if score >= 90: return "MALICIOUS"
    elif score >= 60: return "SUSPICIOUS"
    elif score >= 25: return "LOW RISK"
    else: return "SAFE"
