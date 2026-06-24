# display.py - UNIVERSAL REPORTING ENGINE (GUI & CLI COMPATIBLE)

def get_report_text(url, url_analysis, domain_info, risk_score, risk_level, is_blocked):
    """
    Generates a detailed report as a formatted string. 
    This allows both the Terminal and the GUI to use the same logic.
    """
    report = []
    report.append("\n" + "="*50)
    report.append(" " * 12 + "📊 DEEP SCAN REPORT")
    report.append("="*50)
    
    report.append(f"🔗 URL: {url}")
    report.append(f"🌐 FQDN: {url_analysis.get('fqdn', 'Unknown')}\n")
    
    # Risk status icons
    colors = {
        "MALICIOUS": "🔴",
        "SUSPICIOUS": "🟡",
        "LOW RISK": "🟠",
        "SAFE": "🟢"
    }
    icon = colors.get(risk_level, "⚪")
    report.append(f"{icon} STATUS: {risk_level}")
    report.append(f"📈 Risk Score: {risk_score}/100\n")
    
    report.append("🔍 DETECTED THREATS:")
    report.append("-" * 30)
    
    factors = url_analysis.get('risk_factors', [])
    findings = False
    
    for factor_code, description in factors:
        findings = True
        if factor_code in ['BRAND_IMPERSONATION', 'TYPOSQUATTING', 'AUTHORITY_SPLIT', 'IP_ADDRESS', 'SUBDOMAIN_ABUSE']:
            report.append(f"🚨 [CRITICAL] {description}")
        elif factor_code == 'RISKY_TLD':
            report.append(f"⚠️ [HIGH] {description}")
        else:
            report.append(f"⚠️ {description}")

    if url_analysis.get('keywords_found') and risk_score < 100:
        kws = ", ".join(url_analysis['keywords_found'])
        report.append(f"⚠️ Suspicious Keywords: {kws}")
        findings = True

    if not findings and not is_blocked:
        if url_analysis.get('is_whitelisted'):
            report.append("✅ Domain is Whitelisted (Official Brand Site)")
        else:
            report.append("✅ No specific threats detected.")

    report.append("\n📅 DOMAIN INFORMATION:")
    report.append("-" * 30)
    report.append(f"Registrar: {domain_info.get('registrar', 'Unknown')}")
    
    if domain_info.get('creation_date') != 'Not available':
        try:
            if hasattr(domain_info['creation_date'], 'strftime'):
                date_str = domain_info['creation_date'].strftime('%Y-%m-%d')
            else:
                date_str = str(domain_info['creation_date'])
            report.append(f"Created: {date_str}")
            report.append(f"Age: {domain_info.get('age_days', 0)} days")
            if domain_info.get('is_new', False):
                report.append("⚠️ New domain (less than 6 months old)")
        except:
            report.append("Created: Available")
            
    report.append("\n🛡️ BLOCKLIST CHECK:")
    report.append("-" * 30)
    report.append("❌ Domain is in blocklist" if is_blocked else "✅ Domain not in blocklist")
    report.append("="*50 + "\n")
    
    return "\n".join(report)

def show_results(url, url_analysis, domain_info, risk_score, risk_level, is_blocked):
    """Maintains backward compatibility for main.py (Terminal)"""
    print(get_report_text(url, url_analysis, domain_info, risk_score, risk_level, is_blocked))
