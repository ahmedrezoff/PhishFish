# main.py - CLI with Phishing AND Vulnerability Scanning
import analyzer
import blocklist_manager
import risk_calculator
import display
import education
import whois_checker
import vuln_scanner # <--- The new import

def show_welcome():
    print("\n" + "="*60 + "\n" + " "*20 + "🐟 PHISH FISH 🐟" + "\n" + " "*15 + "Security Suite v2.0" + "\n" + "="*60 + "\n")

def show_menu():
    print("\nMAIN MENU:\n1. Check a URL (Phishing & Vuln Scan)\n2. Education\n3. Blocklist\n4. Add to Blocklist\n5. Exit\n" + "-"*60)

def check_url(blocklist):
    url = input("\n🎣 Enter URL to check: ").strip()
    if not analyzer.is_valid_url(url):
        print("❌ Invalid URL format.")
        return blocklist

    if '://' not in url: scan_url = 'http://' + url
    else: scan_url = url

    print(f"\n🔍 Analyzing Phishing Threats...")
    try:
        # 1. Phishing Analysis
        is_blocked = blocklist_manager.is_blocked(url, blocklist)
        url_analysis = analyzer.analyze_url(url)
        domain_info = whois_checker.check_domain(url)
        risk_score = risk_calculator.calculate_risk(url_analysis, domain_info, is_blocked)
        risk_level = risk_calculator.get_risk_level(risk_score)
        
        display.show_results(url, url_analysis, domain_info, risk_score, risk_level, is_blocked)
        
        # 2. Vulnerability Scan (Optional)
        # We only offer this if the site isn't already known to be malicious
        if risk_level != "MALICIOUS":
            print("\n" + "="*60)
            print("🛡️  VULNERABILITY SCANNER (OWASP TOP 10)")
            print("Would you like to deep-scan this site for SQL Injection and XSS?")
            print("(Only scan sites you have permission to test, e.g., testphp.vulnweb.com)")
            choice = input("Start Deep Scan? (y/n): ").lower()
            
            if choice == 'y':
                print("\n🚀 Starting Deep Vulnerability Scan...")
                report = vuln_scanner.perform_deep_scan(scan_url)
                
                print("\n📊 VULNERABILITY REPORT:")
                if not report['is_vulnerable']:
                    print("✅ No obvious vulnerabilities found.")
                else:
                    if report['sqli_found']:
                        print("🚨 [CRITICAL] SQL Injection Found:")
                        for vuln in report['sqli_found']: print(f"   - {vuln}")
                    
                    if report['xss_found']:
                        print("⚠️ [HIGH] XSS Detected:")
                        for vuln in report['xss_found']: print(f"   - {vuln}")
            print("="*60)

    except Exception as e:
        print(f"\n❌ ANALYSIS FAILED: {str(e)}")
    return blocklist

def main():
    show_welcome()
    blocklist = blocklist_manager.load_blocklist()
    while True:
        show_menu()
        choice = input("Select option: ")
        if choice == '1': blocklist = check_url(blocklist)
        elif choice == '2': education.show_phishing_examples()
        elif choice == '3': 
            print("Blocklist items:")
            for d in blocklist: print(f"- {d}")
        elif choice == '4':
            url = input("Enter URL to block: ")
            blocklist_manager.add_to_blocklist(url)
            blocklist = blocklist_manager.load_blocklist()
        elif choice == '5': break

if __name__ == "__main__":
    main()
