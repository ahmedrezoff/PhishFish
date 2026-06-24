# education.py - Phishing education module

def show_phishing_examples():
    """Show examples of phishing URLs"""
    print("\n" + "="*60)
    print(" " * 20 + "📚 PHISHING EDUCATION")
    print("="*60)
    
    print("\n🔍 COMMON PHISHING TECHNIQUES:")
    print("-" * 50)
    
    examples = [
        {
            'name': 'Homograph Attack (IDN Spoofing)',
            'url': 'http://www.аррle.com',
            'explanation': [
                '• Looks exactly like apple.com',
                '• Uses Cyrillic "а" instead of Latin "a"',
                '• Extremely hard to detect visually',
                '• Phish Fish detects the foreign characters'
            ]
        },
        {
            'name': 'Redirect Abuse (@ Symbol)',
            'url': 'http://google.com@evil-site.com',
            'explanation': [
                '• Browser ignores everything before the "@"',
                '• You think you are going to Google',
                '• Actually redirects to "evil-site.com"'
            ]
        },
        {
            'name': 'Typosquatting & Leetspeak',
            'url': 'http://g00gle.com / http://paypa1.com',
            'explanation': [
                '• Uses numbers to look like letters (0->o, 1->l)',
                '• Relies on users reading quickly',
                '• Often looks identical in certain fonts'
            ]
        },
        {
            'name': 'Brand Hijacking',
            'url': 'http://paypal.security-alert.com',
            'explanation': [
                '• Uses legitimate brand (PayPal) in subdomain',
                '• Creates fake urgency with "security-alert"',
                '• Appears legitimate but controlled by attacker'
            ]
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n📌 Example {i} - {example['name']}:")
        print(f"URL: {example['url']}")
        for line in example['explanation']:
            print(f"  {line}")
    
    print("\n" + "="*60)
    print("🛡️ HOW PHISH FISH DETECTS THESE:")
    print("="*60)
    
    detection_methods = [
        "1. ✅ Homograph/IDN detection (Cyrillic checks)",
        "2. ✅ Malicious redirect detection (@ symbol)",
        "3. ✅ Advanced Fuzzy Matching for Typos (g00gle -> google)",
        "4. ✅ Brand name detection in subdomains",
        "5. ✅ URL shortener identification",
        "6. ✅ Suspicious keyword analysis",
        "7. ✅ Domain age checking (new = riskier)",
        "8. ✅ TLD analysis (.xyz, .top = suspicious)"
    ]
    
    for method in detection_methods:
        print(method)
    
    print("\n" + "="*60)

def get_safety_tips(risk_level):
    """Get safety tips based on risk level"""
    tips = {
        'SAFE': [
            "✅ Link appears legitimate",
            "✅ Domain is well-established",
            "✅ No suspicious patterns detected",
            "⚠️ Still verify if the request seems unusual",
            "⚠️ Check sender identity if in email"
        ],
        'SUSPICIOUS': [
            "⚠️ Contains suspicious elements",
            "⚠️ Consider the source of this link",
            "⚠️ Don't enter personal or financial information",
            "⚠️ Contact sender through another channel to verify",
            "⚠️ Check if you were expecting this link",
            "❌ Better to avoid clicking"
        ],
        'MALICIOUS': [
            "❌ DO NOT CLICK THIS LINK",
            "❌ Likely phishing or malware attempt",
            "❌ Report to IT security if at work/school",
            "❌ Delete the email/message immediately",
            "❌ Warn others who might receive it",
            "❌ Consider reporting to authorities if financial"
        ]
    }
    
    return tips.get(risk_level, ["No specific tips available"])
