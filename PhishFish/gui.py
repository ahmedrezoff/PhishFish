# gui.py - UI with Phishing AND Vulnerability Scanning
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import analyzer
import whois_checker
import blocklist_manager
import risk_calculator
import display
import education
import vuln_scanner 
import threading

class PhishFishGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🐟 Phish Fish - Security Suite v2.0")
        self.window.geometry("950x850")
        self.window.configure(bg="#f0f8ff")
        
        self.blocklist = blocklist_manager.load_blocklist()
        self.setup_gui()
    
    def setup_gui(self):
        # Header
        header_frame = tk.Frame(self.window, bg="#2E86C1", height=100)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        title = tk.Label(header_frame, text="🐟 PHISH FISH", font=("Segoe UI", 28, "bold"), fg="white", bg="#2E86C1")
        title.pack(pady=(15, 5))
        subtitle = tk.Label(header_frame, text="Advanced Phishing Detection & Vulnerability Scanner", font=("Segoe UI", 11), fg="#E8F4FF", bg="#2E86C1")
        subtitle.pack()

        # Main Content
        main_frame = tk.Frame(self.window, bg="#f0f8ff", padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # URL Input Section
        input_frame = tk.LabelFrame(main_frame, text="🔗 URL Analysis", font=("Segoe UI", 12, "bold"), bg="#ffffff", fg="#2E86C1", relief=tk.GROOVE, bd=2)
        input_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(input_frame, text="Target URL:", font=("Segoe UI", 11), bg="#ffffff").grid(row=0, column=0, padx=15, pady=15, sticky='w')
        self.url_entry = tk.Entry(input_frame, width=50, font=("Segoe UI", 11), relief=tk.SOLID, bd=1)
        self.url_entry.grid(row=0, column=1, padx=10, pady=15, sticky='ew')
        self.url_entry.insert(0, "http://testphp.vulnweb.com") 
        
        # Buttons
        self.check_btn = tk.Button(input_frame, text="🔍 1. Detect Phishing", command=self.check_url, bg="#28B463", fg="white", font=("Segoe UI", 11, "bold"), padx=10)
        self.check_btn.grid(row=0, column=2, padx=5, pady=15)
        
        self.scan_btn = tk.Button(input_frame, text="🛡️ 2. Vuln Scan", command=self.start_vuln_scan, bg="#E67E22", fg="white", font=("Segoe UI", 11, "bold"), padx=10, state="disabled")
        self.scan_btn.grid(row=0, column=3, padx=5, pady=15)

        input_frame.columnconfigure(1, weight=1)
        
        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill='x', pady=(0, 20))
        
        # Results Display
        results_frame = tk.LabelFrame(main_frame, text="📊 Analysis Results", font=("Segoe UI", 12, "bold"), bg="#ffffff", fg="#2E86C1")
        results_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        self.status_label = tk.Label(results_frame, text="Ready to analyze", font=("Segoe UI", 12, "bold"), bg="#f8f9fa", fg="#5D6D7E", relief=tk.FLAT, padx=10, pady=8)
        self.status_label.pack(fill='x', padx=10, pady=10)
        
        text_frame = tk.Frame(results_frame, bg="#ffffff")
        text_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.results_text = scrolledtext.ScrolledText(text_frame, height=18, font=("Consolas", 10), bg="#f8f9fa", wrap=tk.WORD)
        self.results_text.pack(fill='both', expand=True)

        # Bottom Buttons
        btn_frame = tk.Frame(main_frame, bg="#f0f8ff")
        btn_frame.pack(fill='x', pady=5)
        tk.Button(btn_frame, text="📚 Education", command=self.show_education, bg="#8E44AD", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🗑️ Clear", command=self.clear_results, bg="#95A5A6", fg="white").pack(side=tk.RIGHT, padx=5)

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.status_label.config(text="Ready", fg="#5D6D7E", bg="#f8f9fa")
        self.scan_btn.config(state='disabled')

    def check_url(self):
        url = self.url_entry.get().strip()
        if not analyzer.is_valid_url(url):
            messagebox.showerror("Error", "Invalid URL")
            return
            
        self.check_btn.config(state='disabled')
        self.scan_btn.config(state='disabled') 
        self.progress.start()
        self.status_label.config(text="🔄 Analyzing Phishing Threats...", fg="#F39C12", bg="#FEF9E7")
        self.results_text.delete(1.0, tk.END)
        
        thread = threading.Thread(target=self.perform_phish_analysis, args=(url,))
        thread.start()

    def perform_phish_analysis(self, url):
        try:
            # Run the Phishing Logic
            is_blocked = blocklist_manager.is_blocked(url, self.blocklist)
            url_analysis = analyzer.analyze_url(url)
            domain_info = whois_checker.check_domain(url)
            risk_score = risk_calculator.calculate_risk(url_analysis, domain_info, is_blocked)
            risk_level = risk_calculator.get_risk_level(risk_score)
            
            # --- THE FIX: USE THE UNIVERSAL DISPLAY ENGINE ---
            result_text = display.get_report_text(url, url_analysis, domain_info, risk_score, risk_level, is_blocked)
                
            self.window.after(0, self.update_phish_results, result_text, risk_level)
            
        except Exception as e:
            self.window.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.window.after(0, self.progress.stop)
            self.window.after(0, lambda: self.check_btn.config(state='normal'))

    def update_phish_results(self, text, risk_level):
        self.progress.stop()
        self.check_btn.config(state='normal')
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        
        if risk_level == "MALICIOUS":
            self.status_label.config(text="🚨 MALICIOUS URL - SCAN BLOCKED", fg="#E74C3C", bg="#FDEDEC")
            self.scan_btn.config(state='disabled')
        elif risk_level == "SUSPICIOUS":
            self.status_label.config(text="⚠️ SUSPICIOUS - PROCEED WITH CAUTION", fg="#F39C12", bg="#FEF9E7")
            self.scan_btn.config(state='normal')
        else:
            self.status_label.config(text="✅ URL APPEARS SAFE - Scan Available", fg="#28B463", bg="#EAFAF1")
            self.scan_btn.config(state='normal')
            messagebox.showinfo("Analysis Complete", "Phishing check passed.\n\nYou can now run a Vulnerability Scan.")

    def start_vuln_scan(self):
        url = self.url_entry.get().strip()
        if '://' not in url: url = 'http://' + url
        
        resp = messagebox.askyesno("Confirm Scan", "⚠️ AUTHORIZATION CHECK\n\nOnly scan websites you own or have permission to test.\n\nDo you want to proceed?")
        if not resp: return
        
        self.scan_btn.config(state='disabled')
        self.check_btn.config(state='disabled')
        self.progress.start()
        self.status_label.config(text="🛡️ Scanning for SQLi & XSS...", fg="orange", bg="#FEF9E7")
        self.results_text.insert(tk.END, "\n\n" + "="*40 + "\n🚀 STARTING VULNERABILITY SCAN...\n" + "="*40 + "\n")
        self.results_text.see(tk.END)
        
        thread = threading.Thread(target=self.perform_vuln_scan, args=(url,))
        thread.start()

    def perform_vuln_scan(self, url):
        try:
            report = vuln_scanner.perform_deep_scan(url)
            self.window.after(0, self.update_vuln_results, report)
        except Exception as e:
             self.window.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
             self.window.after(0, self.progress.stop)

    def update_vuln_results(self, report):
        self.progress.stop()
        self.check_btn.config(state='normal')
        self.scan_btn.config(state='normal')
        self.status_label.config(text="📊 Scan Complete", fg="blue", bg="#f8f9fa")
        
        text = "\n[VULNERABILITY REPORT]\n"
        if not report['is_vulnerable']:
            text += "✅ No obvious SQLi or XSS vulnerabilities found.\n"
        else:
            if report['sqli_found']:
                text += "🚨 SQL INJECTION FOUND:\n"
                for item in report['sqli_found']: text += f"  - {item}\n"
            if report['xss_found']:
                text += "⚠️ XSS DETECTED:\n"
                for item in report['xss_found']: text += f"  - {item}\n"
        
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)

    def show_education(self):
        education.show_phishing_examples()

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PhishFishGUI()
    app.run()
