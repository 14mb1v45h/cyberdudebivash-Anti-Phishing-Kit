import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re
import urllib.parse
import urllib.request
import json
import os
import numpy as np

# Basic phishing detection rules (expandable; this is rule-based for simplicity)
def detect_phishing_url(url):
    """Simple rule-based phishing URL detection."""
    flags = []
    
    # Check for IP address in URL (common in phishing)
    if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        flags.append("URL uses IP address instead of domain (suspicious).")
    
    # Split for features
    parsed = urllib.parse.urlparse(url)
    if '@' in parsed.netloc or '%' in parsed.netloc:
        flags.append("URL contains '@' or encoded characters in domain (possible obfuscation).")
    
    # Check for common phishing keywords
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'bank', 'verify']
    if any(keyword in parsed.path.lower() for keyword in suspicious_keywords):
        flags.append("URL path contains suspicious keywords like 'login' or 'verify'.")
    
    # Check domain entropy or homographs (basic check for punycode)
    if 'xn--' in parsed.netloc:
        flags.append("URL uses internationalized domain (potential homograph attack).")
    
    return flags if flags else ["URL appears safe based on basic checks."]

def extract_url_features(url):
    """Extract features for ML-like classification."""
    features = []
    
    # Feature 1: URL length
    features.append(len(url))
    
    # Feature 2: Number of dots in domain
    parsed = urllib.parse.urlparse(url)
    features.append(parsed.netloc.count('.'))
    
    # Feature 3: Has IP (1 if yes, 0 no)
    has_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc) else 0
    features.append(has_ip)
    
    # Feature 4: Has @ symbol (1 if yes)
    has_at = 1 if '@' in parsed.netloc else 0
    features.append(has_at)
    
    # Feature 5: Number of subdomains
    features.append(len(parsed.netloc.split('.')) - 2)  # Subtract domain and TLD
    
    # Feature 6: Has HTTPS (0 if yes, 1 if no - risk if no)
    no_https = 0 if url.startswith('https://') else 1
    features.append(no_https)
    
    return np.array(features)

def simple_ml_classifier(features):
    """Simple numpy-based 'ML' classifier (threshold-based decision for demonstration).
    In a real app, train a model with scikit-learn or torch on a dataset.
    Here, we use a basic scoring system: higher score = higher phishing risk."""
    # Weights (hard-coded based on common importance: length, dots, ip, at, subdomains, no_https)
    weights = np.array([0.01, 0.2, 1.0, 1.0, 0.3, 0.5])  # Normalized to sum ~3
    score = np.dot(features, weights)
    
    # Threshold: >2 = phishing risk
    if score > 2:
        return "High phishing risk (ML score: {:.2f})".format(score)
    elif score > 1:
        return "Medium phishing risk (ML score: {:.2f})".format(score)
    else:
        return "Low phishing risk (ML score: {:.2f})".format(score)

def scan_with_virustotal(url, api_key):
    """Scan URL with VirusTotal API."""
    if not api_key:
        return "VirusTotal API key required for scanning."
    
    try:
        # Step 1: Submit URL for scan
        submit_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        params = urllib.parse.urlencode({'apikey': api_key, 'url': url})
        req = urllib.request.Request(submit_url, data=params.encode('utf-8'))
        with urllib.request.urlopen(req) as response:
            submit_result = json.loads(response.read().decode('utf-8'))
        
        if submit_result['response_code'] != 1:
            return "Failed to submit URL for scan."
        
        scan_id = submit_result['scan_id']
        
        # Step 2: Get report (may need delay for analysis, but for simplicity, fetch immediately)
        report_url = "https://www.virustotal.com/vtapi/v2/url/report"
        params = urllib.parse.urlencode({'apikey': api_key, 'resource': scan_id})
        req = urllib.request.Request(report_url + '?' + params)
        with urllib.request.urlopen(req) as response:
            report = json.loads(response.read().decode('utf-8'))
        
        if report['response_code'] == 1:
            positives = report.get('positives', 0)
            total = report.get('total', 0)
            return f"VirusTotal Scan: {positives}/{total} engines flagged as malicious.\nDetails: {report.get('verbose_msg', 'No details.')}"
        else:
            return "Scan report not ready or failed."
    except Exception as e:
        return f"Error scanning with VirusTotal: {str(e)}"

def analyze_email_content(content):
    """Basic analysis of email text for phishing indicators."""
    flags = []
    
    # Check for urgency or threats
    urgent_phrases = ['urgent', 'immediate action', 'account suspended', 'verify now', 'click here']
    if any(phrase in content.lower() for phrase in urgent_phrases):
        flags.append("Email contains urgent language (common in phishing).")
    
    # Check for poor grammar or generic greetings
    if 'dear user' in content.lower() or 'dear customer' in content.lower():
        flags.append("Generic greeting (possible phishing indicator).")
    
    return flags if flags else ["Email content appears normal based on basic checks."]

def browse_file():
    file_path = filedialog.askopenfilename(
        title="Select Email File or Enter URL/Text",
        filetypes=[("Text Files", "*.txt *.eml"), ("All Files", "*.*")]
    )
    if file_path:
        file_label.config(text=f"Selected: {os.path.basename(file_path)}")
        output_text.delete(1.0, tk.END)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Analyze as email content
            email_flags = analyze_email_content(content)
            output_text.insert(tk.END, "Email Content Analysis:\n" + "\n".join(email_flags) + "\n\n")
            
            # Extract and analyze URLs
            urls = re.findall(r'https?://[^\s]+', content)
            if urls:
                output_text.insert(tk.END, "Detected URLs:\n")
                for url in urls:
                    url_flags = detect_phishing_url(url)
                    features = extract_url_features(url)
                    ml_result = simple_ml_classifier(features)
                    output_text.insert(tk.END, f"URL: {url}\n" + "\n".join(url_flags) + f"\nML Classification: {ml_result}\n\n")
            else:
                output_text.insert(tk.END, "No URLs detected in the content.\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")

def analyze_input():
    user_input = input_text.get(1.0, tk.END).strip()
    if user_input:
        output_text.delete(1.0, tk.END)
        
        # Check if input is a URL
        if re.match(r'^https?://', user_input):
            url_flags = detect_phishing_url(user_input)
            features = extract_url_features(user_input)
            ml_result = simple_ml_classifier(features)
            output_text.insert(tk.END, "URL Analysis:\n" + "\n".join(url_flags) + f"\nML Classification: {ml_result}\n\n")
        else:
            # Treat as email/text content
            email_flags = analyze_email_content(user_input)
            output_text.insert(tk.END, "Text/Content Analysis:\n" + "\n".join(email_flags) + "\n\n")
            
            # Extract URLs if any
            urls = re.findall(r'https?://[^\s]+', user_input)
            if urls:
                output_text.insert(tk.END, "Detected URLs:\n")
                for url in urls:
                    url_flags = detect_phishing_url(url)
                    features = extract_url_features(url)
                    ml_result = simple_ml_classifier(features)
                    output_text.insert(tk.END, f"URL: {url}\n" + "\n".join(url_flags) + f"\nML Classification: {ml_result}\n\n")
        
def scan_vt():
    user_input = input_text.get(1.0, tk.END).strip()
    api_key = vt_key_entry.get().strip()
    if user_input and re.match(r'^https?://', user_input) and api_key:
        vt_result = scan_with_virustotal(user_input, api_key)
        output_text.insert(tk.END, vt_result + "\n")

# GUI Setup
root = tk.Tk()
root.title("cyberdudebivash Anti-Phishing Kit")
root.geometry("800x600")

tk.Label(root, text="cyberdudebivash Anti-Phishing Kit", font=("Arial", 14, "bold")).pack(pady=10)

tk.Label(root, text="Paste URL or Email Text Below:").pack()
input_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=10)
input_text.pack(pady=5)

analyze_btn = tk.Button(root, text="Analyze Input", command=analyze_input, width=20)
analyze_btn.pack()

tk.Label(root, text="VirusTotal API Key (for URL Scan):").pack()
vt_key_entry = tk.Entry(root, width=50)
vt_key_entry.pack(pady=5)

vt_btn = tk.Button(root, text="Scan URL with VirusTotal", command=scan_vt, width=30)
vt_btn.pack()

tk.Label(root, text="Browse Email File (.txt or .eml):").pack()
browse_btn = tk.Button(root, text="Browse File", command=browse_file, width=20)
browse_btn.pack(pady=5)

file_label = tk.Label(root, text="No file selected", fg="blue")
file_label.pack(pady=5)

output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=15)
output_text.pack(pady=10)

root.mainloop()