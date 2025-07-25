# cyberdudebivash Anti-Phishing Kit

A simple, educational Python-based tool designed to detect potential phishing attempts in URLs, emails, or text content. This app uses rule-based heuristics to flag suspicious indicators like non-HTTPS URLs, urgent language, or obfuscated domains. It's meant for learning and basic awareness—**not a replacement for professional antivirus or ML-based detectors**.

**Note:** Phishing detection is complex; this tool provides basic checks only. For real-world use, integrate with APIs like VirusTotal or ML models (e.g., via scikit-learn). Always verify results manually and use in a safe environment.

## Features
- **URL Analysis:** Checks for IP-based URLs, non-HTTPS, long domains, suspicious keywords, and more.
- **Email/Text Content Analysis:** Scans for urgent phrases, generic greetings, and extracts/analyzes embedded URLs.
- **File Input Support:** Browse and analyze .txt or .eml files containing email content.
- **GUI Interface:** User-friendly Tkinter-based interface for pasting text or loading files.
- **Output:** Detailed flags on potential phishing risks with explanations.

## Installation
1. Ensure Python 3.x is installed (tested on Python 3.12).
2. Clone or download the repository:

git clone <repository-url>
cd cyberdudebivash-anti-phishing-kit</repository-url>

3. No external dependencies are required (uses standard libraries: tkinter, re, urllib, os). If tkinter is missing (rare), install via your OS package manager (e.g., `sudo apt install python3-tk` on Ubuntu).

## Usage
1. Run the script:

python anti_phishing_kit.py

2. **Option 1: Paste Input**
- Enter a URL or email text in the top scrolled text box.
- Click "Analyze Input" to scan for phishing indicators.
3. **Option 2: Browse File**
- Click "Browse File" to select a .txt or .eml file.
- The tool analyzes the content and any URLs within.
4. **Output Interpretation**
- Results show in the bottom box: Safe if no flags; otherwise, lists suspicions.
- Example: A URL like "http://192.168.1.1/login" might flag as "URL uses IP address" and "suspicious keyword 'login'".

## Limitations
- **Rule-Based Only:** Relies on heuristics; may miss advanced phishing or produce false positives/negatives.
- **No ML Integration:** For enhanced accuracy, add scikit-learn or TensorFlow (not included here).
- **No Internet Access:** Does not fetch external data; for URL validation, consider adding safe API calls (e.g., to check domain reputation).
- **Platform:** GUI requires Tkinter; tested on Windows/Linux/Mac.
- **Security Warning:** Analyzing real phishing content can be risky—use a virtual machine. This tool does not block or remove threats.

## Contributing
Contributions welcome! Fork the repo and submit pull requests for features like ML-based detection, more rules, or UI improvements. Issues? Open a ticket.

## License
MIT License—free to use, modify, and distribute.

## Author
Developed by cyberdudebivash . For questions, contact via the site www.cyberdudebivash.com

mail to iambivash.bn@proton.me

## COPYRIGHT@CYBERDUDEBIVASH   2025



