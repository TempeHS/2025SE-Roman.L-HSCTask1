[![Python Version](https://img.shields.io/badge/python-3.12.2-blue.svg?style=flat-square)](https://www.python.org/downloads/release/python-3122/)
# 2025 Developer Log
**CONTACT FOR ENQUIRIES: roman.lacbungan@education.nsw.gov.au**
## Screenshots
## Secure Features

- Strict Content Security Policy
  - No inline `<script></script>`.
  - Restricted `<iframe>` loading
  - CORS JS blocked
- Automatic account deletion after 6+ months
- Enforces an 8 character minimum password with letters and numbers
- User data can be downloaded and deleted through settings
- Passwords are hashed with randomised cryptography
- Secure session handling with Flask
- Strict input sanitization and validation
- App logging and alerts for suspicious activities
- SSL and HTTPS support

## Installation
1. Clone repository
<pre>git clone https://github.com/TempeHS/2025SE-Roman.L-HSCTask1</pre>

2. Check directory
<pre>cd 2025SE-Roman.L-HSCTask1</pre>
   
2. Gather dependencies
<pre>pip install -r requirements</pre>

2. Deploy live server (port: 5000)
<pre>python main.py</pre>

Once deployed, the app can be accessed on either:
- http://localhost:5000
- http://127.0.0.1:5000
