> [!Important]
>
> - CSP violations caused by unsupported text editor, can be ignored: https://www.tiny.cloud/docs/tinymce/latest/tinymce-and-csp/
> - For SSL and HTTPS to work, change SSL context from None to Context and allow self-signed certificates (will show up as unsafe)
>
[![Python Version](https://img.shields.io/badge/python-3.12.2-blue.svg?style=flat-square)](https://www.python.org/downloads/release/python-3122/)
# 2025 Developer Log
**CONTACT FOR ENQUIRIES: roman.lacbungan@education.nsw.gov.au**
## Working Login
- <b>EMAIL:</b> john@gmail.com
- <b>PASSWORD:</b> helloworld1

## Main Features
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
- SSL and HTTPS support (allow self-signed certificates)
- Dark Mode support

## Installation
1. Clone repository
<pre>git clone https://github.com/TempeHS/2025SE-Roman.L-HSCTask1</pre>

2. Check directory
<pre>cd 2025SE-Roman.L-HSCTask1</pre>
   
3. Gather dependencies
<pre>pip install -r requirements.txt</pre>

4. Deploy live server (port: 5000)
<pre>python main.py</pre>

Once deployed, the app can be accessed on either:
- http://localhost:5000
- http://127.0.0.1:5000


## Screenshots
### Login
![desktop_screenshot (2)](https://github.com/user-attachments/assets/7f1af0c3-96ba-4030-9b91-30b945fc1581)

### Dashboard
![Screenshot_5-2-2025_125731_127 0 0 1](https://github.com/user-attachments/assets/83be37a5-8ebb-4231-9613-9eaad0c5ee50)
