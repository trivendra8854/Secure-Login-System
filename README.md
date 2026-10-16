# Secure Login System

A modern, responsive Flask web application demonstrating account registration, secure password hashing, input validation, parameterized SQL queries, session handling, logout, and optional authenticator-app 2FA.

## Features
- Responsive modern interface with login, registration, and protected dashboard
- Passwords hashed using Werkzeug's scrypt password hashing
- Username/email validation and password-strength requirements
- SQLite with parameterized queries to reduce SQL-injection risk
- CSRF protection on forms using Flask-WTF
- Session cookie settings: HttpOnly, SameSite=Lax, 30-minute lifetime
- Optional time-based one-time password (TOTP) two-factor authentication
- Security headers including Content-Security-Policy, X-Frame-Options, and nosniff
- Logout clears the session

## Requirements
- Python 3.10+
- Internet connection for the first dependency installation

## Run on Windows
1. Extract the ZIP file.
2. Open the extracted `Secure_Login_System` folder.
3. Click the File Explorer address bar, type `cmd`, and press Enter.
4. Create and activate a virtual environment (recommended):

   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   ```

5. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

6. Start the app:

   ```powershell
   py app.py
   ```

7. Open http://127.0.0.1:5000 in your browser.
8. Register a new account, then log in.

## Enable optional 2FA
1. Log in and open the dashboard.
2. Click **Set up two-factor authentication**.
3. Add the displayed secret/provisioning URI to an authenticator app that supports TOTP.
4. Enter the current six-digit code to enable 2FA.
5. Log out and log in again to test the second factor.

Keep your 2FA secret private. This demo shows the secret on the setup page for educational setup; a production app should use a secure QR workflow and provide recovery codes.

## Environment and deployment
- `SECRET_KEY` must be replaced with a long random secret in any deployment.
- Set `COOKIE_SECURE=true` when serving over HTTPS.
- Keep `FLASK_DEBUG=false` in production.
- The included SQLite database is created automatically and is ignored by Git.

This is an educational project, not a security audit or a drop-in production identity provider. Production systems should also add rate limiting, monitoring, recovery flows, and deployment-specific hardening.
