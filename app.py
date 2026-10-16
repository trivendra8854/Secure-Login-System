import os
import re
import sqlite3
from functools import wraps
from datetime import timedelta

import pyotp
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "secure_login.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
csrf = CSRFProtect(app)

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                twofa_enabled INTEGER NOT NULL DEFAULT 0,
                twofa_secret TEXT
            )
        """)
        db.commit()

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
        "script-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    return response

@app.before_request
def make_session_permanent():
    session.permanent = True

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access your dashboard.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def valid_password(password):
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
    )

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,24}", username):
            flash("Username must be 3–24 characters and use letters, numbers, dots, underscores, or hyphens.", "error")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
        elif not valid_password(password):
            flash("Use at least 8 characters, including uppercase, lowercase, and a number.", "error")
        elif password != confirm:
            flash("The passwords do not match.", "error")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password, method="scrypt"))
                )
                db.commit()
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username or email is already registered.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
            (identity, identity)
        ).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username/email or password.", "error")
            return render_template("login.html")
        session.clear()
        session["pending_user_id"] = user["id"]
        if user["twofa_enabled"]:
            return redirect(url_for("verify_2fa"))
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session.permanent = True
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (pending_id,)).fetchone()
        if user and user["twofa_enabled"] and pyotp.TOTP(user["twofa_secret"]).verify(code, valid_window=1):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            return redirect(url_for("dashboard"))
        flash("The verification code is incorrect or expired.", "error")
    return render_template("verify_2fa.html")

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)

@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user["twofa_enabled"]:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("dashboard"))
    secret = session.get("pending_2fa_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["pending_2fa_secret"] = secret
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["email"], issuer_name="Secure Login System"
    )
    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            db.execute("UPDATE users SET twofa_enabled = 1, twofa_secret = ? WHERE id = ?",
                       (secret, session["user_id"]))
            db.commit()
            session.pop("pending_2fa_secret", None)
            flash("Two-factor authentication is now enabled.", "success")
            return redirect(url_for("dashboard"))
        flash("That code is not valid. Check your authenticator app and try again.", "error")
    return render_template("setup_2fa.html", secret=secret, provisioning_uri=provisioning_uri)

@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    password = request.form.get("password", "")
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        get_db().execute("UPDATE users SET twofa_enabled = 0, twofa_secret = NULL WHERE id = ?", (user["id"],))
        get_db().commit()
        flash("Two-factor authentication has been disabled.", "success")
    else:
        flash("Password incorrect. Two-factor authentication was not changed.", "error")
    return redirect(url_for("dashboard"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been securely logged out.", "success")
    return redirect(url_for("index"))

@app.errorhandler(400)
def bad_request(_error):
    return render_template("error.html", code=400, message="Your request could not be verified. Refresh the page and try again."), 400

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="We couldn't find that page."), 404

init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
            host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
