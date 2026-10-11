"""Secure Notes Manager: a small Flask app for demonstrating secure coding.

Run with: python app.py
Required environment variables: APP_SECRET_KEY, FERNET_KEY
"""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, abort, flash, g, redirect, render_template_string, request, session, url_for, current_app
from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
MIN_PASSWORD_LENGTH = 12
MAX_NOTE_TITLE_LENGTH = 100
MAX_NOTE_CONTENT_LENGTH = 5000

PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} · Secure Notes Manager</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
input, textarea, button { box-sizing: border-box; font: inherit; margin: .25rem 0 .75rem; padding: .55rem; width: 100%; }
textarea { min-height: 110px; } button { cursor: pointer; width: auto; }
.note { border: 1px solid #bbb; border-radius: 8px; padding: 1rem; margin: 1rem 0; overflow-wrap: anywhere; }
.messages { background: #fff5d6; padding: .7rem 1rem; } .muted { color: #555; }
nav { display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; } nav form { margin: 0; } nav button { margin: 0; }
</style></head>
<body><header><h1>Secure Notes Manager</h1><nav><a href="{{ url_for('home') }}">Home</a>
{% if user_id %}<a href="{{ url_for('notes') }}">My notes</a>
<form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><button type="submit">Log out</button></form>
{% else %}<a href="{{ url_for('register') }}">Register</a><a href="{{ url_for('login') }}">Log in</a>{% endif %}
</nav></header>
{% with messages = get_flashed_messages() %}{% if messages %}<ul class="messages">{% for message in messages %}<li>{{ message }}</li>{% endfor %}</ul>{% endif %}{% endwith %}
<main>{{ body|safe }}</main><footer><p class="muted">Training project · Never store production secrets in source control.</p></footer></body></html>"""

HOME_BODY = """<p>This educational application demonstrates safer authentication, database access,
CSRF protection, validation, encrypted note content, and safer error handling.</p>
{% if user_id %}<p><a href="{{ url_for('notes') }}">Open your notes</a></p>
{% else %}<p>Create an account or log in to manage encrypted notes.</p>{% endif %}"""
REGISTER_BODY = """<h2>Create account</h2><p>Usernames: 3–30 letters, digits, or underscores. Passwords: at least 12 characters.</p>
<form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<label>Username <input name="username" minlength="3" maxlength="30" pattern="[A-Za-z0-9_]{3,30}" required autocomplete="username"></label>
<label>Password <input name="password" type="password" minlength="12" maxlength="128" required autocomplete="new-password"></label>
<button type="submit">Register</button></form>"""
LOGIN_BODY = """<h2>Log in</h2><form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<label>Username <input name="username" maxlength="30" required autocomplete="username"></label>
<label>Password <input name="password" type="password" maxlength="128" required autocomplete="current-password"></label>
<button type="submit">Log in</button></form>"""
NOTES_BODY = """<h2>Add a note</h2><form method="post" action="{{ url_for('create_note') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<label>Title <input name="title" maxlength="100" required></label>
<label>Content <textarea name="content" maxlength="5000" required></textarea></label><button type="submit">Save encrypted note</button></form>
<h2>Your notes</h2>{% if notes %}{% for note in notes %}
<article class="note"><h3>{{ note.title }}</h3><p>{{ note.content }}</p>
<form method="post" action="{{ url_for('delete_note', note_id=note.id) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><button type="submit">Delete note</button></form></article>
{% endfor %}{% else %}<p>No notes yet.</p>{% endif %}"""
ERROR_BODY = """<h2>Request could not be completed</h2><p>{{ message }}</p><p><a href="{{ url_for('home') }}">Return home</a></p>"""


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("APP_SECRET_KEY"),
        FERNET_KEY=os.environ.get("FERNET_KEY"),
        DATABASE=os.environ.get("DATABASE_PATH", str(Path(app.instance_path) / "secure_notes.sqlite3")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("APP_ENV", "").lower() == "production",
        MAX_CONTENT_LENGTH=64 * 1024,
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("APP_SECRET_KEY is required. Generate a random secret and set it in the environment.")
    if not app.config.get("FERNET_KEY"):
        raise RuntimeError("FERNET_KEY is required. Generate a valid Fernet key and set it in the environment.")
    try:
        key = app.config["FERNET_KEY"]
        Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("FERNET_KEY is invalid. Generate a valid Fernet key.") from exc

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    init_db(app)

    def cipher() -> Fernet:
        key = app.config["FERNET_KEY"]
        return Fernet(key.encode() if isinstance(key, str) else key)

    def render_page(title: str, body: str, **context: Any):
        context.setdefault("user_id", session.get("user_id"))
        context.setdefault("csrf_token", csrf_token())
        rendered_body = render_template_string(body, **context)
        return render_template_string(PAGE, title=title, body=rendered_body,
                                      user_id=session.get("user_id"), csrf_token=csrf_token())

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in to continue.")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    @app.before_request
    def enforce_csrf():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected = session.get("_csrf_token")
            supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not expected or not supplied or not secrets.compare_digest(expected, supplied):
                abort(400)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def home():
        return render_page("Home", HOME_BODY, user_id=session.get("user_id"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_page("Register", REGISTER_BODY)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_RE.fullmatch(username):
            flash("Use a username containing 3–30 letters, digits, or underscores.")
            return render_page("Register", REGISTER_BODY), 400
        if len(password) < MIN_PASSWORD_LENGTH or len(password) > 128:
            flash("Password must contain 12–128 characters.")
            return render_page("Register", REGISTER_BODY), 400
        password_hash = generate_password_hash(password, method="scrypt")
        try:
            with get_db() as db:
                db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        except sqlite3.IntegrityError:
            flash("Unable to create account with those details.")
            return render_page("Register", REGISTER_BODY), 400
        flash("Account created. Please log in.")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_page("Log in", LOGIN_BODY)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.")
            return render_page("Log in", LOGIN_BODY), 401
        session.clear()
        session["user_id"] = user["id"]
        session["_csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("notes"))

    @app.post("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.")
        return redirect(url_for("home"))

    @app.get("/notes")
    @login_required
    def notes():
        with get_db() as db:
            rows = db.execute("SELECT id, title, encrypted_content FROM notes WHERE user_id = ? ORDER BY id DESC",
                              (session["user_id"],)).fetchall()
        safe_notes = []
        for row in rows:
            try:
                content = cipher().decrypt(row["encrypted_content"].encode()).decode()
            except (InvalidToken, UnicodeDecodeError):
                app.logger.error("Stored note could not be decrypted (note_id=%s)", row["id"])
                content = "[This note could not be decrypted.]"
            safe_notes.append({"id": row["id"], "title": row["title"], "content": content})
        return render_page("My notes", NOTES_BODY, notes=safe_notes)

    @app.post("/notes")
    @login_required
    def create_note():
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if not title or len(title) > MAX_NOTE_TITLE_LENGTH:
            flash("Title must contain 1–100 characters.")
            return redirect(url_for("notes"))
        if not content or len(content) > MAX_NOTE_CONTENT_LENGTH:
            flash("Note content must contain 1–5000 characters.")
            return redirect(url_for("notes"))
        encrypted = cipher().encrypt(content.encode()).decode()
        with get_db() as db:
            db.execute("INSERT INTO notes (user_id, title, encrypted_content) VALUES (?, ?, ?)",
                       (session["user_id"], title, encrypted))
        flash("Note saved.")
        return redirect(url_for("notes"))

    @app.post("/notes/<int:note_id>/delete")
    @login_required
    def delete_note(note_id: int):
        with get_db() as db:
            cursor = db.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, session["user_id"]))
        if cursor.rowcount == 0:
            abort(404)
        flash("Note deleted.")
        return redirect(url_for("notes"))

    @app.errorhandler(400)
    def bad_request(_error):
        return render_page("Bad request", ERROR_BODY,
                           message="The request was invalid or expired. Refresh the page and try again."), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_page("Not found", ERROR_BODY, message="The requested resource was not found."), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_page("Request too large", ERROR_BODY, message="The submitted request is too large."), 413

    @app.errorhandler(500)
    def internal_error(_error):
        app.logger.exception("Unhandled application error")
        return render_page("Server error", ERROR_BODY,
                           message="An unexpected error occurred. Please try again later."), 500

    app.teardown_appcontext(close_db)
    return app


def init_db(app: Flask) -> None:
    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            encrypted_content TEXT NOT NULL
        )""")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db = sqlite3.connect(current_app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        g.db = db
    return g.db


def csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


def close_db(_error: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


if __name__ == "__main__":
    application = create_app()
    application.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
