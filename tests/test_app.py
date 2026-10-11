import re

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import check_password_hash

from app import create_app


@pytest.fixture()
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "SECRET_KEY": "test-only-secret-key-not-for-production",
        "FERNET_KEY": Fernet.generate_key().decode(),
        "DATABASE": str(tmp_path / "test.sqlite3"),
        "SESSION_COOKIE_SECURE": False,
    })


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client, path):
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, f"CSRF token missing from {path}"
    return match.group(1).decode()


def register(client, username="student_01", password="Correct-Horse-42!"):
    token = csrf(client, "/register")
    return client.post("/register", data={
        "csrf_token": token, "username": username, "password": password
    }, follow_redirects=True)


def login(client, username="student_01", password="Correct-Horse-42!"):
    token = csrf(client, "/login")
    return client.post("/login", data={
        "csrf_token": token, "username": username, "password": password
    }, follow_redirects=True)


def test_register_hashes_password(app, client):
    response = register(client)
    assert response.status_code == 200
    with app.app_context():
        from app import get_db
        with get_db() as db:
            row = db.execute("SELECT password_hash FROM users WHERE username = ?", ("student_01",)).fetchone()
            assert row is not None
            assert row["password_hash"] != "Correct-Horse-42!"
            assert check_password_hash(row["password_hash"], "Correct-Horse-42!")


def test_registration_rejects_weak_password(client):
    token = csrf(client, "/register")
    response = client.post("/register", data={
        "csrf_token": token, "username": "valid_user", "password": "short"
    })
    assert response.status_code == 400
    assert b"12" in response.data


def test_registration_rejects_invalid_username(client):
    token = csrf(client, "/register")
    response = client.post("/register", data={
        "csrf_token": token, "username": "bad user';--", "password": "Long-enough-pass-123"
    })
    assert response.status_code == 400


def test_missing_csrf_token_is_rejected(client):
    response = client.post("/register", data={
        "username": "student_02", "password": "Correct-Horse-42!"
    })
    assert response.status_code == 400


def test_login_error_is_generic(client):
    token = csrf(client, "/login")
    response = client.post("/login", data={
        "csrf_token": token, "username": "not_real", "password": "wrong-password"
    })
    assert response.status_code == 401
    assert b"Invalid username or password" in response.data
    assert b"account does not exist" not in response.data.lower()


def test_note_content_is_encrypted_in_database(app, client):
    register(client)
    login(client)
    token = csrf(client, "/notes")
    response = client.post("/notes", data={
        "csrf_token": token, "title": "Private", "content": "my confidential text"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"my confidential text" in response.data
    with app.app_context():
        from app import get_db
        with get_db() as db:
            row = db.execute("SELECT encrypted_content FROM notes").fetchone()
            assert row is not None
            assert row["encrypted_content"] != "my confidential text"
            assert b"my confidential text" not in row["encrypted_content"].encode()


def test_notes_require_login(client):
    response = client.get("/notes", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_note_length_validation(client):
    register(client)
    login(client)
    token = csrf(client, "/notes")
    response = client.post("/notes", data={
        "csrf_token": token, "title": "x" * 101, "content": "text"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Title must contain" in response.data


def test_security_headers_are_present(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_note_title_is_escaped_by_template(client):
    register(client)
    login(client)
    token = csrf(client, "/notes")
    client.post("/notes", data={
        "csrf_token": token, "title": "<script>alert(1)</script>", "content": "safe text"
    })
    response = client.get("/notes")
    assert b"&lt;script&gt;" in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_duplicate_registration_is_handled_without_traceback(client):
    register(client)
    token = csrf(client, "/register")
    response = client.post("/register", data={
        "csrf_token": token, "username": "student_01", "password": "Correct-Horse-42!"
    })
    assert response.status_code == 400
    assert b"Traceback" not in response.data
