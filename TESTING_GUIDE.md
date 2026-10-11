# Testing and Validation Guide

## Prerequisites

- Python 3.10 or newer
- pip
- A terminal in the project directory

## 1. Create an environment and install dependencies

Windows PowerShell:

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt

macOS/Linux:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    pip install -r requirements.txt

## 2. Generate application secrets

Generate a random Flask session secret and a Fernet encryption key. Keep both private.

PowerShell:

    $env:APP_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
    $env:FERNET_KEY = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

macOS/Linux:

    export APP_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    export FERNET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

For a local persistent setup, save these values in a private .env file and load them with your shell or a suitable environment loader. Do not commit .env. Losing the Fernet key makes existing encrypted notes unreadable.

## 3. Run automated tests

    python -m pytest -q

Tests cover password hashing, input validation, CSRF enforcement, generic login errors, encryption at rest, authentication requirements, security headers, output escaping, and duplicate registration.

## 4. Run static analysis

    python -m bandit -r app.py

Review each finding. A scan is one source of evidence, not proof of security.

## 5. Run the application

After setting both environment variables:

    python app.py

Open http://127.0.0.1:5000 in your browser. Create an account with a username of 3–30 letters/digits/underscores and a password of 12–128 characters. Create a note and verify it appears after saving. The app binds to loopback by default.

## 6. Manual security checks

1. Try registering with a short password; the application should reject it.
2. Submit a POST request without a CSRF token; it should return HTTP 400.
3. Try a username containing spaces or SQL punctuation; registration should reject it.
4. Log in with an incorrect password; the message should not disclose whether the account exists.
5. Create a note with a script tag in its title; it should display as text, not execute.
6. Inspect the SQLite notes.encrypted_content value; it should not equal the original note text.
7. Open /notes while logged out; the application should redirect to login.
8. Inspect response headers for CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Cache-Control.

## 7. Save evidence for submission

Copy actual pytest and Bandit output into your submission notes. Include screenshots of the app, a passing test run, and one or two manual checks if your mentor expects visual evidence. Never include actual secrets or private note contents in screenshots.