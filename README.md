# Week 5 — Security Enhancements in Python Applications

An educational Flask application that demonstrates practical secure-coding controls for authentication and private notes.

## Features

- User registration with username and password validation
- Scrypt password hashing using Werkzeug
- Parameterized SQLite queries to mitigate SQL injection
- Fernet encryption for note bodies stored in the database
- Session-bound CSRF tokens for state-changing requests
- Authentication and ownership checks for private notes
- Generic login and error messages
- Output escaping and security-related HTTP response headers
- Automated tests with pytest and a Bandit static-analysis workflow

## Project structure

    app.py                         Flask application
    tests/test_app.py              Automated security and functionality tests
    SECURITY_AUDIT_REPORT.md       Risks, fixes, rationale, and residual risks
    TESTING_GUIDE.md               Setup, test, and manual validation instructions
    requirements.txt               Python dependencies
    .env.example                   Example configuration names (not real secrets)
    .github/workflows/tests.yml    GitHub Actions test and scan workflow

## Setup (Windows PowerShell)

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    $env:APP_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
    $env:FERNET_KEY = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    python app.py

Then open http://127.0.0.1:5000. See TESTING_GUIDE.md for macOS/Linux commands, automated tests, and manual security checks.

## Run checks

    python -m pytest -q
    python -m bandit -r app.py

## Security notes

- Never commit real secrets or a .env file. The example file contains placeholders only.
- Keep the Fernet key separate from the database and back it up securely. Losing it makes encrypted note contents unrecoverable.
- The application is for learning and local demonstration. Before production use, add rate limiting, HTTPS, production secret management, operational monitoring, backup and key-rotation procedures, and a deployment-specific review.
- The audit report is a self-assessment, not a third-party penetration test. Record actual test and static-analysis output rather than claiming checks passed without running them.

## Deliverables

- Application source code
- Automated tests
- Security audit report
- Testing guide
- Dependency list and GitHub Actions workflow