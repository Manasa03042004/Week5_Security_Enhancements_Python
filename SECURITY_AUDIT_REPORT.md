# Security Audit Report — Secure Notes Manager

## 1. Summary

This report documents risks considered in the Week 5 Python security-enhancement task and controls implemented in the Secure Notes Manager demonstration application. The application uses Flask, SQLite, Werkzeug password hashing, and Fernet authenticated encryption.

Scope: registration, login, session handling, note creation/listing/deletion, database operations, error responses, configuration, and automated tests.

Important: This is an educational self-assessment, not a third-party penetration test or certification. Do not deploy publicly without further review, HTTPS, production secret management, rate limiting, monitoring, backups, and a deployment-specific security assessment.

## 2. Findings and fixes

| ID | Risk / potential vulnerability | How it could be exploited | Implemented mitigation | Validation |
|---|---|---|---|---|
| SEC-01 | SQL injection from untrusted input | Crafted usernames or note IDs could alter a query if concatenated into SQL strings | SQL statements use ? placeholders and separate parameter values | Code review and input tests |
| SEC-02 | Plain-text password storage | A database leak would reveal passwords directly | Passwords are hashed with Werkzeug's scrypt password-hashing implementation | test_register_hashes_password |
| SEC-03 | Plain-text sensitive note content at rest | Someone with the SQLite file could read note bodies | Note bodies are encrypted with Fernet before insertion and decrypted for the authenticated owner | test_note_content_is_encrypted_in_database |
| SEC-04 | Cross-site request forgery (CSRF) | A malicious site could try to submit an authenticated user's state-changing form | Random session-bound CSRF tokens are required for state-changing requests and compared using secrets.compare_digest | test_missing_csrf_token_is_rejected |
| SEC-05 | Weak or malformed input | Oversized fields or unexpected usernames may cause abuse or inconsistent data | Username allowlist, password length rules, title/content limits, HTML constraints, and request-size limit | Input validation tests |
| SEC-06 | Account enumeration through login errors | Different messages could tell attackers which usernames exist | Login failures use the same generic message | test_login_error_is_generic |
| SEC-07 | Cross-user access to notes | A user could try to access or delete another user's records | Listing filters by session user ID; deletion checks note ID and owner ID in one parameterized query | Authorization code review; add more multi-user tests before production |
| SEC-08 | Cross-site scripting (XSS) | Crafted note titles or contents could be interpreted as executable HTML | Jinja autoescaping is retained for user-controlled fields | test_note_title_is_escaped_by_template |
| SEC-09 | Missing browser security headers | Clickjacking, MIME sniffing, or referrer leakage may be easier | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy | test_security_headers_are_present |
| SEC-10 | Secrets committed to source control | Exposed keys could allow session forgery or loss of data confidentiality | Required secrets come from environment/configuration; .env and local databases are ignored by Git | Configuration and .gitignore review |
| SEC-11 | Verbose error disclosure | Tracebacks and SQL details could reveal implementation internals | Generic user-facing error pages; unexpected errors logged server-side | Duplicate-registration test and error-handler review |
| SEC-12 | Unnecessary caching of sensitive pages | Shared browser caches could retain private content | Responses use Cache-Control: no-store | test_security_headers_are_present |

## 3. Secure implementation examples

### Parameterized SQL

    db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,),
    )

Input is supplied as data rather than interpolated into SQL syntax.

### Password hashing

    password_hash = generate_password_hash(password, method="scrypt")
    check_password_hash(user["password_hash"], submitted_password)

The application stores a password hash, not the original password.

### Encrypting note content

    encrypted = cipher.encrypt(content.encode()).decode()
    db.execute(
        "INSERT INTO notes (user_id, title, encrypted_content) VALUES (?, ?, ?)",
        (user_id, title, encrypted),
    )

The Fernet key must be kept separately from the database. If the key is lost, encrypted notes cannot be recovered. Anyone who obtains both the database and key may be able to decrypt notes.

### CSRF validation

    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        abort(400)

Every state-changing form includes a token tied to the user's session.

## 4. Testing strategy

The automated suite covers password hashing, weak input rejection, missing CSRF tokens, generic login errors, encryption at rest, authentication requirements, field length checks, response headers, template escaping, and duplicate account handling.

Run:

    python -m pytest -q
    python -m bandit -r app.py

Record actual output from your environment. Static analysis may report findings requiring human review; a clean scan does not prove an application is secure.

## 5. Residual risks and future improvements

- Add login throttling/rate limiting and account lockout protections that resist denial-of-service abuse.
- Use HTTPS behind a properly configured production server; set APP_ENV=production so session cookies use the Secure attribute.
- Store APP_SECRET_KEY and FERNET_KEY in a secrets manager or protected deployment environment, never in Git.
- Consider managed database hosting, migrations, backup/restore tests, key rotation procedures, and audit logging.
- Add multi-user authorization tests, including attempts to delete another user's note.
- Review the Content Security Policy and deployment headers against the hosting environment.
- Pin and regularly update dependencies, and run dependency vulnerability checks.
- Use a shared, persistent limiter for production rate limiting.
- Review logging, retention, privacy, and data deletion requirements before real users store personal data.

## 6. Conclusion

The application demonstrates practical risk reduction through parameterized SQL, password hashing, encryption of note bodies at rest, CSRF protection, validation, authorization checks, generic errors, and security headers. Automated tests provide repeatable evidence for the listed controls. Security is ongoing; the limitations above should be addressed before production use.