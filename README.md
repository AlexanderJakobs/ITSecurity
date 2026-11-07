# 🔐 IT Security Web Application

A university project exploring core **IT security concepts** through a practical web application, hosted on a university-provided virtual machine. The project demonstrates real-world implementation of modern authentication and cryptographic techniques.

---

## 📋 Topics Covered

### 🔒 TLS Server Certificate
The web application was served over HTTPS using a TLS server certificate, ensuring encrypted communication between the client and server. This included certificate configuration and validation on the university VM.

### 2 FA (TOTP)
QR-Codes are being created locally, liveliness is 30 seconds but is adaptive

### 🔑 Hashed Password Storage
User passwords are never stored in plaintext. Instead, they are securely hashed before being persisted — protecting users even in the event of a database breach.

### Passkeys
Implementation of **passkey-based authentication** as a passwordless login alternative, leveraging the WebAuthn standard. Worked only on MacOS.

### 🌐 Web Pages

| Page                         | Description                                                 |
|------------------------------|-------------------------------------------------------------|
| **Login** (`/login`)         | Authenticates existing users with password or passkey       |
| **Register** (`/add_user`)   | Create an account for new users                             |
| **2-Factor Auth** (`/2fa`)   | Second factor verification step for enhanced login security |

### 🤝 Implicit Login with Nonces and Shared Key *(Impliziter Login)*
A custom implicit login mechanism using **nonces** (number used once) and a **shared secret key** to authenticate users without transmitting credentials directly. This prevents replay attacks and ensures session integrity.

---

## 🛠️ Tech Stack

- **Crypto / Auth:** WebAuthn, AES-256, HMAC/nonce-based tokens
- **Infrastructure:** University Virtual Machine, HTTPS/TLS
- **Backend:** Python / Flask, ngrok, 
- **Frontend:** HTML


---



## 🎓 Context

This project was developed as part of a university course on **IT Security**. The goal was to apply theoretical security concepts in a working web application, covering topics from secure transport (TLS) to modern authentication mechanisms (Passkeys, 2FA) and cryptographic patterns (nonce-based implicit login).

---
## 🛡️ Security Review / Known Issues

After finishing the course I reviewed my own code the way an attacker would. This project was built to learn about security mechanisms, not to be deployed. **Do not run it on a public network.** The findings below are documented on purpose: finding and explaining weaknesses in my own code was part of the learning.

### Summary

| # | Finding | Fixed? | Severity | Location |
|---|---------|----------|----------|
| 1 | Hardcoded Flask `secret_key` allows forged sessions | ✅ Fixed| 🔴 Critical | `app.py:16` |
| 2 | Unauthenticated admin endpoints leak TOTP secrets (2FA bypass) | 🔴 Critical | `app.py` – `/admin/add_user`, `/admin/qr/<username>` |
| 3 | Debug mode enabled on all interfaces (remote code execution) |✅ Fixed| 🔴 Critical | `app.py:115`, `server.py:364` |
| 4 | Secrets and test credentials committed to the repository | 🟠 High | `data/users.json`, `client/shared_key.txt` |
| 5 | AES-CBC without integrity protection + detailed error messages (padding oracle) | 🟠 High | `server.py` – `encrypt_aes` / `decrypt_aes`, `/login`, `/chat` |
| 6 | Shared key is derived from the stored password hash | 🟠 High | `server.py` – `get_shared_key_for_user` |
| 7 | Reflected XSS in user registration response | 🟠 High | `app.py` – `add_user_submit` |
| 8 | TOTP secrets and codes written to logs | 🟡 Medium | `user_store.py` – `_verify_totp`, `app.py` – `submit_2fa` |
| 9 | Overly wide TOTP window and no rate limiting | 🟡 Medium | `user_store.py` – `valid_window=10` |
| 10 | No CSRF protection on forms | 🟡 Medium | `templates/*.html` |
| 11 | Sessions never expire, no nonce replay cache | 🟢 Low | `server.py` – `sessions`, `/login` |
| 12 | User enumeration | 🟢 Low | `server.py` – `/login` (404 vs. 401) |

### Attack chain: account takeover without the password

Findings 1 and 2 together allow a full login as any user:

1. Because `secret_key` is public, an attacker can sign their own Flask session cookie containing `pending_user = <victim>`. This skips the password check.
2. `GET /admin/qr/<victim>` requires no authentication and returns the victim's TOTP QR code. Scanning it gives the attacker valid 2FA codes.
3. `POST /login/2fa` with such a code logs the attacker in as the victim.

### Details and fixes

**1. Hardcoded `secret_key`.** Flask signs session cookies with this key. Anyone who knows it can create valid sessions for any user.
→ Load a long random key from an environment variable (`os.environ["FLASK_SECRET_KEY"]`, e.g. generated with `secrets.token_hex(32)`) and never commit it.

**2. Unauthenticated admin endpoints.** `/admin/add_user` and `/admin/qr/<username>` are reachable without login. Anyone can create accounts, and anyone who knows a username can fetch that user's TOTP secret.
→ Protect admin routes with authentication and authorization. Show the QR code only once, at registration, and only to the user who is enrolling.

**3. `debug=True` with `host="0.0.0.0"`.** The Werkzeug debugger allows executing Python code from the browser when an error occurs.
→ Never enable debug mode outside local development. Run behind a production WSGI server (e.g. gunicorn).

**4. Committed secrets.** `users.json` contains plaintext passwords for old test users (`test`–`test3`) and TOTP secrets. `client/shared_key.txt` contains key material. All of it is test data, but committing secrets is a bad habit, and they stay in the git history.
→ Add these files to `.gitignore`, keep an example file with placeholders, and use secret scanning (e.g. gitleaks) in CI.

**5. AES-CBC without integrity + verbose errors.** CBC only provides confidentiality. A modified ciphertext is not detected. The API also returns the exact exception text (`"Entschlüsselung fehlgeschlagen: {str(e)}"`), so an attacker can tell padding errors apart from other errors. Together this enables a **padding oracle attack** that can decrypt messages without the key.
→ Use an AEAD mode such as **AES-GCM**, which provides encryption and integrity. Return one generic error message for all decryption failures.

**6. Shared key derived from the password hash.** The shared key is `SHA-256(argon2_hash)`. Anyone who obtains `users.json` (exactly the attacker model the password hashing is supposed to defend against) can compute every user's shared key and log in without knowing any password. The stored hash effectively becomes a password equivalent.
→ Generate an independent random key per user, or derive it on the client from the password with a KDF and a separate salt, so that the server's stored data is not enough to authenticate.

**7. Reflected XSS.** The registration response inserts the username into HTML without escaping (`f"Benutzer {username} wurde angelegt."`). A username like `<script>…</script>` is executed in the browser.
→ Render output through Jinja2 templates (auto-escaping) or use `markupsafe.escape()`, and validate usernames against an allowlist of characters.

**8. Secrets in logs.** Debug logging writes the TOTP secret and the submitted code. Anyone with access to the logs can generate valid codes.
→ Never log secrets, passwords or codes. Log only events (e.g. "2FA failed for user X").

**9. TOTP window and brute force.** `valid_window=10` accepts 21 codes (±5 minutes) instead of the usual 1–3, and there is no limit on login or 2FA attempts. Accepted codes can also be reused.
→ Use `valid_window=1`, add rate limiting and account lockout (e.g. Flask-Limiter), and reject codes that were already used.

**10. No CSRF protection.** Forms have no CSRF tokens, so a malicious website could submit requests in a logged-in user's name (e.g. to create users).
→ Use Flask-WTF / CSRF tokens and set `SameSite` on cookies.

**11. Sessions and replay.** Chat sessions are never expired (`created` is stored but not checked). Client nonces are only checked against a 5-minute time window, not stored. A captured login message can therefore be replayed within that window. The impact is limited, because the attacker cannot decrypt the resulting session key.
→ Expire sessions, store used nonces until their timestamp expires, and reject duplicates.

**12. User enumeration.** `/login` in `server.py` returns `404 User nicht gefunden` for unknown users and `401` for wrong credentials, so attackers can find out which usernames exist.
→ Return the same response for both cases.

### What I would do differently today

- Treat every input (form fields, JSON, ciphertexts) as untrusted.
- Use well-tested libraries for authentication instead of building my own flow, e.g. Flask-Login, Flask-WTF and an AEAD mode for encryption.
- Add SAST and secret scanning (e.g. Semgrep, Bandit, gitleaks) to a CI pipeline so issues like 3, 4 and 7 are found automatically.

