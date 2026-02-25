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
