#!/usr/bin/env python3
"""
Challenge-Response Login Server
Implementiert ein sicheres Login-Protokoll ohne Passwortübertragung.

Nutzt bestehende user_store.py für User-Verwaltung.

Protokoll:
1. Client -> Server: username, { NonceClient }SharedKey
2. Server -> Client: { NonceClient, NonceServer, SID, SessionKey }SharedKey
3. Client -> Server: SID, { Message }SessionKey
4. Server -> Client: SID, { Answer }SessionKey
"""

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import base64
import json
import os
import time
import uuid

# Import der bestehenden user_store Funktionen
import user_store

app = Flask(__name__)

# In-Memory Session Storage
# Format: { "SID": { "username": str, "session_key": bytes, "created": float } }
sessions = {}

# ============================================
# Hilfsfunktionen für Verschlüsselung
# ============================================

def encrypt_aes(plaintext: bytes, key: bytes) -> bytes:
    """
    Verschlüsselt mit AES-256-CBC.
    Gibt IV + Ciphertext zurück.
    """
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext


def decrypt_aes(ciphertext: bytes, key: bytes) -> bytes:
    """
    Entschlüsselt AES-256-CBC.
    Erwartet IV + Ciphertext.
    """
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


def get_shared_key_for_user(username: str) -> bytes | None:
    """
    Holt den SharedKey für einen User.
    
    Der SharedKey ist ein SHA-256 Hash des Argon2-Hashes.
    So bekommen wir einen festen 32-Byte Key für AES-256.
    
    WICHTIG: Der Client muss denselben SharedKey haben!
    Dieser wird bei der Registrierung ausgegeben.
    """
    data = user_store._load()
    
    for u in data["users"]:
        if u["name"] == username:
            # Argon2-Hash als Basis für SharedKey
            argon2_hash = u["password"]
            # SHA-256 daraus machen für feste 32 Bytes
            shared_key = hashlib.sha256(argon2_hash.encode()).digest()
            return shared_key
    
    return None


def get_argon2_hash_for_user(username: str) -> str | None:
    """Holt den Argon2-Hash eines Users (für Ausgabe an Client)."""
    data = user_store._load()
    
    for u in data["users"]:
        if u["name"] == username:
            return u["password"]
    
    return None


# ============================================
# API Endpoints
# ============================================

@app.route("/register", methods=["POST"])
def register():
    """
    Registriert einen neuen User (nutzt bestehende user_store).
    
    Request JSON:
    {
        "username": "alice",
        "password": "geheim123"
    }
    
    Response JSON:
    {
        "success": true,
        "shared_key": "abc123..." (hex-encoded, für Client-Setup)
    }
    """
    data = request.get_json()
    
    if not data or "username" not in data or "password" not in data:
        return jsonify({"success": False, "error": "username und password erforderlich"}), 400
    
    username = data["username"]
    password = data["password"]
    
    # Nutze bestehende user_store Funktion
    success = user_store._add_user(username, password)
    
    if not success:
        return jsonify({"success": False, "error": "User existiert bereits"}), 400
    
    # SharedKey für Client ausgeben
    shared_key = get_shared_key_for_user(username)
    argon2_hash = get_argon2_hash_for_user(username)
    
    return jsonify({
        "success": True,
        "message": f"User '{username}' registriert",
        "argon2_hash": argon2_hash,
        "shared_key": shared_key.hex(),
        "info": "Kopiere den shared_key zum Client! (shared_key = SHA256 von argon2_hash)"
    })


@app.route("/get_shared_key", methods=["POST"])
def get_shared_key():
    """
    Gibt den SharedKey für einen existierenden User aus.
    Erfordert Passwort-Verifikation.
    
    Request JSON:
    {
        "username": "alice",
        "password": "geheim123"
    }
    """
    data = request.get_json()
    
    if not data or "username" not in data or "password" not in data:
        return jsonify({"success": False, "error": "username und password erforderlich"}), 400
    
    username = data["username"]
    password = data["password"]
    
    # Passwort prüfen mit bestehender Funktion
    if not user_store._login(username, password):
        return jsonify({"success": False, "error": "Login fehlgeschlagen"}), 401
    
    shared_key = get_shared_key_for_user(username)
    argon2_hash = get_argon2_hash_for_user(username)
    
    return jsonify({
        "success": True,
        "argon2_hash": argon2_hash,
        "shared_key": shared_key.hex(),
        "info": "Kopiere den shared_key zum Client!"
    })


@app.route("/login", methods=["POST"])
def login():
    """
    Phase 1+2 des Protokolls: Login und Session-Etablierung.
    
    Request JSON (Phase 1):
    {
        "username": "alice",
        "encrypted_nonce": "base64..." (verschlüsselte NonceClient)
    }
    
    Response JSON (Phase 2):
    {
        "success": true,
        "encrypted_response": "base64..." (verschlüsselt: NonceClient, NonceServer, SID, SessionKey)
    }
    """
    data = request.get_json()
    
    if not data or "username" not in data or "encrypted_nonce" not in data:
        return jsonify({"success": False, "error": "username und encrypted_nonce erforderlich"}), 400
    
    username = data["username"]
    encrypted_nonce_b64 = data["encrypted_nonce"]
    
    # SharedKey des Users holen
    shared_key = get_shared_key_for_user(username)
    if not shared_key:
        return jsonify({"success": False, "error": "User nicht gefunden"}), 404
    
    try:
        # Phase 1: Client-Nonce entschlüsseln
        encrypted_nonce = base64.b64decode(encrypted_nonce_b64)
        nonce_client_data = decrypt_aes(encrypted_nonce, shared_key)
        nonce_client = json.loads(nonce_client_data.decode())
        
        # Timestamp-Check (Nonce sollte aktuell sein, max 5 Minuten alt)
        if abs(time.time() - nonce_client["timestamp"]) > 300:
            return jsonify({"success": False, "error": "Nonce abgelaufen"}), 401
        
    except Exception as e:
        return jsonify({"success": False, "error": f"Entschlüsselung fehlgeschlagen: {str(e)}"}), 401
    
    # Phase 2: Antwort erstellen
    nonce_server = {"timestamp": time.time(), "random": base64.b64encode(get_random_bytes(8)).decode()}
    sid = str(uuid.uuid4())
    session_key = get_random_bytes(32)  # 256-bit Session Key
    
    # Session speichern
    sessions[sid] = {
        "username": username,
        "session_key": session_key,
        "created": time.time()
    }
    
    # Antwort-Payload erstellen
    response_payload = {
        "nonce_client": nonce_client,
        "nonce_server": nonce_server,
        "sid": sid,
        "session_key": base64.b64encode(session_key).decode()
    }
    
    # Mit SharedKey verschlüsseln
    response_encrypted = encrypt_aes(
        json.dumps(response_payload).encode(),
        shared_key
    )
    
    return jsonify({
        "success": True,
        "encrypted_response": base64.b64encode(response_encrypted).decode()
    })


@app.route("/chat", methods=["POST"])
def chat():
    """
    Phase 3+4 des Protokolls: Verschlüsselter Chat.
    
    Request JSON (Phase 3):
    {
        "sid": "session-id",
        "encrypted_message": "base64..." (verschlüsselt mit SessionKey)
    }
    
    Response JSON (Phase 4):
    {
        "success": true,
        "sid": "session-id",
        "encrypted_response": "base64..." (verschlüsselt mit SessionKey)
    }
    """
    data = request.get_json()
    
    if not data or "sid" not in data or "encrypted_message" not in data:
        return jsonify({"success": False, "error": "sid und encrypted_message erforderlich"}), 400
    
    sid = data["sid"]
    encrypted_message_b64 = data["encrypted_message"]
    
    # Session prüfen
    if sid not in sessions:
        return jsonify({"success": False, "error": "Ungültige Session"}), 401
    
    session = sessions[sid]
    session_key = session["session_key"]
    username = session["username"]
    
    try:
        # Nachricht entschlüsseln
        encrypted_message = base64.b64decode(encrypted_message_b64)
        message_data = decrypt_aes(encrypted_message, session_key)
        message = json.loads(message_data.decode())
        
        print(f"[{username}]: {message.get('text', '')}")
        
    except Exception as e:
        return jsonify({"success": False, "error": f"Entschlüsselung fehlgeschlagen: {str(e)}"}), 400
    
    # Antwort generieren (hier könnte echte Chat-Logik sein)
    user_text = message.get("text", "")
    
    # Einfache Echo/Bot-Antworten
    if user_text.lower() in ["hallo", "hi", "hey"]:
        response_text = f"Hallo {username}! Willkommen im sicheren Chat."
    elif user_text.lower() == "zeit":
        response_text = f"Server-Zeit: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    elif user_text.lower() == "hilfe":
        response_text = "Befehle: 'hallo', 'zeit', 'hilfe', 'quit' oder einfach chatten!"
    elif user_text.lower() == "quit":
        # Session beenden
        del sessions[sid]
        response_text = "Session beendet. Auf Wiedersehen!"
    elif user_text.lower() == "whoami":
        response_text = f"Du bist eingeloggt als: {username}"
    else:
        response_text = f"Du sagtest: '{user_text}' (Echo vom Server)"
    
    # Antwort verschlüsseln
    response_payload = {
        "text": response_text,
        "timestamp": time.time()
    }
    
    encrypted_response = encrypt_aes(
        json.dumps(response_payload).encode(),
        session_key
    )
    
    return jsonify({
        "success": True,
        "sid": sid,
        "encrypted_response": base64.b64encode(encrypted_response).decode()
    })


@app.route("/status", methods=["GET"])
def status():
    """Health-Check und Status-Endpoint."""
    data = user_store._load()
    return jsonify({
        "status": "running",
        "active_sessions": len(sessions),
        "registered_users": len(data["users"])
    })


# ============================================
# Main
# ============================================

if __name__ == "__main__":
    print("=" * 50)
    print("Challenge-Response Login Server")
    print("=" * 50)
    print("Nutzt bestehende user_store.py")
    print("Endpoints:")
    print("  POST /register       - Neuen User registrieren")
    print("  POST /get_shared_key - SharedKey für existierenden User")
    print("  POST /login          - Login (Phase 1+2)")
    print("  POST /chat           - Chat (Phase 3+4)")
    print("  GET  /status         - Server-Status")
    print("=" * 50)
    
    # Server starten
    app.run(host="0.0.0.0", port=5000, debug=True)
