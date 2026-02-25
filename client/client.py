#!/usr/bin/env python3
"""
Challenge-Response Login Client
Konsolen-Client für das sichere Login-Protokoll ohne Passwortübertragung.

Protokoll:
1. Client -> Server: username, { NonceClient }SharedKey
2. Server -> Client: { NonceClient, NonceServer, SID, SessionKey }SharedKey
3. Client -> Server: SID, { Message }SessionKey
4. Server -> Client: SID, { Answer }SessionKey
"""

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import base64
import json
import time
import os

# ============================================
# Konfiguration
# ============================================

# Server-URL (anpassen!)
SERVER_URL = os.environ.get("SERVER_URL", "https://141.22.11.115")

# Datei zum Speichern des SharedKeys
KEY_FILE = "shared_key.txt"


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


# ============================================
# Client-Funktionen
# ============================================

def load_shared_key() -> bytes | None:
    """Lädt den SharedKey aus Datei."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r") as f:
            hex_key = f.read().strip()
            return bytes.fromhex(hex_key)
    return None


def save_shared_key(hex_key: str):
    """Speichert den SharedKey in Datei."""
    with open(KEY_FILE, "w") as f:
        f.write(hex_key)
    print(f"SharedKey gespeichert in {KEY_FILE}")


def do_login(username: str, shared_key: bytes) -> tuple[str, bytes] | None:
    """
    Führt Phase 1+2 des Protokolls durch.
    
    Returns:
        (sid, session_key) bei Erfolg, None bei Fehler
    """
    print(f"\n[Phase 1] Sende Login-Request für '{username}'...")
    
    # Phase 1: Nonce erstellen und verschlüsseln
    nonce_client = {
        "timestamp": time.time(),
        "random": base64.b64encode(get_random_bytes(8)).decode()
    }
    
    encrypted_nonce = encrypt_aes(
        json.dumps(nonce_client).encode(),
        shared_key
    )
    
    # Request senden
    try:
        response = requests.post(
            f"{SERVER_URL}/login",
            json={
                "username": username,
                "encrypted_nonce": base64.b64encode(encrypted_nonce).decode()
            }
        )
    except requests.exceptions.ConnectionError:
        print(f"✗ Verbindung zu {SERVER_URL} fehlgeschlagen!")
        return None
    
    data = response.json()
    
    if not data.get("success"):
        print(f"✗ Login fehlgeschlagen: {data.get('error')}")
        return None
    
    # Phase 2: Antwort entschlüsseln
    print("[Phase 2] Entschlüssle Server-Antwort...")
    
    try:
        encrypted_response = base64.b64decode(data["encrypted_response"])
        response_data = decrypt_aes(encrypted_response, shared_key)
        response_payload = json.loads(response_data.decode())
    except Exception as e:
        print(f"✗ Entschlüsselung fehlgeschlagen: {e}")
        return None
    
    # Nonce verifizieren
    if response_payload["nonce_client"]["timestamp"] != nonce_client["timestamp"]:
        print("✗ Nonce-Verifikation fehlgeschlagen!")
        return None
    
    sid = response_payload["sid"]
    session_key = base64.b64decode(response_payload["session_key"])
    
    print(f"✓ Login erfolgreich!")
    print(f"  Session-ID: {sid[:8]}...")
    
    return sid, session_key


def send_message(sid: str, session_key: bytes, message: str) -> str | None:
    """
    Führt Phase 3+4 des Protokolls durch.
    
    Returns:
        Server-Antwort bei Erfolg, None bei Fehler
    """
    # Phase 3: Nachricht verschlüsseln und senden
    message_payload = {
        "text": message,
        "timestamp": time.time()
    }
    
    encrypted_message = encrypt_aes(
        json.dumps(message_payload).encode(),
        session_key
    )
    
    try:
        response = requests.post(
            f"{SERVER_URL}/chat",
            json={
                "sid": sid,
                "encrypted_message": base64.b64encode(encrypted_message).decode()
            }
        )
    except requests.exceptions.ConnectionError:
        print(f"✗ Verbindung verloren!")
        return None
    
    data = response.json()
    
    if not data.get("success"):
        print(f"✗ Fehler: {data.get('error')}")
        return None
    
    # Phase 4: Antwort entschlüsseln
    try:
        encrypted_response = base64.b64decode(data["encrypted_response"])
        response_data = decrypt_aes(encrypted_response, session_key)
        response_payload = json.loads(response_data.decode())
        return response_payload["text"]
    except Exception as e:
        print(f"✗ Entschlüsselung fehlgeschlagen: {e}")
        return None


def chat_loop(username: str, sid: str, session_key: bytes):
    """Haupt-Chat-Schleife."""
    print("\n" + "=" * 50)
    print("Sichere Chat-Session gestartet")
    print("Befehle: 'hallo', 'zeit', 'hilfe', 'whoami', 'quit'")
    print("=" * 50 + "\n")
    
    while True:
        try:
            user_input = input(f"[{username}] > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nSession beendet.")
            break
        
        if not user_input:
            continue
        
        # Nachricht senden
        response = send_message(sid, session_key, user_input)
        
        if response:
            print(f"[Server] < {response}")
        
        # Bei "quit" Session beenden
        if user_input.lower() == "quit":
            break
    
    print("\nAuf Wiedersehen!")


def setup_key():
    """Interaktiver Setup für den SharedKey."""
    print("\n" + "=" * 50)
    print("SharedKey Setup")
    print("=" * 50)
    print("\nDu hast zwei Optionen:")
    print("1. SharedKey manuell eingeben (von Server kopiert)")
    print("2. SharedKey vom Server holen (erfordert Passwort)")
    
    choice = input("\nWahl [1/2]: ").strip()
    
    if choice == "1":
        hex_key = input("SharedKey (hex): ").strip()
        try:
            # Validieren
            key = bytes.fromhex(hex_key)
            if len(key) != 32:
                print("✗ SharedKey muss 32 Bytes (64 Hex-Zeichen) sein!")
                return None
            save_shared_key(hex_key)
            return key
        except ValueError:
            print("✗ Ungültiger Hex-String!")
            return None
    
    elif choice == "2":
        username = input("Username: ").strip()
        password = input("Passwort: ").strip()
        
        try:
            response = requests.post(
                f"{SERVER_URL}/get_shared_key",
                json={"username": username, "password": password}
            )
            data = response.json()
            
            if data.get("success"):
                hex_key = data["shared_key"]
                save_shared_key(hex_key)
                print(f"✓ SharedKey erhalten und gespeichert!")
                return bytes.fromhex(hex_key)
            else:
                print(f"✗ Fehler: {data.get('error')}")
                return None
        except requests.exceptions.ConnectionError:
            print(f"✗ Verbindung zu {SERVER_URL} fehlgeschlagen!")
            return None
    
    return None


# ============================================
# Main
# ============================================

def main():
    print("=" * 50)
    print("Challenge-Response Login Client")
    print(f"Server: {SERVER_URL}")
    print("=" * 50)
    
    # SharedKey laden oder einrichten
    shared_key = load_shared_key()
    
    if not shared_key:
        print("\nKein SharedKey gefunden.")
        shared_key = setup_key()
        if not shared_key:
            print("Setup abgebrochen.")
            return
    else:
        print(f"✓ SharedKey geladen aus {KEY_FILE}")
    
    # Username abfragen
    username = input("\nUsername: ").strip()
    
    if not username:
        print("Username erforderlich!")
        return
    
    # Login durchführen (Phase 1+2)
    result = do_login(username, shared_key)
    
    if not result:
        print("\nLogin fehlgeschlagen. Prüfe:")
        print("  - Ist der Server erreichbar?")
        print("  - Ist der SharedKey korrekt?")
        print("  - Existiert der User?")
        return
    
    sid, session_key = result
    
    # Chat starten (Phase 3+4)
    chat_loop(username, sid, session_key)


if __name__ == "__main__":
    main()
