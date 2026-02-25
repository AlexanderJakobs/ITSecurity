import json
import os

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

import pyotp

import logging
logger = logging.getLogger(__name__)
# zum Erstellen des Hashs aus einem Passwort,
# salt_len sorgt dafür, dass ein gleiches Passwort
# einen anderen Hash bekommt
ph = PasswordHasher(time_cost=5,
    memory_cost=102400,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID)

# Path resolution damit Docker und Flask die Dateien finden
BASE_DIR = os.path.dirname(__file__)
USERS_PATH = os.path.join(BASE_DIR, "data", "users.json")

# Load and save helpers
def _load():
    with open(USERS_PATH, "r") as f:
        return json.load(f)

def _save(data):
    with open(USERS_PATH, "w") as f:
        json.dump(data, f, indent=4)


# Nutzer hinzufügen 
# input: Name und Passwort
# 1. Json holen
# 2. Prüfen, ob Nutzer schon da ist
# ja -> output false, nein -> 3.
# 3. Password hashen, TOTP Secret erstellen, Json ergänzen
# 4. users.json updaten
# return true oder false (benutzer existiert bereits)

def _add_user(name, password):
    data = _load()

    # Überprüfung ob User existiert
    for u in data["users"]:
        if u["name"] == name:
            return False

    # Password hashen
    password_hashed = ph.hash(password)

    # TOTP secret erstellen
    secret = pyotp.random_base32()#totp.generate_secret()

    # Store user entry
    data["users"].append({
        "name": name,
        "password": password_hashed,
        "totp_secret": secret
    })

    _save(data)
    return True

# Login prüfen
# 1. Json holen
# 2. gibt es den Nutzer?
# ja -> 3. nein -> return false
# 3. passwort stimmt über ein?
# 4. ja -> true, nein -> false
# return true, false 
def _login(name, password):
    data = _load()

    for u in data["users"]:
        if u["name"] == name:
            try:
                return ph.verify(u["password"], password)
            except VerifyMismatchError:
                return False

    return False 


# TOTP Validierung
def _verify_totp(name, code):
    data = _load()

    for u in data["users"]:
        if u["name"] == name:
            secret = u.get("totp_secret")
            
            logger.debug(f"TOTP verify: user={name}, secret={secret}, code={code}, now=")
            
            if not secret:
                logger.warning(f"No TOTP secret for user {name}")
                return False

            totp = pyotp.TOTP(secret)
            logger.debug(f"TOTP verify result for {name}: {totp.verify(code, valid_window=10)}")

            logger.debug(f"TOTP verify: user={name}, secret={secret}, code={code}, now={totp.now()}")
            return totp.verify(code, valid_window=10)

    logger.warning(f"TOTP verify failed: user {name} not found")
    return False

# Provide URI um QR code zu generieren
def _get_totp_uri(name):
    data = _load()

    for u in data["users"]:
        if u["name"] == name:
            secret = u["totp_secret"]
            return pyotp.TOTP(secret).provisioning_uri(name=name)

    return None
