# Challenge-Response Login Client

Konsolen-Client für das sichere Login-Protokoll ohne Passwortübertragung.

## Installation

```bash
# Optional: Virtual Environment
python3 -m venv venv
source venv/bin/activate

# Dependencies installieren
pip install -r requirements.txt
```

## Konfiguration

### Server-URL setzen

```bash
# Option 1: Environment Variable
export SERVER_URL="http://deine-vm-ip:5000"
python3 client.py

# Option 2: Direkt im Code ändern (Zeile 20)
SERVER_URL = "http://deine-vm-ip:5000"
```

### SharedKey einrichten

Beim ersten Start wirst du nach dem SharedKey gefragt. Du hast zwei Optionen:

**Option 1: Manuell eingeben**
- Kopiere den SharedKey vom Server (bei `/register` oder `/get_shared_key` ausgegeben)
- Füge den 64-stelligen Hex-String ein

**Option 2: Vom Server holen**
- Gib Username und Passwort ein
- Der Client holt den SharedKey automatisch (erfordert `/get_shared_key` Endpoint)

Der SharedKey wird in `shared_key.txt` gespeichert.

## Verwendung

```bash
python3 client.py
```

### Beispiel-Session

```
==================================================
Challenge-Response Login Client
Server: http://localhost:5000
==================================================
✓ SharedKey geladen aus shared_key.txt

Username: alice

[Phase 1] Sende Login-Request für 'alice'...
[Phase 2] Entschlüssle Server-Antwort...
✓ Login erfolgreich!
  Session-ID: a1b2c3d4...

==================================================
Sichere Chat-Session gestartet
Befehle: 'hallo', 'zeit', 'hilfe', 'whoami', 'quit'
==================================================

[alice] > hallo
[Server] < Hallo alice! Willkommen im sicheren Chat.

[alice] > zeit
[Server] < Server-Zeit: 2024-01-15 14:30:22

[alice] > quit
[Server] < Session beendet. Auf Wiedersehen!

Auf Wiedersehen!
```

## Protokoll-Übersicht

```
Phase 1: Client → Server
         username + { NonceClient }SharedKey

Phase 2: Server → Client  
         { NonceClient, NonceServer, SID, SessionKey }SharedKey

Phase 3: Client → Server
         SID + { Message }SessionKey

Phase 4: Server → Client
         SID + { Answer }SessionKey
```

## Dateien

| Datei | Beschreibung |
|-------|--------------|
| `client.py` | Haupt-Client |
| `requirements.txt` | Dependencies |
| `shared_key.txt` | Gespeicherter SharedKey (wird erstellt) |
