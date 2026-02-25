from flask import Flask, render_template, request, redirect, session, url_for, send_file
import user_store
import logging
import qrcode
import io

# Route             | Methode | Zweck                                |
# ----------------- | ------- | ------------------------------------ |
# `/login`          | GET     | Login-Form anzeigen                  |
# `/login`          | POST    | Login prüfen                         |
# `/admin/add_user` | GET     | Formular zum Anlegen eines Benutzers |
# `/admin/add_user` | POST    | Benutzer speichern                   |
# `/admin/qr/<user>`| GET     | QR-Code für TOTP lokal generieren    |

app = Flask(__name__)
app.secret_key = "AppSecretKey"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
app.logger.setLevel(logging.DEBUG)

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login_submit():
    username = request.form.get("user")
    password = request.form.get("password")

    #wenn falsher User, dann sofort sperren
    if not user_store._login(username, password):
        return "Falsche Login-Daten"
    
    #sonst Session starten
    session["pending_user"] = username
    return redirect("/login/2fa")

@app.route("/login/2fa", methods=["GET"])
def page_2fa():
    if "pending_user" not in session:
        return redirect("/login")
    return render_template("2fa.html")

@app.route("/login/2fa", methods=["POST"])
def submit_2fa():
    username = session.get("pending_user")
    code = request.form.get("code")

    app.logger.debug(f"2FA attempt for user={username}, code={code}")

    if not username:
        return redirect("/login")

    app.logger.debug(f"2FA verification result for {username}: {user_store._verify_totp(username, code)}")
    if user_store._verify_totp(username, code):
        session.pop("pending_user")
        session["user"] = username
        app.logger.info(f"User {username} logged in successfully with 2FA")
        return "Geheime Daten (eingeloggt mit 2FA)"
    else:
        app.logger.warning(f"Invalid 2FA code for user {username}")
        return "Falscher 2FA-Code"

@app.route("/admin/add_user", methods=["GET"])
def add_user_page():
    return render_template("add_user.html")

@app.route("/admin/add_user", methods=["POST"])
def add_user_submit():
    username = request.form.get("user")
    password = request.form.get("password")

    if user_store._add_user(username, password):
        # SICHER: QR-Code wird lokal generiert, nicht über externen Dienst
        return f"""
        Benutzer {username} wurde angelegt.<br>
        Öffne Google Authenticator und scanne diesen QR-Code:<br>
        <img src="/admin/qr/{username}">
        """
    else:
        return f"Benutzer {username} existiert bereits!"


@app.route("/admin/qr/<username>", methods=["GET"])
def get_qr_code(username):
    """
    Generiert QR-Code lokal auf dem Server.
    SICHER: Das TOTP-Secret wird nie an externe Dienste übertragen.
    """
    # TOTP URI holen
    totp_uri = user_store._get_totp_uri(username)
    
    if not totp_uri:
        return "User nicht gefunden", 404
    
    # QR-Code lokal generieren
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Als Bild im Speicher halten und zurückgeben
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    return send_file(buffer, mimetype="image/png")


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
