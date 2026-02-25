import pyotp

#generiert base32 secret
def generate_secret():
    return pyotp.random_base32()

#URI für Google um Account zu speichern
def get_provisioning_uri(username, secret):
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name="sokka-server")

#validere TOTP code
def verify_code(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=10)
