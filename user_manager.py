import hashlib
import secrets
from storage.database import Database


class UserManager:
    def __init__(self, db=None):
        self.db = db or Database()

    def _hash(self, password, salt):
        return hashlib.sha256((salt + password).encode()).hexdigest()

    def register(self, username, password, role="librarian"):
        salt = secrets.token_hex(8)
        h = self._hash(password, salt)
        from auth.two_factor import TwoFactor
        secret = TwoFactor.generate_secret()
        with self.db.connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash, twofa_secret, role) VALUES (?,?,?,?)",
                    (username, f"{salt}${h}", secret, role),
                )
                conn.commit()
            except Exception as e:
                if "UNIQUE" in str(e):
                    return None, "Username already exists."
                raise
        return secret, "Registered."

    def authenticate(self, username, password):
        with self.db.connect() as conn:
            r = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not r:
            return False, None
        salt, h = r["password_hash"].split("$")
        if self._hash(password, salt) != h:
            return False, None
        return True, r
