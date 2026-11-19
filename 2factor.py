import random
import time
import hashlib


class TwoFactor:
    @staticmethod
    def generate_secret():
        return "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", k=16))

    @staticmethod
    def generate_code(secret):
        # Simulated TOTP: deterministic 6-digit code based on secret and current 30s window
        counter = int(time.time()) // 30
        h = hashlib.sha1((secret + str(counter)).encode()).hexdigest()
        code = str(int(h, 16) % 1000000).zfill(6)
        return code

    @staticmethod
    def verify(secret, code):
        # Accept current and previous window for clock skew
        for offset in (0, -1, 1):
            counter = int(time.time()) // 30 + offset
            h = hashlib.sha1((secret + str(counter)).encode()).hexdigest()
            expected = str(int(h, 16) % 1000000).zfill(6)
            if expected == code.strip():
                return True
        return False
