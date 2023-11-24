from cryptography.hazmat.primitives import hashes, hmac
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

salt = os.urandom(16)
# derive key
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)
key = kdf.derive(b"gps authentication key")

# generate mac
hm = hmac.HMAC(key, hashes.SHA256())
hm.update(b"11001001")
mac = hm.finalize()

# verify mac
hm = hmac.HMAC(key, hashes.SHA256())
hm.update(("11001001").encode())
hm.verify(mac)
print("MAC is valid.")

# spoof the original signal, the validation should fail
#hm = hmac.HMAC(key, hashes.SHA256())
#hm.update(b"10001001")
#hm.verify(mac)
