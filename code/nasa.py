from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime

private_key_nasa = rsa.generate_private_key(
    public_exponent=65537, 
    key_size=2048,
    backend=default_backend()
)
public_key_nasa = private_key_nasa.public_key()
pem_public_key_nasa = public_key_nasa.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

nasa_pk_path = "nasa_public_key.pem"
with open(nasa_pk_path, 'wb') as nasa_pk_file:
    nasa_pk_file.write(pem_public_key_nasa)

sat_pk_path = "sat_public_key.pem"

with open(sat_pk_path, 'rb') as sat_pk_file:
    pem_public_key_sat = sat_pk_file.read()

public_key_sat = serialization.load_pem_public_key(
    pem_public_key_sat,
    backend=default_backend()
)

issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"nasa"),
])
certificate = x509.CertificateBuilder().subject_name(
    issuer
).issuer_name(
    issuer
).public_key(
    public_key_sat
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # Valid for 1 year
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).sign(private_key_nasa, hashes.SHA256(), default_backend())

# Serialize certificate
pem_certificate = certificate.public_bytes(encoding=serialization.Encoding.PEM)

cert_path = "cert.pem"
with open(cert_path, 'wb') as cert_file:
    cert_file.write(pem_certificate)


