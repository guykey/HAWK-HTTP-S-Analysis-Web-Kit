from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
import datetime

# Generate a private key for the CA
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Generate the root CA certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"IL"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"North"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Haifa"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"HAWK_CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"HAWK_ROOT_CA.com"),
])
ca_cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    ca_private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # The certificate is valid for 10 years
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None),
    critical=True,
).sign(ca_private_key, hashes.SHA256(), default_backend())

# Save the private key and the certificate to files
with open("key.pem", "wb") as f:
    f.write(ca_private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    ))

with open("cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(Encoding.PEM))
