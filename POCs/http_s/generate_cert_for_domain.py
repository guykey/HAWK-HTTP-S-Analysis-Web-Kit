from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
import datetime

def generate_domain_cert(domain, ca_cert, ca_key):
    domain_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"North"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Haifa"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"HAWK_LTD"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        domain_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # The certificate is valid for 1 year
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    return cert, domain_key

if __name__ == "__main__":
    target_host = "guthib.com"
    ca = "example.com_cert.pem"
    k = "example.com_key.pem"

    with open(ca, "rb") as f:
        ca = x509.load_pem_x509_certificate(f.read(), default_backend())

    with open(k, "rb") as f:
        k = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        
    domain_cert, domain_key = generate_domain_cert(target_host, ca, k)

    with open(f"{target_host}_cert.pem", "w", encoding="utf-8") as temp_cert:
        temp_cert.write(domain_cert.public_bytes(Encoding.PEM).decode())
    with open(f"{target_host}_key.pem", "w", encoding="utf-8") as temp_key:
        temp_key.write(domain_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL,
                                                 NoEncryption()).decode())