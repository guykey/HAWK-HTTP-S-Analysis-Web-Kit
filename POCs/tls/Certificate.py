from tls_utils import *
import win32crypt
import Crypto
import OpenSSL
import ssl


RSA_algorithms = {
    "sha1WithRSAEncryption": SHA1,
    "sha256WithRSAEncryption": SHA256,
    "sha384WithRSAEncryption": SHA384,
}


class Certificates:
    def __init__(self, certs: list[bytes]):
        self.cert_stream = certs[0]
        self.cert = x509.load_der_x509_certificate(certs[0], default_backend())
        self.version = self.cert.version.name
        self.serial_number = self.cert.serial_number
        self.signature_algo = self.cert.signature_algorithm_oid._name
        self.algo_of_hash_signature = self.cert.signature_hash_algorithm.name,
        self.issuer = Certificates.parse_cert_data(self.cert.issuer.rfc4514_string())
        self.valid_from = self.cert.not_valid_before_utc.strftime("%m/%d/%Y")
        self.valid_until = self.cert.not_valid_after_utc.strftime("%m/%d/%Y")
        self.subject = Certificates.parse_cert_data(self.cert.subject.rfc4514_string())
        self.public_key = dict()
        self.signature = self.cert.signature

        public_key = self.cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            self.public_key = {
                "type": "RSA",
                "key_size": public_key.key_size,
                "n": public_key.public_numbers().n,
                "e": public_key.public_numbers().e
            }
        else:
            raise RuntimeError("Certificate algorithm not supported")

        self.next_cert = None

        size_signed_data = bytes2int(self.cert_stream[6:8])
        self.signed_data = self.cert_stream[4:8 + size_signed_data]

        if len(certs) > 1:
            self.next_cert = Certificates(certs[1:])


    @staticmethod
    def parse_cert_data(data):
        dict_list = list(map(lambda a: a.split("="), data.split(',')))
        dict_list = list(filter(lambda a: len(a) == 2, dict_list))

        return dict(dict_list)

    def verify_signature(self, signed_data: bytes, algo: Crypto.Hash, signature: bytes):  # checks if a signature was signed by this certificate
        hash_size = algo.digest_size
        hash1 = nb_to_bytes(pow(bytes2int(signature), self.public_key['e'], self.public_key['n']))[-hash_size:]
        h = algo.new()
        h.update(signed_data)
        hash2 = h.digest()

        if hash1 != hash2:
            return False

        return True

    def verify_chain_of_trust(self, domain=None):
        if domain is not None:
            if self.subject["CN"] != domain:
                print("WARNING: wrong domain: %s != %s" % (self.subject["CN"], domain))

        if self.signed_data is not None and self.next_cert is not None:
            chain = self.next_cert.verify_signature(self.signed_data, RSA_algorithms[self.signature_algo], self.signature)
            return chain and self.next_cert.verify_chain_of_trust()

        root_ca = load_root_ca("root_certificates.pem")

        h = SHA256.new()
        h.update(nb_to_bytes(self.public_key['n']))
        h = h.digest()

        if h not in root_ca:
            return False

        return self.public_key['n'] == root_ca[h]
