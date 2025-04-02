import os
import socket
import shutil
import subprocess
import hashlib
import hmac
import binascii

from Crypto.Hash import *
from Crypto.Cipher import AES
from Crypto.Util import Counter

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509

import base64

TLS_APPLICATION_DATA = 23
TLS_HANDSHAKE = 22
CHANGE_CIPHER_SPEC = 20

CIPHER_SUITES = {
    "c02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
}


ALGORITHMS_DICT = {
    6: SHA512,
    5: SHA384,
    4: SHA256,
    3: SHA224,
    2: SHA1
}

#  unhexlify("c0da") -> bytes([0xc0, 0xda])


def hex_to_bytes(s: str):
    return binascii.unhexlify(s)


def nb_to_bytes(n: int):
    h = '%x' % n
    s = binascii.unhexlify('0' * (len(h) % 2) + h)
    return s


def nb_to_n_bytes(number: int, size: int):
    h = '%x' % number
    s = binascii.unhexlify('0' * (size * 2 - len(h)) + h)
    return s


def bytes_to_hex_str(byte_array: bytes):
    return "".join(format(x, "02x") for x in byte_array)


def bytes2int(b: bytes):
    return int.from_bytes(b, byteorder='big')


def bytes_to_str(b):
    return str(b)


def str_to_bytes(s):
    return s.encode()


def print_hex(byte_array: bytes):
    print("".join(format(x, "02x") for x in byte_array))


def create_cert_from_der(path: str):
    # Command to run
    command = f"openssl x509 -inform der -in {path}.der -out {path}.pem"  # Example command to list directory contents

    # Run the command
    process = subprocess.run(command, shell=True, capture_output=True, text=True)

    return process.stderr == ""


def extract_ec(name: bytes):
    if name == bytes([0, 0x17]):
        return ec.SECP256R1()

    if name == bytes([0, 0x18]):
        return ec.SECP384R1()


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def prf_sha256(secret, label, seed, length):
    """Pseudorandom function to generate key material."""
    result = b""
    A = label + seed
    while len(result) < length:
        # Update A using HMAC with the secret
        A = hmac_sha256(secret, A)
        # Concatenate A with the label and seed, then HMAC to get the next block
        result += hmac_sha256(secret, A + label + seed)
    return result[:length]


def calculate_master(pre, client_random, server_random):
    # this is how you make the master secret
    master_secret = prf_sha256(pre, b"master secret", client_random + server_random, 48)

    return master_secret


def create_tls_record(data: bytes, content_type: int):
    return bytes([content_type, 0x3, 0x3]) + len(data).to_bytes(2) + data


def gf_mult(x, y):
    product = 0
    for i in range(127, -1, -1):
        product ^= x * ((y >> i) & 1)
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    return product


def h_mult(h, val):
    product = 0
    for i in range(16):
        product ^= gf_mult(h, (val & 0xFF) << (8 * i))
        val >>= 8
    return product


def ghash(h, a, c):
    C_len = len(c)
    A_padded = bytes2int(a + b'\x00' * (16 - len(a) % 16))
    if C_len % 16 != 0:
        c += b'\x00' * (16 - C_len % 16)

    tag = h_mult(h, A_padded)

    for i in range(0, len(c) // 16):
        tag ^= bytes2int(c[i * 16:i * 16 + 16])
        tag = h_mult(h, tag)

    tag ^= bytes2int(nb_to_n_bytes(8 * len(a), 8) + nb_to_n_bytes(8 * C_len, 8))
    tag = h_mult(h, tag)

    return tag


def add_root_ca(certificate):
    try:
        cert = x509.load_pem_x509_certificate(certificate, default_backend())

        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            # Extract the RSA public key components
            public_numbers = public_key.public_numbers()
            n = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8)  # Modulus
            raw_public_key = n

        elif isinstance(public_key, dsa.DSAPublicKey):
            # Extract the DSA public key components
            public_numbers = public_key.public_numbers()
            y = public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, 'big')  # Y value
            raw_public_key = y

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # Extract the raw bytes from the EC public key
            raw_key = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            raw_public_key = raw_key

        else:
            raise Exception

        h = SHA256.new()
        h.update(raw_public_key)

        return h.digest(), bytes2int(raw_public_key)

    except Exception as e:
        pass


def load_root_ca(file):
    f = open(file, 'r')
    body = f.read()
    f.close()

    lines = body.split('\n')

    root_ca = dict()

    status = False
    certificate = ''

    for line in lines:
        if not status and line == '-----BEGIN CERTIFICATE-----':
            status = True
            certificate = '-----BEGIN CERTIFICATE-----\n'
        elif status and line != '-----END CERTIFICATE-----':
            certificate += line + "\n"
        elif status and line == '-----END CERTIFICATE-----':
            certificate += "-----END CERTIFICATE-----\n"
            dict_val = add_root_ca(certificate.encode())

            if dict_val:
                root_ca[dict_val[0]] = dict_val[1]

            status = False

    return root_ca
