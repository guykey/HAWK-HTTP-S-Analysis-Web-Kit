import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
from struct import pack


from tls_utils import *

"""
# Parameters
plaintext = b"hello"
seq_num = 0
content_type = 0x16
ivv = bytes([0x35, 0xb5, 0x1f, 0x7c])
client_write_key = bytes([0x37, 0x6d, 0x4b, 0xfd, 0x94, 0xe2, 0x93, 0x8c, 0x23, 0xa6, 0x66, 0x65, 0x19, 0xd4, 0x84, 0xaa])
H_client = 0xffffffffffffa732  # Already in integer form

# Function to compute
def encrypt(plaintext):
    iv = ivv + bytes([0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18])

    # Encrypt the plaintext
    plaintext_size = len(plaintext)
    counter = Counter.new(nbits=32, prefix=iv, initial_value=2, allow_wraparound=False)
    cipher = AES.new(client_write_key, AES.MODE_CTR, counter=counter)
    ciphertext = cipher.encrypt(plaintext)

    # Compute the Authentication Tag
    auth_data = (
        nb_to_n_bytes(seq_num, 8)
        + nb_to_n_bytes(content_type, 1)
        + bytes([0x3, 0x3])
        + nb_to_n_bytes(plaintext_size, 2)
    )

    auth_tag = ghash(H_client, auth_data, ciphertext)
    auth_tag ^= bytes2int(
        AES.new(client_write_key, AES.MODE_ECB).encrypt(iv + b"\x00" * 3 + b"\x01")
    )
    auth_tag = nb_to_bytes(auth_tag)

    print("IV RANDOM:", iv[4:].hex().upper())
    print("Cipher Text:", ciphertext.hex().upper())
    print("Auth Tag:", auth_tag.hex().upper())


    return iv[4:] + ciphertext + auth_tag



def decrypt(self, ciphertext, seq_num, content_type, debug=True):
    iv = self.server_write_IV + ciphertext[0:8]

    counter = Counter.new(nbits=32, prefix=iv, initial_value=2, allow_wraparound=False)
    cipher = AES.new(self.server_write_key, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(ciphertext[8:-16])

    # Computing the tag is actually pretty time-consuming
    if debug:
        auth_data = nb_to_n_bytes(seq_num, 8) + nb_to_n_bytes(content_type, 1) + bytes([0x3, 0x3]) + nb_to_n_bytes(len(ciphertext)-8-16, 2)
        auth_tag = ghash(self.H_server, auth_data, ciphertext[8:-16])
        auth_tag ^= bytes2int(AES.new(self.server_write_key, AES.MODE_ECB).encrypt(iv + '\x00' * 3 + '\x01'))
        auth_tag = nb_to_bytes(auth_tag)

        print('Auth tag (from server): ' + bytes_to_hex(ciphertext[-16:]))
        print('Auth tag (from client): ' + bytes_to_hex(auth_tag))

    return plaintext


encrypt(b"hello")

srandom = hex_to_bytes("6E0C0AB5A0FE4B1D878EE7456131F557869DF0E981A7F2EA8CE29F88965BF9E1")
crandom = hex_to_bytes("E0B9183D64BDB88325D05863FD19C5D1A82DD083793FABBD4A36DF12E39938BB")
pre = hex_to_bytes("128CA80B98A49701A986C1AB2CE6DE66BB0CBC3AF91E2A4F9622C78F8802E2DA000000000000000000000000000000000000000000000000000000000000000000")

print(bytes_to_hex_str(calculate_master(pre, crandom, srandom)))

"""

with open("certs/Intermediate_Cert1.der", "rb") as file:
    content = file.read()
    
    
for i in content:
    print(hex(int(i)), end=", ")
    