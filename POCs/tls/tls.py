import os
from tls_utils import *
from Certificate import Certificates


class TLS_handler:
    def __init__(self, sock: socket.socket, server_ip: str):
        self.sock = sock
        self.server_host = server_ip

        self.client_random = os.urandom(32)
        self.server_random = None

        self.session_id = os.urandom(32)

        self.certificate = None
        self.server_signature = None

        self.all_traffic = b""

        self.ec_name = None
        self.sequence_number = 0
        self.server_sequence_number = 0

        self.private_key = None
        self.public_key = None
        self.premastered_secret = None
        self.server_pubkey = None
        self.master_secret = None

        self.client_write_MAC_key = None
        self.server_write_MAC_key = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_IV = None
        self.server_write_IV = None

        self.raw_client_pubkey = None

        self.H_client = None
        self.H_server = None

        self.cipher_suite = None

    def do_handshake(self):
        self.client_hello(self.server_host)

        print("-- Server Hello --")
        print("  parsing server hello")
        self.parse_server_hello()
        print("  Cipher Suite: " + CIPHER_SUITES[self.cipher_suite])

        print("\n-- Certificate --")
        print("  parsing certificate")
        self.parse_certificate()
        print("  Checking Certificate Auth")
        if self.certificate.verify_chain_of_trust(self.server_host):
            print("  Certificates Valid")

        else:
            print("  Certificates Invalid")

        print("\n-- Key Exchange --")
        print("  parsing server key exchange")
        self.parse_server_key_exchange()
        print("    checking server's signature")
        if self.check_signature():
            print("    signature OK")

        else:
            print("    signature Not OK")

        self.parse_server_hello_done()

        print("\n  sending client key exchange")
        self.client_key_exchange()
        print("  Computing Master secret and key expansions")

        print("\n-- Encrypted Handshake Message")
        self.client_change_cipher_spec()
        print("  sending encrypted message")
        self.client_encrypted_handshake_message()
        if self.parse_change_cipher_spec():
            print("    encrypted message is OK")

        print("\n  parsing server's encrypted message")
        if self.check_server_encrypted_handshake_message():
            print("    server's message OK")
        else:
            print("    server's message not OK")

        print("\n-- HANDSHAKE FINISHED --")

    def client_hello(self, url):
        # extensions without sni
        client_hello_request = bytes([
            # Extension: EC Point Formats
            0x00, 0x0b,  # Extension type (EC Point Formats)
            0x00, 0x02,  # Length
            0x01,  # EC Point Formats length
            0x00,  # uncompressed

            # Extension: supported groups
            0x00, 0x0a,
            0x00, 0x06,
            0x00, 0x04,
            0x00, 0x17,
            0x00, 0x18,

            # Extension: renegotiation_info
            0xff, 0x01,
            0x00, 0x01,
            0x00,

            # Extension: supported versions
            0x00, 0x2b,  # Extension type
            0x00, 0x03,  # Length
            0x02,  # Supported version length
            0x03, 0x03,  # TLS 1.2

            # Extension: signature algorithm
            0x00, 0x0d,  # Extension type
            0x00, 0x04,  # Length
            0x00, 0x02,  # Algorithms length
            0x04, 0x01
        ])

        client_hello_request = url.encode() + client_hello_request  # sni url
        client_hello_request = len(url).to_bytes(2) + client_hello_request  # sni url length
        client_hello_request = bytes([0x00]) + client_hello_request  # server name type: host_name
        client_hello_request = (len(url) + 3).to_bytes(2) + client_hello_request  # length sni
        client_hello_request = (len(url) + 5).to_bytes(2) + client_hello_request  # length sni extension
        client_hello_request = bytes([0x00, 0x00]) + client_hello_request  # extension type

        client_hello_request = len(client_hello_request).to_bytes(2) + client_hello_request  # len extensions

        client_hello_request = bytes([0x01, 0x00]) + client_hello_request  # compression

        client_hello_request = bytes([0x00, 0x02,  # Cipher Suites Length
                                      0xc0, 0x2f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                                      ]) + client_hello_request  # cipher suites

        client_hello_request = self.session_id + client_hello_request  # session id
        client_hello_request = bytes([0x20]) + client_hello_request  # session id len

        client_hello_request = self.client_random + client_hello_request  # random
        client_hello_request = bytes([0x03, 0x03]) + client_hello_request  # Version: TLS 1.2 (0x0303)

        client_hello_request = len(client_hello_request).to_bytes(3) + client_hello_request  # content length

        client_hello_request = bytes([0x01]) + client_hello_request  # client hello type request

        client_hello_request = len(client_hello_request).to_bytes(2) + client_hello_request  # request length

        client_hello_request = bytes([0x16,
                                      0x03, 0x01
                                      ]) + client_hello_request  # client hello header

        self.all_traffic += client_hello_request[5:]
        self.sock.sendall(client_hello_request)

    def parse_server_hello(self):
        headers = self.sock.recv(5)

        content_type = headers[:1]

        headers = headers[1:]

        version = headers[:2]

        headers = headers[2:]
        request_length_bytes = headers[:2]

        request_length = int.from_bytes(request_length_bytes, byteorder='big')

        response = self.sock.recv(request_length)
        self.all_traffic += response

        handshake_type = response[:1]
        response = response[1:]
        content_length_bytes = response[:3]
        response = response[3:]
        content_length = int.from_bytes(content_length_bytes, byteorder='big')
        version_two = response[:2]
        response = response[2:]
        random_hash = response[:32]
        response = response[32:]
        session_id_len_bytes = response[:1]
        session_id_len = int.from_bytes(session_id_len_bytes, byteorder='big')
        response = response[1:]
        session_id = response[:session_id_len]
        response = response[session_id_len:]
        cipher_suite = response[:2]
        response = response[2:]
        compression_method = response[:1]
        response = response[1:]
        extensions_length_bytes = response[:2]
        response = response[2:]
        extensions_length = int.from_bytes(extensions_length_bytes, byteorder='big')

        extensions = []
        length_read = 0
        while length_read < extensions_length:
            extension_type = response[:2]
            response = response[2:]
            extension_len_bytes = response[:2]
            response = response[2:]
            extension_len = int.from_bytes(extension_len_bytes, byteorder='big')
            length_read += 4

            if extension_len == 0:
                extensions.append(
                    {"type": bytes_to_hex_str(extension_type), "length": bytes_to_hex_str(extension_len_bytes),
                     "data": "NONE"})
                continue

            extension_data = response[:extension_len]
            response = response[extension_len:]
            length_read += extension_len

            extensions.append(
                {"type": bytes_to_hex_str(extension_type), "length": bytes_to_hex_str(extension_len_bytes),
                 "data": bytes_to_hex_str(extension_data)})

        self.server_random = random_hash
        self.cipher_suite = bytes_to_hex_str(cipher_suite)

        """
        print("content type: ", end="")
        print_hex(content_type)
        print("version: ", end="")
        print_hex(version)
        print("request length: ", end="")
        print_hex(request_length_bytes)
        print("handshake type: ", end="")
        print_hex(handshake_type)
        print("content length: ", end="")
        print_hex(content_length_bytes)
        print("version: ", end="")
        print_hex(version_two)
        print("random_hash: ", end="")
        print_hex(random_hash)
        print("session id length: ", end="")
        print_hex(session_id_len_bytes)
        print("session id: ", end="")
        print_hex(session_id)
        print("cipher suite: ", end="")
        print_hex(cipher_suite)
        print("compression method: ", end="")
        print_hex(compression_method)
        print("extensions length: ", end="")
        print_hex(extensions_length_bytes)
        print("extensions: ", end="")
        print(extensions)
        """

    def parse_certificate(self):
        headers = self.sock.recv(5)

        content_type = bytes2int(headers[0:1])
        version = bytes2int(headers[1:3])

        content_length = bytes2int(headers[3:])

        cert_content = self.sock.recv(content_length)
        while len(cert_content) < content_length:
            cert_content += self.sock.recv(content_length - len(cert_content))

        self.all_traffic += cert_content

        handshake_type = bytes2int(cert_content[0:1])
        length = bytes2int(cert_content[1:4])
        certs_length = bytes2int(cert_content[4:7])

        s = 7
        lst_of_certs = []
        i = 0

        while s <= content_length:
            cert_length = bytes2int(cert_content[s:s + 3])
            if cert_length <= 0:
                break
            i += 1
            s += 3
            lst_of_certs.append(cert_content[s:s + cert_length])
            s += cert_length

        if len(lst_of_certs) == 0:
            return

        directory = "certs"

        if os.path.exists(directory):
            shutil.rmtree(directory)

        os.makedirs(directory)

        error = ""
        self.certificate = Certificates(lst_of_certs)

        for idx, val in enumerate(lst_of_certs):
            if idx == 0:
                name = "Server_Cert"

            else:
                name = f"Intermediate_Cert{idx}"

            name = f"{directory}\\{name}"

            with open(f"{name}.der", "wb") as file:
                file.write(val)

            if not create_cert_from_der(name):
                error += f"Couldn't convert certificate {idx}\n"

        if error != "":
            print("Certificate Error List\n" + error)

    def parse_server_key_exchange(self):
        headers = self.sock.recv(5)

        content_type = bytes2int(headers[0:1])
        version = bytes2int(headers[1:3])

        content_length = bytes2int(headers[3:])

        data = self.sock.recv(content_length)
        while len(data) < content_length:
            data += self.sock.recv(content_length - len(data))

        self.all_traffic += data
        handshake_type = bytes2int(data[0:1])
        length = bytes2int(data[1:4])

        s = 4

        curve_type = data[s:s + 1]
        s += 1
        named_curve = data[s:s + 2]
        s += 2
        public_key_length = bytes2int(data[s:s + 1])
        s += 1
        public_key = data[s:s + public_key_length]
        s += public_key_length
        signature_algorithm = data[s:s + 2]
        s += 2
        signature_length = bytes2int(data[s:s + 2])
        s += 2
        signature = data[s:s + signature_length]
        self.server_signature = {"signature": signature,
                                 "signed_data": self.client_random + self.server_random + curve_type + named_curve + public_key_length.to_bytes(1) + public_key,
                                 "algo": ALGORITHMS_DICT[signature_algorithm[0]]
                                 }
        self.server_pubkey = public_key
        self.ec_name = extract_ec(named_curve)

        self.extract_keys()

    def extract_keys(self):
        self.private_key = ec.generate_private_key(self.ec_name, default_backend())
        self.public_key = self.private_key.public_key()
        # Create an ECPublicKey object

        self.server_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(self.ec_name, self.server_pubkey)
        self.premastered_secret = self.private_key.exchange(ec.ECDH(), self.server_pubkey)

        self.master_secret = calculate_master(self.premastered_secret, self.client_random, self.server_random)
        keys = prf_sha256(self.master_secret, b"key expansion", self.server_random + self.client_random, 40)
        # is 40 bytes, tested works

        # The client and server keys are 16 bytes because we are using AES 128-bit aka a 128 bit = 16 bytes key
        self.client_write_key = keys[:16]
        self.server_write_key = keys[16:32]
        
        self.client_write_IV = keys[32:36]
        self.server_write_IV = keys[36:40]
        
        self.H_client = bytes2int(AES.new(self.client_write_key, AES.MODE_ECB).encrypt(bytes([0] * 16)))
        self.H_server = bytes2int(AES.new(self.server_write_key, AES.MODE_ECB).encrypt(bytes([0] * 16)))

    def check_signature(self):
        return self.certificate.verify_signature(self.server_signature["signed_data"], self.server_signature["algo"], self.server_signature["signature"])

    def parse_server_hello_done(self):
        headers = self.sock.recv(5)

        content_type = bytes2int(headers[0:1])
        version = bytes2int(headers[1:3])

        content_length = bytes2int(headers[3:])

        data = self.sock.recv(content_length)
        while len(data) < content_length:
            data += self.sock.recv(content_length - len(data))

        self.all_traffic += data

    def client_key_exchange(self):
        client_key_exchange_request = bytes([0x10])

        key = self.public_key.public_bytes(encoding=serialization.Encoding.X962,
                                           format=serialization.PublicFormat.UncompressedPoint)
        self.raw_client_pubkey = key

        dh_params = len(key).to_bytes(1) + key

        client_key_exchange_request += len(dh_params).to_bytes(3) + dh_params

        self.all_traffic += client_key_exchange_request

        self.sock.sendall(create_tls_record(client_key_exchange_request, TLS_HANDSHAKE))

    def client_change_cipher_spec(self):
        request = bytes([0x01])

        self.sock.sendall(create_tls_record(request, CHANGE_CIPHER_SPEC))

    def client_encrypted_handshake_message(self):
        handshake_hash = hashlib.sha256(self.all_traffic).digest()

        verify_data = prf_sha256(self.master_secret, b"client finished", handshake_hash, 12)

        encrypted_finish = bytes([0x14, 0x00, 0x00, 0x0C]) + verify_data
        self.all_traffic += encrypted_finish # this is NOT WRONG!

        self.send(encrypted_finish, content_type=TLS_HANDSHAKE)

    def parse_change_cipher_spec(self):
        headers = self.sock.recv(5)

        content_type = bytes2int(headers[0:1])
        version = bytes2int(headers[1:3])

        content_length = bytes2int(headers[3:])

        data = self.sock.recv(content_length)
        while len(data) < content_length:
            data += self.sock.recv(content_length - len(data))

        if content_type == CHANGE_CIPHER_SPEC:
            return True

        return False

    def check_server_encrypted_handshake_message(self):
        headers = self.sock.recv(5)

        content_type = bytes2int(headers[0:1])
        version = bytes2int(headers[1:3])

        content_length = bytes2int(headers[3:])

        data = self.sock.recv(content_length)
        while len(data) < content_length:
            data += self.sock.recv(content_length - len(data))

        #server_encrypted_message = data[5:]  # go to data section
        server_encrypted_message = data
        try:
            server_message = self.decrypt(server_encrypted_message, seq_num=self.server_sequence_number, content_type=TLS_HANDSHAKE)

            self.server_sequence_number += 1

            handshake_hash = hashlib.sha256(self.all_traffic).digest()
            verify_data = prf_sha256(self.master_secret, b"server finished", handshake_hash, 12)
            server_message_hash_computed = bytes([0x14, 0x00, 0x00, 0x0C]) + verify_data

            return server_message == server_message_hash_computed

        except Exception:
            return False

    def encrypt(self, plaintext, seq_num, content_type):
        iv = self.client_write_IV + os.urandom(8)

        # Encrypts the plaintext
        plaintext_size = len(plaintext)
        counter = Counter.new(nbits=32, prefix=iv, initial_value=2, allow_wraparound=False)
        cipher = AES.new(self.client_write_key, AES.MODE_CTR, counter=counter)
        ciphertext = cipher.encrypt(plaintext)

        # Compute the Authentication Tag
        auth_data = nb_to_n_bytes(seq_num, 8) + nb_to_n_bytes(content_type, 1) + bytes([0x3, 0x3]) + nb_to_n_bytes(plaintext_size, 2)
        auth_tag = ghash(self.H_client, auth_data, ciphertext)
        auth_tag ^= bytes2int(AES.new(self.client_write_key, AES.MODE_ECB).encrypt(iv + b'\x00' * 3 + b'\x01'))
        auth_tag = nb_to_bytes(auth_tag)

        return iv[4:] + ciphertext + auth_tag
   
    def decrypt(self, ciphertext, seq_num, content_type, debug=False):
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
              
    def send_http_get(self):
        plaintext = 'GET / HTTP/1.1\r\nHOST: ' + self.server_host + '\r\n\r\n'
        self.send(plaintext.encode())
        return self.recv(4096)
    def send(self, text: bytes, content_type=TLS_APPLICATION_DATA):
        ciphertext = self.encrypt(text, seq_num=self.sequence_number, content_type=content_type)
        self.sock.sendall(create_tls_record(ciphertext, content_type))

        self.sequence_number += 1
        return ciphertext

    def receive(self):
        data = []
        app_data = b''
        plaintext_downloaded = 0

        bytes_expected = 0
        bytes_received = 0
        need_to_download_more = True
        content_length = None

        idx = 0

        while bytes_received < bytes_expected or need_to_download_more:
            msg = self.sock.recv(65536)
            app_data += msg
            bytes_received += len(msg)

            while idx < bytes_received:
                size = bytes2int(app_data[idx + 3:idx + 5])

                bytes_expected += size + 5
                while bytes_received < bytes_expected:
                    msg = self.sock.recv(65536)
                    app_data += msg
                    bytes_received += len(msg)

                # Decrypt
                plaintext = bytes_to_str(self.decrypt(app_data[idx+5:idx+5+size], seq_num=self.server_sequence_number, content_type=TLS_APPLICATION_DATA))
                self.server_sequence_number += 1

                if content_length is None:
                    length_start_idx = plaintext.find('Content-Length:')
                    start = plaintext.find('\r\n\r\n')

                    if length_start_idx < 0:
                        try:
                            start += 4
                            end = plaintext.find('\r\n', start)
                            size_hex = plaintext[start:end]

                            if len(size_hex) % 2 == 1:
                                size_hex = '0' + size_hex

                            content_length = bytes2int(hex_to_bytes(size_hex))
                            start = end

                        except Exception:
                            return plaintext

                    else:
                        length_start_idx += 15
                        length_end_idx = plaintext.find('\r\n', length_start_idx)
                        content_length = int(plaintext[length_start_idx:length_end_idx])

                data.append(plaintext)
                plaintext_downloaded += len(plaintext)

                if plaintext_downloaded >= content_length:
                    need_to_download_more = False

                idx += size + 5

        return ''.join(data)

    def recv(self, size: int):
        headers = self.sock.recv(5)

        content_type = bytes2int(headers[0:1])
        version = bytes2int(headers[1:3])

        content_length = bytes2int(headers[3:])

        data = self.sock.recv(content_length)
        while len(data) < content_length:
            data += self.sock.recv(content_length - len(data))

        text = self.decrypt(data, self.server_sequence_number, TLS_APPLICATION_DATA)
        self.server_sequence_number += 1

        return text
