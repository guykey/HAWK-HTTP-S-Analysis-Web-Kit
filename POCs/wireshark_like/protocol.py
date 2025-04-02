TCP_ = 6

IP_SCHEMA = {"version": 4,
             "IHL": 4,
             "TOS": 8,
             "Length": 16,
             "ID": 16,
             "Flags": 3,
             "Fragment Offset": 13,
             "TTL": 8,
             "Protocol": 8,
             "Checksum": 16,
             "Source IP": 32,
             "Destination IP": 32}
TCP_SCHEMA = {
    'Source Port': 16,
    'Destination Port': 16,
    'Sequence Number': 32,
    'Acknowledgment Number': 32,
    'Header length': 4,
    'Reserved': 3,
    'Flags': 9,
    'Window Size': 16,
    'Checksum': 16,
    'Urgent Pointer': 16
}
UDP_SCHEMA = {
    'Source Port': 16,
    'Destination Port': 16,
    'Length': 16,
    'Checksum': 16
}


class Protocol:
    def __init__(self, raw_data):
        self.schema = dict()
        self.content = dict()

        self.raw_data = ''.join(f'{byte:08b}' for byte in raw_data)
        self.hex = ' '.join(f'{byte:02x}' for byte in raw_data)
        self.stream = raw_data

    def parse(self):
        if self.get_length() * 8 != len(self.raw_data):
            print("Problem parsing")

        i = 0
        for key, val in list(self.schema.items()):
            self.content[key] = int(self.raw_data[i:i + val], 2)
            i += val

    def edit(self, header, val):
        if header not in list(self.content.keys()):
            raise RuntimeError(f"No header named {header}")

        self.content[header] = val

    def get_stream(self):
        binary_string = ''
        for header, val in list(self.content.items()):
            bits = self.schema[header]
            # Format value as binary and pad with leading zeros
            binary_string += f'{val:0{bits}b}'

        byte_array = bytearray()
        for i in range(0, len(binary_string), 8):
            byte = binary_string[i:i + 8]
            byte_array.append(int(byte, 2))

        return bytes(byte_array)

    def get_headers(self):
        return list(self.schema.keys())

    def get_header(self, header):
        return self.content[header]

    def print_whole(self):
        for header, val in list(self.content.items()):
            print(f"{header}: {val}")

    def get_hex(self):
        return self.hex

    def get_original_stream(self):
        return self.stream

    @staticmethod
    def get_length():
        return 0


class IP(Protocol):
    def __init__(self, raw_data):
        super().__init__(raw_data)

        self.schema = IP_SCHEMA

        self.parse()

    def parse(self):
        if self.get_length() * 8 != len(self.raw_data):
            print("Problem parsing")

        i = 0
        for header, val in list(self.schema.items()):
            if "IP" in header:
                self.content[header] = str(int(self.raw_data[i:i + 8], 2))
                i += 8
                for j in range(3):
                    self.content[header] += "." + str(int(self.raw_data[i:i + 8], 2))
                    i += 8
            else:
                self.content[header] = int(self.raw_data[i:i + val], 2)
                i += val

    def get_stream(self):
        binary_string = ''
        for header, val in list(self.content.items()):
            if type(val) == str:
                values = val.split(".")
                for i in values:
                    binary_string += f'{int(i):0{8}b}'

            else:
                bits = self.schema[header]
                # Format value as binary and pad with leading zeros
                binary_string += f'{val:0{bits}b}'

        byte_array = bytearray()
        for i in range(0, len(binary_string), 8):
            byte = binary_string[i:i + 8]
            byte_array.append(int(byte, 2))

        return bytes(byte_array)

    @staticmethod
    def get_length():
        return sum(list(IP_SCHEMA.values())) // 8


class TCP(Protocol):
    def __init__(self, raw_data):
        super().__init__(raw_data)

        self.schema = TCP_SCHEMA
        self.parse()

    @staticmethod
    def get_length():
        return sum(list(TCP_SCHEMA.values())) // 8


class UDP(Protocol):
    def __init__(self, raw_data):
        super().__init__(raw_data)

        self.schema = UDP_SCHEMA
        self.parse()

    @staticmethod
    def get_length():
        return sum(list(UDP_SCHEMA.values())) // 8


class Packet:
    def __init__(self, raw_data):
        self.tcp = False
        i = 0
        self.ip = IP(raw_data[:IP.get_length()])
        i += IP.get_length()

        if self.ip.get_header("Protocol") == TCP_:
            self.tcp = True
            self.transport = TCP(raw_data[i:i + TCP.get_length()])
            i += TCP.get_length()
        else:
            self.transport = UDP(raw_data[i:i + UDP.get_length()])
            i += UDP.get_length()

        try:
            self.app = Protocol(raw_data[i:])

        except Exception:
            #  print("No application")
            self.app = None
            pass

    def is_tcp(self):
        return self.tcp

    def print_packet(self):
        print('*' * 5 + " IP " + '*' * 5)
        self.ip.print_whole()

        if self.tcp:
            print('*' * 5 + " TCP " + '*' * 5)
        else:
            print('*' * 5 + " UDP " + '*' * 5)

        self.transport.print_whole()

        if self.app:
            print('*' * 5 + " Application " + '*' * 5)
            print(self.app.get_original_stream())

        print()
        print()

    def get_stream(self):
        to_send = self.ip.get_stream() + self.transport.get_stream()

        if self.app:
            return to_send + self.app.get_original_stream()

        return to_send
