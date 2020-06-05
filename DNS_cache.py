import socket
import argparse
import sys
import struct
import datetime
import copy


def is_correct_IP(hostname):
    ip_parts = hostname.strip().split('.')
    if len(ip_parts) != 4:
        return False
    for part in ip_parts:
        try:
            if int(part) < 0 or int(part) > 255:
                return False
        except ValueError:
            return False
    return True


def convert_to_IP(hostname):
    if is_correct_IP(hostname):
        return hostname
    return socket.gethostbyname(hostname)


def parse_args():
    parser = argparse.ArgumentParser(description='DNS-cache task')
    parser.add_argument('-f', '--forwarder', type=str, help="Опрашиваемый сервер. Примеры: 8.8.8.8:53; 8.8.8.8")
    parser.add_argument('-p', '--port', type=int, default=53, help='прослушиваемый нами порт, стандартное значение 53')
    return parser.parse_args()


def main():
    args = parse_args()
    forwarder_port = 53
    forwarder_parts = args.forwarder.split(':')
    try:
        forwarder_address = convert_to_IP(forwarder_parts[0])
        if len(forwarder_parts) == 2:
            forwarder_port = int(forwarder_parts[1])
        server = DNSServer(forwarder_address, forwarder_port, args.port)
        server.start()
    except Exception as exception:
        print("Некорректный адрес опрашиваемого сервера")
        sys.exit()


class DNSServer:
    def __init__(self, forwarder_address, forwarder_port, listening_port):
        self.cache = DNSCache()
        self.attempts_count = 3
        self.forwarder_port = forwarder_port
        self.listening_port = listening_port
        self.forwarder_address = forwarder_address

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.listening_port))
        try:
            while True:
                try:
                    buffer, sender_address = sock.recvfrom(4096)
                except socket.error as exception:
                    continue
                except KeyboardInterrupt:
                    sys.exit()
                if buffer:
                    if self.attempts_count == 0:
                        print("Сервер недоступен")
                        sys.exit()
                    self.process_request(sender_address, sock, buffer)
        except KeyboardInterrupt:
            sys.exit()

    def _ask_cache(self, request_to_forwarder, parsed_request, sender_address, answer_packet):
        answer_packet.header.qr = 1
        answer_packet.header.ra = 1

        for request in parsed_request.requests:
            answers = self.cache.get_record(request.qtype, request.qname, datetime.datetime.now())
            if answers is not None:
                request_to_forwarder.header.qdcount -= 1
                request_to_forwarder.requests.remove(request)
                for answer in answers:
                    self.print_information(sender_address[0], str(DNSPacket.TYPES[answer.qtype]), answer.get_name(),
                                           "cache")
                    answer_packet.answers.append(answer)
                    answer_packet.header.ancount += 1

    def _ask_forwarder(self, requests_packet_to_forwarder, packet_parser, sender_address, answer_packet, sock):
        sock.sendto(requests_packet_to_forwarder, (self.forwarder_address, self.forwarder_port))
        sock.settimeout(5)
        packet_data = ''.encode('utf-8')
        while True:
            try:
                buffer = sock.recv(4096)
            except socket.timeout:
                print('Сервер не отвечает')
                self.attempts_count -= 1
                break
            if buffer:
                packet_data += buffer
            break
        if len(packet_data) != 0:
            forwarder_answer = packet_parser.parse_packet(packet_data)
            self.cache.set_records_from_packet(forwarder_answer)
            for answer in forwarder_answer.answers:
                self.print_information(sender_address[0], str(DNSPacket.TYPES[answer.qtype]), answer.get_name(),
                                       "forwarder")
                answer_packet.answers.append(answer)
                answer_packet.header.ancount += 1

    def process_request(self, sender_address, sock, buffer):
        packet_parser = DNSPacketParser()
        parsed_request = packet_parser.parse_packet(buffer)
        if parsed_request.header.qr == 1 or parsed_request.header.qdcount == 0:
            return

        request_to_forwarder = copy.deepcopy(parsed_request)
        answer_packet = copy.deepcopy(parsed_request)

        self._ask_cache(request_to_forwarder,parsed_request, sender_address, answer_packet)

        if request_to_forwarder.header.qdcount != 0:
            requests_packet_to_forwarder = packet_parser.get_packet(request_to_forwarder)
            self._ask_forwarder(requests_packet_to_forwarder, packet_parser, sender_address, answer_packet, sock)

        sock.sendto(packet_parser.get_packet(answer_packet), sender_address)

    def print_information(self, sender_address, DNS_packet_type, answer_name, source):
        print(str(sender_address + " ; " + str(DNS_packet_type) +
                  " ; " + answer_name + " from " + source))


class DNSCache:
    def __init__(self):
        self.cache = {}

    def get_record(self, qtype, qname, time):
        pair = (tuple(qname), qtype)
        if pair in self.cache:
            records = self.cache[pair]
            if len(records) == 0:
                return None
            for record in records:
                record.ttl -= (time - record.time).seconds
                if record.ttl <= 0:
                    self.cache.pop(pair)
                    return None
            return records
        return None

    def set_record(self, record, qtype, qname, rewrite):
        pair = (tuple(qname), qtype)
        if pair not in self.cache:
            self.cache[pair] = []
        if rewrite:
            self.cache[pair] = []
        self.cache[pair].append(record)

    def set_records_from_packet(self, packet):
        pairs = []
        for record in packet.answers:
            self._send_to_cache(record, record.qtype, record.qname, pairs)
        for record in packet.additional_record_section:
            self._send_to_cache(record, record.qtype, record.qname, pairs)
        for record in packet.authority_section:
            self._send_to_cache(record, record.qtype, record.qname, pairs)

    def _send_to_cache(self, record, record_type, record_name, pairs):
        pair = (tuple(record.qname), record.qtype)
        self.set_record(record, record_type, record_name, pair not in pairs)
        pairs.append(pair)


class DNSPacketParser:
    def __init__(self):
        self.pointer = 0

    @staticmethod
    def parse_header(header):
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            '>HHHHHH', header)
        flags = bin(flags)[2:].zfill(16)
        qr = int(flags[0], base=2)
        aa = int(flags[5], base=2)
        tc = int(flags[6], base=2)
        rd = int(flags[7], base=2)
        ra = int(flags[8], base=2)
        z = int(flags[9:12], base=2)
        rcode = int(flags[12:], base=2)
        opcode = int(flags[1:5], base=2)
        return DNSHeader(id, qr, opcode, aa, tc, rd, ra, z,
                         rcode, qdcount, ancount, nscount, arcount)

    @staticmethod
    def get_header(dns_header):
        flags = ''
        flags += bin(dns_header.qr)[2:]
        flags += bin(dns_header.opcode)[2:].zfill(4)
        flags += bin(dns_header.aa)[2:]
        flags += bin(dns_header.tc)[2:]
        flags += bin(dns_header.rd)[2:]
        flags += bin(dns_header.ra)[2:]
        flags += bin(dns_header.z)[2:].zfill(3)
        flags += bin(dns_header.rcode)[2:].zfill(4)
        flags = int(flags, base=2)
        return struct.pack('>HHHHHH', dns_header.id, flags,
                           dns_header.qdcount, dns_header.ancount,
                           dns_header.nscount, dns_header.arcount)

    def get_packet(self, dns_packet):
        packet = self.get_header(dns_packet.header)
        for request in dns_packet.requests:
            packet += self.get_request(request)
        for answer in dns_packet.answers:
            packet += self.get_record(answer)
        for record in dns_packet.authority_section:
            packet += self.get_record(record)
        for record in dns_packet.additional_record_section:
            packet += self.get_record(record)
        return packet

    def get_request(self, dns_request):
        return self.get_name(dns_request.qname) + struct.pack(
            '>HH', dns_request.qtype, dns_request.qclass)

    def get_record(self, dns_record):
        return self.get_name(dns_record.qname) + struct.pack(
            '>HHIH', dns_record.qtype, dns_record.qclass,
            dns_record.ttl,
            dns_record.rdlength) + dns_record.rdata

    def get_name(self, name):
        b_name = b''
        for part in name:
            b_part = part.encode('utf-8')
            b_name += struct.pack('>B', len(b_part))
            b_name += b_part
        b_name += struct.pack('>B', 0)
        return b_name

    def parse_packet(self, packet):
        requests = []
        answers = []
        authority_section = []
        additional_record_section = []
        time = datetime.datetime.now()

        header = self.parse_header(packet[:12])
        qdcount = header.qdcount
        ancount = header.ancount
        nscount = header.nscount
        arcount = header.arcount
        self.pointer = 12
        while True:
            if self.pointer == len(packet):
                break
            request_name = self.read_name(packet)
            request_type, request_class = struct.unpack('>HH', packet[self.pointer:(self.pointer + 4)])
            self.pointer += 4

            if qdcount != 0:
                requests.append(DNSRequest(request_name, request_type, request_class))
                qdcount -= 1
                continue
            ttl, record_length = struct.unpack('>IH', packet[self.pointer:(self.pointer + 6)])
            self.pointer += 6
            record_data = packet[self.pointer:(self.pointer + record_length)]
            self.pointer += record_length

            record = DNSRecord(request_name, request_type, request_class, ttl, record_length, record_data, time)
            if ancount != 0:
                answers.append(record)
                ancount -= 1
            elif nscount != 0:
                authority_section.append(record)
                nscount -= 1
            elif arcount != 0:
                additional_record_section.append(record)
                arcount -= 1
            else:
                break
        self.pointer = 0
        return DNSPacket(header, requests, answers, authority_section, additional_record_section)

    def read_name(self, packet):
        name = []
        while True:
            b = bin(struct.unpack('>B', packet[self.pointer:(self.pointer + 1)])[0])[2:].zfill(8)
            self.pointer += 1
            mark = b[:2]
            number = int(b[2:], base=2)
            if mark == '00' and number == 0:
                break
            if mark == '00':
                name.append(packet[self.pointer:(self.pointer + number)].decode('utf-8'))
                self.pointer += number
            elif mark == '11':
                reference = int(b[2:] + bin(struct.unpack('>B', packet[self.pointer:self.pointer + 1])[0])[2:], base=2)
                previous_pointer = self.pointer + 1
                self.pointer = reference
                name += self.read_name(packet)
                self.pointer = previous_pointer
                break
        return name


class DNSPacket:
    TYPES = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
    }

    def __init__(self, header, requests, answers, authority_section, additional_record_section):
        self.header = header
        self.requests = requests
        self.answers = answers
        self.authority_section = authority_section
        self.additional_record_section = additional_record_section


class DNSRequest:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def get_name(self):
        return '.'.join(self.qname)

    def __eq__(self, other):
        return (self.qname == other.qname
                and self.qtype == other.qtype
                and self.qclass == other.qclass)


class DNSHeader:
    def __init__(self, id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount):
        self.z = z
        self.id = id
        self.qr = qr
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = rcode
        self.opcode = opcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def __eq__(self, other):
        return (self.id == other.id
                and self.qr == other.qr
                and self.aa == other.aa
                and self.tc == other.tc
                and self.rd == other.rd
                and self.ra == other.ra
                and self.rcode == other.rcode
                and self.opcode == other.opcode
                and self.qdcount == other.qdcount
                and self.ancount == other.ancount
                and self.nscount == other.nscount
                and self.arcount == other.arcount)


class DNSRecord:
    def __init__(self, qname, qtype, qclass, ttl, rdlength, rdata, time):
        self.ttl = ttl
        self.time = time
        self.qname = qname
        self.qtype = qtype
        self.rdata = rdata
        self.qclass = qclass
        self.rdlength = rdlength

    def get_name(self):
        return '.'.join(self.qname)

    def __eq__(self, other):
        return (self.qname == other.qname
                and self.qtype == other.qtype
                and self.qclass == other.qclass
                and self.rdata == other.rdata)


# запуск с помощью следующей команды
# python DNS_cache.py -f <адрес опрашиваемого сервера>:<порт сервера> -p <порт, который мы сами прослушиваем>
# Пример запуска: python DNS_cache.py -f 8.8.8.8:53 -p 53
main()
