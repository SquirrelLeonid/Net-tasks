import socket
import subprocess
import sys
import select
import re

def is_ip_correct(hostname):
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


def is_ip_private(ip):
    if not is_ip_correct(ip):
        return False
    ip_parts = ip.strip().split('.')
    if ip_parts[0] == '10':
        return True
    if ip_parts[0] == '100' and 64 <= int(ip_parts[1]) <= 127:
        return True
    if ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:
        return True
    if ip_parts[0] == '192' and ip_parts[1] == '168':
        return True
    return False


def convert_to_ip(hostname):
    if is_ip_correct(hostname):
        return hostname
    return socket.gethostbyname(hostname)


class TracertAS:
    RIRS = ['whois.arin.net', 'whois.apnic.net', 'whois.ripe.net', 'whois.afrinic.net','whois.lacnic.net']

    def __init__(self, destination_server):
        self.destination_server = destination_server
        try:
            self.destination_ip = convert_to_ip(destination_server)
            print("route to: " + self.destination_ip)
        except socket.gaierror:
            print(self.destination_server + " is invalid")
            sys.exit()

    def print_local_IP(self, number, ip):
        msg = "№" + str(number) + " " + str(ip) + " local" + "\r\n"
        print(msg)

    def print_white_IP(self, number, ip, netname, country, autonomous_system_number):
        msg = "№" + str(number) + " " + str(ip) + " | "
        details = []
        if netname is not None:
            msg += netname + " | "
        if country is not None:
            msg += country + " | "
        if autonomous_system_number is not None:
            msg += autonomous_system_number
        msg += ' | '.join(details) + "\r\n"
        print(msg)

    def start(self):
        number = 0
        list_ip = self.get_trace()
        self.show_trace(list_ip)

        for address in list_ip:
            number += 1
            if is_ip_private(address):
                self.print_local_IP(number, address)
                continue
            netname, country, autonomous_system_number = self.get_information(address)
            self.print_white_IP(number, address, netname, country, autonomous_system_number)

    def get_trace(self):
        tracert_result = subprocess.check_output("tracert -d 8.8.8.8").decode("cp866")
        result_split = tracert_result.split()
        list_ip = []
        for element in result_split:
            if element == "*":
                break
            if re.search("(\d{1,3}.){3}\d{1,3}", element) and element not in list_ip:
                list_ip.append(element)
        return list_ip[1:]

    def show_trace(self, list_ip):
        print("Tracert found next IP addresses before * * *")
        for ip in list_ip:
            print(ip)
        print("\r\n")

    def get_information(self, ip):
        is_RIR_visited = {}
        for RIR in self.RIRS:
            is_RIR_visited[RIR] = False
        server = self.RIRS[0]
        netname = None
        country = None
        autonomous_system_number = None
        while True:
            is_RIR_visited[server] = True
            answer = self.ask_server(ip, server)
            curr_netname, curr_country, current_autonomous_system_number, next_server = self.parse_RIR_answer(server, answer)
            if curr_netname or netname:
                netname = curr_netname or netname
            if curr_country or country:
                country = curr_country or country
            if current_autonomous_system_number or autonomous_system_number:
                autonomous_system_number = current_autonomous_system_number or autonomous_system_number
            if netname and country and autonomous_system_number:
                break
            server = None
            if next_server and not is_RIR_visited[next_server]:
                server = next_server
                continue
            for RIR in is_RIR_visited:
                if not is_RIR_visited[RIR]:
                    server = RIR
                    break
            if server is None:
                break
        return netname, country, autonomous_system_number

    def parse_RIR_answer(self, server, answer):
        if 'IPv4 address block not managed by the RIPE NCC' in answer:
            return None, None, None, None
        spl_answer = answer.split('\n')
        netname = None
        country = None
        autonomous_system_number = None
        next_server = None
        for line in spl_answer:
            lower_line = line.lower()
            if lower_line.startswith('netname'):
                netname = line.split(' ')[-1]
            elif lower_line.startswith('country'):
                country = line.split(' ')[-1]
        if autonomous_system_number is None:
            result = re.search('AS\d*?\n', answer)
            if result:
                autonomous_system_number = result.group(0)[2:-1]
        for RIR in self.RIRS:
            if RIR != server and RIR in answer:
                next_server = RIR
        return netname, country, autonomous_system_number, next_server

    def ask_server(self, ip, server, timeout=10000):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if server == 'whois.arin.net':
            packet = 'n + {}\r\n'.format(ip)
        else:
            packet = '{}\r\n'.format(ip)
        sock.connect((server, 43))
        sock.sendall(packet.encode('utf-8'))
        ready_for_reading, _, _ = select.select([sock], [], [], timeout)

        if not ready_for_reading:
            return None, None
        packet_data = ''.encode('utf-8')
        while True:
            try:
                buf = sock.recv(4096)
            except socket.error:
                break
            if buf:
                packet_data += buf
            else:
                break
        result = packet_data.decode('utf-8')
        return result


def main():
    destination_server = sys.argv[1]
    tr = TracertAS(destination_server)
    tr.start()


"""Launch program from a terminal via next command
    python Tracert.py <IP-address or domain name>"""
main()
