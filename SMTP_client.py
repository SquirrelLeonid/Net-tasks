import os
import ssl
import sys
import socket
import base64
import imghdr
import argparse


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


def convert_to_ip(hostname):
    if is_ip_correct(hostname):
        return hostname
    return socket.gethostbyname(hostname)


def parse_args():
    parser = argparse.ArgumentParser(description='SMTP client')
    parser.add_argument('-s', '--server', type=str, required=True, help="IP адрес или имя сервера")
    parser.add_argument('-f', '--fr', type=str, default='<>', help="От кого")

    parser.add_argument('-d', '--directory', type=str, default=os.getcwd(), help="Путь к директории с изображениями")
    parser.add_argument('-c', '--config', type=str, required=True, help="Имя файла с конфигурацией")
    parser.add_argument('-m', '--message', type=str, required=True, help="Имя файла с текстом сообщения")

    return parser.parse_args()


def check_input(args):
    if not (os.path.exists(args.directory)):
        print("указанный путь не существует")
        sys.exit(1)
    if not os.path.isdir(args.directory):
        print(str(args.directory) + " не является директорией")
        sys.exit(1)
    if not os.path.exists(args.directory + "\\" + args.config):
        print(str(args.config) + " не существует")
        sys.exit(1)
    if not os.path.exists(args.directory + "\\" + args.message):
        print(str(args.message) + " не существует")
        sys.exit(1)


def get_config_info(args):
    address_list = []
    attachment_list = []
    with open(args.directory + "\\" + args.config, "r", encoding="utf-8") as configFile:
        line = configFile.readline()
        while line != "\n":
            address_list.append(line[0:-1])
            line = configFile.readline()

        line = configFile.readline()
        subject = line[0:-1]
        configFile.readline()
        line = configFile.readline()

        while line:
            if line[-1] == "\n":
                line = line[0:-1]
            attachment_list.append(line)
            line = configFile.readline()

    return [subject, address_list, attachment_list]


def main():
    args = parse_args()
    check_input(args)

    config_content = get_config_info(args)
    subject = config_content[0]
    address_list = config_content[1]
    attachment_list = config_content[2]

    server_ip = args.server
    try:
        address = server_ip.split(':')
        server_ip = address[0]
        server_port = int(address[1])
    except Exception:
        server_port = 25
    try:
        server_ip = convert_to_ip(server_ip)
    except Exception:
        print("Некорректное имя или адрес сервера")
        return
    print(server_ip)
    print(server_port)

    attachment_sender = AttachmentSender(server_ip, server_port, address_list,
                                         args.fr, subject, attachment_list, args.directory)
    attachment_sender.send_attachments()


class AttachmentSender:
    def __init__(self, server, port, address_list, address_from, subject, attachment_list,
                 directory):
        self.port = port
        self.server = server
        self.subject = subject
        self.directory = directory
        self.address_list = address_list
        self.address_from = address_from
        self.attachment_list = attachment_list

    def create_sock(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.server, self.port))
        try:
            sock = ssl.wrap_socket(sock)
        except ssl.SSLError:
            print('Порт не использует ssl')
            sys.exit()
        sock.settimeout(5)
        try:
            hello = sock.recv(1024)
            sock.settimeout(None)
        except socket.error:
            print('Сервер не отвечает')
            sys.exit()
        print('S: ' + hello.decode())
        return sock

    def _send_to_all(self, sock):
        self.send(sock, 'MAIL FROM: {}'.format(self.address_from))
        for address in self.address_list:
            print(address)
            self.send(sock, 'RCPT TO: {}'.format(address))
        self.send(sock, 'DATA')
        self.send(sock, self.get_message(address) + '\r\n.\r\n', is_message=True)

    def _authorization(self, sock):
        self.send(sock, 'EHLO attachment_sender')
        self.send(sock, 'AUTH LOGIN')
        print('Введите логин:')
        login = input()
        self.send(sock, base64.b64encode(login.encode()).decode())
        print('Введите пароль:')
        password = input()
        self.send(sock, base64.b64encode(password.encode()).decode(), is_password=True)

    def send_attachments(self):
        sock = self.create_sock()
        self._authorization(sock)
        self._send_to_all(sock)

    def check_response(self, response):
        if response[0] == '5':
            print('что-то пошло не так')
            sys.exit()

    def get_message(self, address):
        temp_boundary = 'someBoundary'
        message = 'From: <{}>\r\n' \
                  'To: <{}>\r\n' \
                  'Subject: =?utf-8?B?{}?=\r\n' \
                  'Content-Type: multipart/mixed; boundary={}\r\n\r\n'.format(self.address_from, address,
                                                                              base64.b64encode(
                                                                                  self.subject.encode()).decode(),
                                                                              temp_boundary)

        for name in os.listdir(self.directory):
            if name not in self.attachment_list:
                continue
            full_name = os.path.join(self.directory, name)
            if not os.path.isfile(full_name):
                continue
            with open(full_name, 'rb') as file:
                if imghdr.what(full_name) == 'jpeg' or imghdr.what(full_name) == 'png' or imghdr.what(
                        full_name) == 'jpg':
                    message += '--{}\r\n' \
                               'Content-Type: image/{};\r\n' \
                               'Content-Disposition: attachment; filename={}\r\n' \
                               'Content-Transfer-Encoding: base64\r\n\r\n' \
                               '{}\r\n'.format(temp_boundary, imghdr.what(full_name), "\"" + name + "\"",
                                               base64.b64encode(file.read()).decode())
                elif name.endswith(".txt"):
                    message += '--{}\r\n' \
                               'Content-Type: text/plain; charset=utf-8\r\n' \
                               'Content-Disposition: attachment; filename={}\r\n' \
                               'Content-Transfer-Encoding: base64\r\n\r\n' \
                               '{}\r\n'.format(temp_boundary, name,
                                               base64.b64encode(file.read()).decode())
        message += '--{}--'.format(temp_boundary)
        return message

    def send(self, sock, request, is_message=False, is_password=False):
        sock.sendall(bytes(request + '\r\n', 'utf-8'))
        response = sock.recv(1024).decode()
        if is_message:
            request = '*какое-то сообщение*'
        if is_password:
            request = '*' * len(request)
        print('C: ' + request)
        print('S: ' + response + '\r\n')
        self.check_response(response)


# Чтобы запустить программу используйте следующую команду
# python SMTP_client.py -s <адрес сервера:465> -f <адрес отправителя> -d <путь к директории с нужными файлами>
# -c <имя файла конфигурации> -m <имя файла с сообщением>
main()
