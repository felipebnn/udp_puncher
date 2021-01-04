#!/usr/bin/env python3
import socket
import time
import json
import sys
import re
from os import path, getcwd
from random import randint
from threading import Thread
from subprocess import Popen
from contextlib import suppress


class HeartBeatThread(Thread):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def run(self):
        self._running = True
        time.sleep(0.5)

        while self._running:
            self.callback()
            time.sleep(0.5)

    def __enter__(self):
        self.start()

    def __exit__(self, type, value, traceback):
        self._running = False
        self.join()


class Puncher:
    def __init__(self, stun_server_addr, stun_server_port, security_key, user_data, **_):
        self.stun_server_addr = stun_server_addr
        self.stun_server_port = stun_server_port
        self.security_key = security_key
        self.user_data = user_data

    def run(self):
        data = None
        while data is None:
            try:
                data = self.punch_attempt()

                if data is None:
                    time.sleep(1.0)
            except Exception as e:
                print(e, file=sys.stderr)
                time.sleep(1.0)

        return data

    def send_data(self, **data):
        self.sock.sendto(json.dumps(dict(**data, security_key=self.security_key)).encode(), (self.stun_server_addr, self.stun_server_port))

    def recv_data(self):
        bin_data, addr = self.sock.recvfrom(65535)
        return json.loads(bin_data.decode())

    def punch_attempt(self):
        try:
            listen_port = randint(32768, 65535)

            print('LISTEN', listen_port)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(2)
            self.sock.bind(('', listen_port))

            self.send_data(**self.user_data)

            data = self.recv_data()

            if 'error' in data:
                print(data['error'], file=sys.stderr)
                return
            
            if self.user_data['command'] == 'open':
                with HeartBeatThread(lambda: self.send_data(command='ping')):
                    data = self.recv_data()
                    print('---received', data)
                    while 'command' in data and data['command'] != 'punch':
                        data = self.recv_data()
                        print('---received', data)
                    
                    if 'error' in data:
                        print(data['error'], file=sys.stderr)
                        return

            if data['command'] != 'punch':
                print('unexpected error occurred', sys.stderr)
                return

            partner_addr = tuple(data['addr'])
            print('PUNCH sending to', partner_addr)
            for i in range(10):
                print('punch', i+1)
                self.sock.sendto(b'punch', partner_addr)
                time.sleep(0.2)

            print('PUNCH receiving')
            self.sock.settimeout(2)
            addr = None
            print(partner_addr)
            while addr != partner_addr:
                punch_data, addr = self.sock.recvfrom(1024)
                print('--- received', punch_data, 'from', addr)

            print('PUNCH received')

            data['listen_port'] = listen_port
            return data
        except socket.timeout:
            if self.user_data['command'] == 'open':
                self.send_data(command='close')
            raise
        finally:
            self.sock.close()


def get_config_data(config_file_name):
    if not path.isfile(config_file_name + '.json'):
        config = {}
    else:
        with open(config_file_name + '.json', 'r') as f:
            config = json.load(f)

    user_data = config.setdefault('user_data', {})

    if 'stun_server_addr' not in config:
        config['stun_server_addr'] = input("Type in the stun server ip address: ")
    
    if 'stun_server_port' not in config:
        while config.get('stun_server_port') != '' and not config.get('stun_server_port', '').isnumeric():
            config['stun_server_port'] = input("Type in the stun server port (empty for default 12345): ")
        config['stun_server_port'] = int(config['stun_server_port'] or 12345)

    if 'security_key' not in config:
        config['security_key'] = input("Type in the stun server security key: ")

    if 'public_key' not in user_data:
        user_data['public_key'] = input("Type in your public key: ")
    
    if 'private_key' not in config:
        config['private_key'] = input("Type in your private key: ")

    while user_data.get('command') not in { 'open', 'join' }:
        user_data['command'] = input("Type in you room role\n    open - open a room\n    join - join an existing room\n> ").lower()

    if 'room_name' not in user_data:
        user_data['room_name'] = input("Type in your room's name: ")

    if 'password' not in user_data:
        user_data['password'] = input("Type in your room's password: ")

    if 'password' not in user_data:
        user_data['password'] = input("Type in your room's password: ")

    if user_data['command'] == 'open' and 'subnet' not in user_data:
        user_data['subnet'] = input("Type in your room's subnet with an @ as the last byte (empty for default 10.200.0.@/24): ") or '10.200.0.@/24'
    
    if 'wireguard_exe' not in config:
        config['wireguard_exe'] = input("Using wireguard? Type in path for wireguard.exe or leave it blank: ")
    
    with open(config_file_name + '.json', 'w') as f:
        json.dump(config, f, indent=4, sort_keys=True)
    
    return config


def configure_wireguard_file(config_file_name, private_key, user_data, listen_port, addr, public_key, subnet, **_):
    with open(config_file_name + '_wg.conf', 'w') as f:
        f.write('\n'.join([
            '[Interface]',
            f'PrivateKey = {private_key}',
            f'ListenPort = {listen_port}',
            f'Address = {subnet.replace("@", "1" if user_data["command"] == "open" else "2")}',
            '',
            '[Peer]',
            f'PublicKey = {public_key}',
            f'AllowedIPs = {subnet.replace("@", "0")}',
            f'Endpoint = {addr[0]}:{addr[1]}',
            'PersistentKeepalive = 25',
        ]))


def start_wireguard(config_file_name, wireguard_exe):
    Popen([ wireguard_exe, '/installtunnelservice', path.join(getcwd(), config_file_name + '_wg.conf') ])
    try:
        print('VPN has started, press enter to stop it!')
        input()
    finally:
        Popen([ wireguard_exe, '/uninstalltunnelservice', config_file_name + '_wg' ])


if __name__ == '__main__':
    CONFIG_FILE_NAME = sys.argv[1] if len(sys.argv) == 2 else 'config'
    config = get_config_data(CONFIG_FILE_NAME)

    try:
        puncher = Puncher(**config)
        data = puncher.run()

        if config['wireguard_exe']:
            configure_wireguard_file(CONFIG_FILE_NAME, config['private_key'], config['user_data'], **data)
            start_wireguard(CONFIG_FILE_NAME, config['wireguard_exe'])
    except KeyboardInterrupt:
        sys.exit(-1)
    