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

CONFIG_FILE_NAME = sys.argv[1] if len(sys.argv) == 2 else 'config'

with open(CONFIG_FILE_NAME + '.json', 'r') as f:
    config = json.load(f)

STUN_SERVER = config['stun_server']
STUN_UDP_PORT = config.get('stun_udp_port', 12345)
SECURITY_KEY = config['security_key']
PRIVATE_KEY = config['private_key']
USER_DATA = config['user_data']
USE_WIREGUARD = config.get('use_wireguard', False)
UPDATE_CONFIG_FILE = config.get('update_config_file', False)
WIREGUARD_EXE = config.get('wireguard_exe')

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


class Puncher:
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

        self.configure_wireguard_file(data)
        self.start_wireguard()

    def send_data(self, **data):
        self.sock.sendto(json.dumps(dict(**data, security_key=SECURITY_KEY)).encode(), (STUN_SERVER, STUN_UDP_PORT))

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

            self.send_data(**USER_DATA)

            data = self.recv_data()

            if 'error' in data:
                print(data['error'], file=sys.stderr)
                return
            
            if USER_DATA['command'] == 'open':
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
            if USER_DATA['command'] == 'open':
                self.send_data(command='close')
            raise
        finally:
            self.sock.close()
    
    def configure_wireguard_file(self, data):
        listen_port = data['listen_port']
        addr = data['addr']
        public_key = data['public_key']
        subnet = data['subnet']

        with open(CONFIG_FILE_NAME + '_wg.conf', 'w') as f:
            f.write('\n'.join([
                '[Interface]',
                f'PrivateKey = {PRIVATE_KEY}',
                f'ListenPort = {listen_port}',
                f'Address = {subnet.replace("@", "1" if USER_DATA["command"] == "open" else "2")}',
                '',
                '[Peer]',
                f'PublicKey = {public_key}',
                f'AllowedIPs = {subnet.replace("@", "0")}',
                f'Endpoint = {addr[0]}:{addr[1]}',
                'PersistentKeepalive = 25',
            ]))
    
    def start_wireguard(self):
        Popen([ WIREGUARD_EXE, '/installtunnelservice', path.join(getcwd(), CONFIG_FILE_NAME + '_wg.conf') ])
        try:
            print('VPN has started, press enter to stop it!')
            input()
        finally:
            Popen([ WIREGUARD_EXE, '/uninstalltunnelservice', CONFIG_FILE_NAME + '_wg' ])


if __name__ == '__main__':
    Puncher().run()
