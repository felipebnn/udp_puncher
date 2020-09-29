#!/usr/bin/env python3
import sys
import json
import socket

with open('config.json', 'r') as f:
    config = json.load(f)

PORT = config.get('port', 12345)
SECURITY_KEY = config.get('security_key', False)

class Server:
    def start(self):
        self.rooms = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', PORT))

        print('listening...')
        while True:
            data, addr = self.sock.recvfrom(1024)
            print(addr, data)
            str_data = data.decode()
            print('received', str_data, 'from', addr)

            try:
                self.handle_data(str_data, addr)
            except Exception as e:
                print(e, file=sys.stderr)
    
    def send_data(self, address, **data):
        # print('sending', json.dumps(data).encode(), 'to', address)
        self.sock.sendto(json.dumps(data).encode(), address)
    
    def handle_data(self, str_data, addr):
        data = json.loads(str_data)
        
        if SECURITY_KEY and SECURITY_KEY != data['security_key']:
            self.send_data(addr, error='invalid security key')
            return

        if data['command'] == 'ping':
            self.send_data(addr, command='pong')
            return
        
        if data['command'] == 'open':
            self.handle_open(addr, data)
            return
        
        if data['command'] == 'join':
            self.handle_join(addr, data)
            return
        
        if data['command'] == 'close':
            self.handle_close(addr, data)
            return

    def handle_open(self, addr, data):
        if 'room_name' not in data:
            self.send_data(addr, error='room name not found in packet')
            return

        if 'password' not in data:
            self.send_data(addr, error='password not found in packet')
            return

        if 'public_key' not in data:
            self.send_data(addr, error='public key not found in packet')
            return

        if 'subnet' not in data:
            self.send_data(addr, error='subnet not found in packet')
            return

        #TODO: consider room closed by ping timeout.
        if data['room_name'] in self.rooms and self.rooms[data['room_name']]['password'] != data['password']:
            self.send_data(addr, error='room already in use')
            return

        self.rooms[data['room_name']] = {
            'password': data['password'],
            'host_data': {
                'addr': addr,
                'public_key': data['public_key'],
                'subnet': data['subnet'],
            },
        }

        self.send_data(addr, command='ok')
    
    def handle_join(self, addr, data):
        if 'room_name' not in data:
            self.send_data(addr, error='room name not found in packet')
            return

        if 'password' not in data:
            self.send_data(addr, error='password not found in packet')
            return

        if 'public_key' not in data:
            self.send_data(addr, error='public key not found in packet')
            return

        #TODO: consider room closed by ping timeout.
        if data['room_name'] not in self.rooms:
            self.send_data(addr, error='room non existent')
            return

        room = self.rooms[data['room_name']]

        if room['password'] != data['password']:
            self.send_data(addr, error='wrong password')
            return

        client_data = {
            'addr': addr,
            'public_key': data['public_key'],
            'subnet': room['host_data']['subnet'],
        }

        self.send_data(addr, command='punch', **room['host_data'])
        self.send_data(room['host_data']['addr'], command='punch', **client_data)

        del self.rooms[data['room_name']]
    
    def handle_close(self, addr, data):
        if 'room_name' not in data:
            self.send_data(addr, error='room name not found in packet')
            return
        
        del self.rooms[data['room_name']]


if __name__ == '__main__':
    Server().start()
