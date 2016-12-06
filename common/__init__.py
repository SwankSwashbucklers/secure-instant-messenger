"""
    Common base classes for the instant messaging system
"""

from os import urandom
from threading import Thread
from socket import socket, AF_INET, SOCK_DGRAM

from common.config import GREETING, IFS
from common.crypto import hash_items

__all__ = ['config', 'crypto', 'exceptions', 'ConnectionHandler', 'ConnectionHelper']


class ConnectionHelper():
    def __init__(self, address, owner):
        self.state = 0
        self.address = address
        self.owner = owner

    def initial_action(self):
        pass

    def handle_response(self, response):
        pass

    def send(self, message):
        self.owner.send(message, self.address)

    def finish(self):
        self.owner.remove_connection(self.address)


class ConnectionHandler():
    def __init__(self, address):
        self.address = address
        self.secret = urandom(32) # secret for stateless cookies
        self.open_connections = {}

        # initialize socket & start listening
        self._socket = socket(AF_INET, SOCK_DGRAM)
        self._socket.bind(self.address)
        self.listening_thread = Thread(target=self.listen)
        self.listening_thread.start()

    def send(self, message, address):
        self._socket.sendto(message, address)

    def listen(self):
        while True:
            data, address = self._socket.recvfrom(4096)
            self.parse_incomming_data(data, address)

    def parse_incomming_data(self, data, address):
        # route to proper handler if there is already an open connection
        if address in self.open_connections.keys():
            self.open_connections[address].handle_response(data)

        # otherwise check and see if they are requesting or returning a cookie
        elif not self.returned_cookie(data, address) and \
             not self.wants_cookie(data, address):
            pass # TODO: send to subclass's parser

    def wants_cookie(self, data, address):
        try:
            message = str(data, 'utf-8')
        except UnicodeDecodeError:
            return False
        else:
            if not message == GREETING:
                return False
            self.send(self.generate_cookie(address), address)
            print('COOKIE LENGTH', len(self.generate_cookie(address)))
            return True

    def returned_cookie(self, data, address):
        items = data.split(IFS)
        if not len(items) == 2:
            #print('COOKIE WAS FALSE')
            return False
        c, message = items
        if not c == self.generate_cookie(address):
            #print('COOKIE WAS FALSE')
            return False
        self.init_connection(message, address) # TODO: check this
        return True

    def generate_cookie(self, address):
        args = [str(x).encode('utf-8') for x in [address, self.secret]]
        return hash_items(*args)

    def add_connection(self, address, handler, *args):
        self.open_connections[address] = handler(address, *args)

    def remove_connection(self, address):
        try:
            self.open_connections.pop(address)
        except KeyError as e:
            pass # TODO: what?
