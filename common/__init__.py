"""
    Common base classes for the instant messaging system
"""

import sys
import time
from os import urandom
from threading import Thread
from socket import socket, AF_INET, SOCK_DGRAM
from socket import timeout as SocketTimeout
from queue import Queue

from common.config import *
from common.crypto import *
from common.exceptions import *

__all__ = ['config', 'crypto', 'exceptions', 'db', 'ConnectionHandler']


### Globals ####################################################################
_OUTGOING_QUEUE = Queue()
_INCOMING_QUEUE = Queue()

class SocketThread(Thread):
    def __init__(self, address):
        Thread.__init__(self)
        self.address = address
        self._socket = socket(AF_INET, SOCK_DGRAM)
        self._socket.bind(self.address)
        self._socket.settimeout(0.01)

    def run(self):
        while True:
            try:
                data, address = self._socket.recvfrom(4096)
            except (BlockingIOError, SocketTimeout):
                while not _OUTGOING_QUEUE.empty():
                    outgoing_msg = _OUTGOING_QUEUE.get()
                    self._socket.sendto(*outgoing_msg)
            else:
                _INCOMING_QUEUE.put((data, address))

class ConnectionHandler():
    def __init__(self, address):
        self.address = address
        self.secret = urandom(32) # secret for stateless cookies
        self.open_connections = {}
        listening_thread = SocketThread(address)
        listening_thread.daemon = True
        listening_thread.start()
        parsing_thread = Thread(target=self.parse_incomming_data, daemon=True)
        parsing_thread.start()

    def send(self, message, address, status=MESSAGE_STATUSES.OK):
        _OUTGOING_QUEUE.put((encode(status.value) + message, address))

    def parse_incomming_data(self):
        while True:
            data, address = _INCOMING_QUEUE.get()
            # check status of message
            status = MESSAGE_STATUSES(decode(data[:4], int))
            data = data[4:]
            # route to proper handler if there is already an open connection
            if address in self.open_connections.keys():
                self.open_connections[address].handle_response(data, status)
            # otherwise check and see if they are requesting or returning a cookie
            elif not status is MESSAGE_STATUSES.ERROR and \
                 not self.returned_cookie(data, address) and \
                 not self.wants_cookie(data, address):
                pass
            # let the CPU sleep a little
            time.sleep(0.01)

    def wants_cookie(self, data, address):
        try:
            message = str(data, 'utf-8')
        except UnicodeDecodeError:
            return False
        else:
            if not message == GREETING:
                return False
            self.send(self.generate_cookie(address), address)
            return True

    def returned_cookie(self, data, address):
        items = data.split(IFS)
        if not len(items) == 2:
            return False
        c, message = items
        if not c == self.generate_cookie(address):
            return False
        self.init_connection(message, address)
        return True

    def generate_cookie(self, address):
        args = [encode(str(x)) for x in [address, self.secret]]
        return hash_items(*args)

    def add_connection(self, address, connection_helper_inst):
        self.open_connections[address] = connection_helper_inst

    def remove_connection(self, address):
        """ Attempts to remove an open connection, if no connection is found
            then it does nothing. """
        try:
            self.open_connections.pop(address)
        except KeyError as e:
            pass
