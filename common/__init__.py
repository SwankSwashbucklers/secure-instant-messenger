"""
    Common base classes for the instant messaging system
"""

import sys
from os import urandom
from threading import Thread
import _thread
from socket import socket, AF_INET, SOCK_DGRAM

from common.config import *
from common.crypto import *
from common.exceptions import *

__all__ = ['config', 'crypto', 'exceptions', 'db', 'ConnectionHandler']


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

    def send(self, message, address, status=MESSAGE_STATUSES.OK):
        if not address == SERVER_ADDRESS:
            print('FOOBAR SENDING', message, "TO", address)
        message = encode(status.value) + message
        self._socket.sendto(message, address)

    def listen(self):
        while True:
            #try:
            data, address = self._socket.recvfrom(4096)
            if not address == SERVER_ADDRESS:
                print('\n\nMessage recieved', data, 'From', address)
            self.parse_incomming_data(data, address)
            # except Exception as e:
            #     print("THE SOCKET ERROR:", e)
            #     break

    def parse_incomming_data(self, data, address):
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

    def wants_cookie(self, data, address):
        try:
            message = str(data, 'utf-8')
        except UnicodeDecodeError:
            return False
        else:
            if not message == GREETING:
                return False
            print("Sent Cookie")
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
        #print("Connection added")
        self.open_connections[address] = connection_helper_inst

    def remove_connection(self, address):
        """ Attempts to remove an open connection, if no connection is found
            then it does nothing. """
        try:
            self.open_connections.pop(address)
            #print("Connection removed")
        except KeyError as e:
            pass

    def shutdown(self):
        print("Shutting down server at:", self.address)
        try: # wait for listening thread to close
            self._socket.close() # close socket
            #self.listening_thread.join()
        except Exception as e:
            print("Exception shutting down server", e)
        else:
            print("Server successfully shutdown")
        finally:
            sys.exit(0)
