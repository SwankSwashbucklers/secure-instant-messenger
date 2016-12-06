# TODO: add exceptions where ever things dont look like they should,
#       maybe return feedback from the server?


# TODO: you can cache the server's cookie (maybe)

# TODO: nice handling of ctrl-c + messages 'press ctrl-c to quit'

# TODO: config file with addresses and ports?

# from common import Connection_Handler, Connection_Helper, decrypt, encrypt, hash_items, sign
# from common import get_public_key, get_private_key
# from common import NonceVerificationError, ResourceNotFoundError
# from common.Constants import GREETING, IFS
# from common.ServerConfiguration import Address as SERVER_ADDRESS
# from common.ServerConfiguration import Resources as SERVER_RESOURCES
# from common.ServerConfiguration import Methods as SERVER_METHODS
# from common.ServerConfiguration import Public_Key as SERVER_PUBKEY

from common import ConnectionHelper, ConnectionHandler
from common.config import *
from common.crypto import *
from common.exceptions import *

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PrivateFormat, PublicFormat, Encoding

import sqlite3 as sqlite
from os import urandom
from time import time


# helpers
def get_data_for_user(username):
    # fetch from the db
    with sqlite.connect('resources/users.db') as con:
        cur = con.cursor()
        try:
            result_set = cur.execute('SELECT * FROM USERS WHERE NAME == ?', [username])
        except sqlite.Error as e:
            print(e)
        else:
            user = result_set.fetchone()
            if user is None: # there should be a user
                return # TODO throw error
            if result_set.fetchone() is None: # there should only be one user
                print('USER', user)
                uid, _, phash, n, _ = user
                return uid, phash, n
            return 1 # TODO: throw error

def update_user(uid, passwd_hash, n):
    with sqlite.connect('resources/users.db') as con:
        cur = con.cursor()
        try:
            cur.execute('''
                UPDATE USERS SET
                    PASSWD_HASH = ?, N = ?, LAST_LOGIN = ?
                WHERE USERS.ID == ?''',
                [ passwd_hash, n, int(time()), uid ]
            )
        except sqlite.Error as e:
            print(e)

class ServerHelper(ConnectionHelper):

    def __init__(self, client_address, server, client_name, client_pubkey, nonce):
        super().__init__(client_address, server)
        self.client_name = client_name
        self.client_pubkey = client_pubkey
        self.initial_action(nonce)

    def decrypt_message(self, ciphertext):
        return decrypt(self.owner.prikey, ciphertext).split(IFS)

    def send(self, *args):
        """ Encrypts and sends a message """
        message = IFS.join(args)
        ciphertext = encrypt(self.client_pubkey, message)
        super().send(ciphertext)


class AuthenicationHelper(ServerHelper):

    def initial_action(self, nonce):
        self.nonce = urandom(32)
        self.user_data = get_data_for_user(self.client_name)
        _, _, n = self.user_data
        self.send(nonce, encode(n), self.nonce)

    def handle_response(self, response):
        try:
            passwd_hash, nonce = self.decrypt_message(response)
        except ValueError:
            return self.finish(False)
        if not nonce == self.nonce:
            return self.finish(False)
        uid, phash, n = self.user_data
        if not hash_items(passwd_hash) == phash:
            return self.finish(False)
        update_user(uid, passwd_hash, n-1) # replace db with passwd_hash and n-1
        self.finish(True)

    def finish(self, success):
        if success:
            certificate = self.owner.generate_certificate(
                self.client_name, self.address, self.client_pubkey
            )
            client_list = self.owner.get_client_list()
            self.send(certificate, client_list)
            print('\n\n\nCLIENT LIST', client_list)
            self.owner.client_list[self.address] = (self.client_name, self.client_pubkey)
        super().finish()


class ResourceRequestHelper(ServerHelper):

    def initial_action(self, nonce):
        self.nonce = urandom(32)
        self.send(nonce, self.nonce)

    def handle_response(self, response):
        try:
            nonce, resource = self.decrypt_message(response)
            resource = SERVER_RESOURCES(decode_int(resource))
            if not nonce == self.nonce:
                raise NonceVerificationError()
            if not resource in SERVER_RESOURCES:
                raise ResourceNotFoundError()
        except (ValueError, NonceVerificationError, ResourceNotFoundError):
            self.finish(False) # break off connection
        else:
            fetched_resource = None
            if resource == SERVER_RESOURCES.LIST:
                fetched_resource = self.owner.get_client_list()
            elif resource == SERVER_RESOURCES.CRL:
                fetched_resource = self.owner.get_CRL()
            print('RESOURCE LIST', fetched_resource)
            self.send(fetched_resource)

    def finish(self, success):
        super().finish()




class ChatServer(ConnectionHandler):

    ADDRESS = SERVER_ADDRESS

    def __init__(self):
        super().__init__(self.ADDRESS)
        self.client_list = {} # address: (name, pubkey)

        # certificate stuff

        # public and private keys
        self.pubkey = get_public_key('resources/server_public_key')
        self.prikey = get_private_key('resources/server_private_key')

    def decrypt_message(self, message):
        return decrypt(self.prikey, message).split(IFS)

    def init_connection(self, message, address):
        items = self.decrypt_message(message)
        if len(items) == 3: # Authentication
            name, pubkey, nonce = items
            name = str(name, 'utf-8')
            pubkey = load_pem_public_key(pubkey, backend=default_backend())
            args = (AuthenicationHelper, self, name, pubkey, nonce)
            super().add_connection(address, *args)
        elif len(items) == 2: # Fetch Resource
            nonce, name = items
            name = str(name, 'utf-8')
            try:
                _, pubkey = self.client_list[address]
            except KeyError:
                pass # TODO: throw error?
            else:
                args = (ResourceRequestHelper, self, name, pubkey, nonce)
                super().add_connection(address, *args)
        elif len(items) == 1:
            pass # TODO: logout here
        else:
            pass # TODO: you got issues throw an exception or something

    def generate_certificate(self, username, address, pubkey):
        message = IFS.join([
            urandom(16),
            username.encode('utf-8'),
            str(address).encode('utf-8'),
            pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
            int(time() + 20*60).to_bytes(4, byteorder='big')
        ])
        signature = sign(self.prikey, message)
        return IFS.join([signature, message])

    def get_CRL(self):
        return ""

    def get_client_list(self):
        # TODO: maybe skip the requesting user?
        client_list = []
        for key, value in self.client_list.items():
            (host, port), (name,_) = key, value
            client_list.append(','.join([name, host, str(port)]).encode('utf-8'))
        return IFS.join(client_list)


def main():
    ChatServer()


if __name__ == '__main__':
    main()
