"""
    docstring
"""

# from common import Connection_Handler, Connection_Helper, decrypt, encrypt, hashn
# from common import get_public_key, get_private_key
# from common import NonceVerificationError, ResourceNotFoundError
# from common.Constants import GREETING, IFS
# from common.ServerConfiguration import Address as SERVER_ADDRESS
# from common.ServerConfiguration import Resources as SERVER_RESOURCES
# from common.ServerConfiguration import Methods as SERVER_METHODS
# from common.ServerConfiguration import Public_Key as SERVER_PUBKEY

from os import urandom
from threading import Thread
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

from common import ConnectionHelper, ConnectionHandler
from common.config import *
from common.crypto import *
from common.exceptions import *



#import cryptography.hazmat.primitives.serialization as serialization
#from serialization import PublicFormat.SubjectPublicKeyInfo as SubjectPublicKeyInfo
#from serialization import Encoding.PEM as PEM, PrivateFormat
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat





class ClientConnectionHelper(ConnectionHelper):
    def __init__(self, address, owner, username):
        super().__init__(address, owner)
        self.nonce = urandom(32)
        self.username = username.encode('utf-8')
        self.decrypt_message = owner.decrypt_message
        self.inital_action()

    def inital_action(self):
        self.send(GREETING.encode('utf-8'))


class AuthenticationHelper(ClientConnectionHelper):
    def __init__(self, address, owner, username, password, pubkey):
        self.password = password.encode('utf-8')
        self.pubkey = pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        super().__init__(address, owner, username)

    def handle_response(self, response):
        if self.state == 0:
            cookie = response
            ciphertext = encrypt(SERVER_PUBKEY,
                IFS.join([ self.username, self.pubkey, self.nonce ])
            )
            self.send(IFS.join([cookie, ciphertext]))
            self.state += 1

        elif self.state == 1:
            n1, n, n2 = self.decrypt_message(response)
            if not n1 == self.nonce:
                raise NonceVerificationError()
            n = int.from_bytes(n, byteorder='big')
            ciphertext = encrypt(SERVER_PUBKEY,
                IFS.join([ hashn(self.password, n-1), n2 ])
            )
            self.send(ciphertext)
            self.state += 1

        elif self.state == 2:
            resp = self.decrypt_message(response)
            certificate = IFS.join(resp[:6])
            active_users = resp[6:]
            self.finish(True, certificate, active_users)

    def finish(self, success, certificate=None, active_users=[]):
        if success:
            self.owner.certificate = certificate
            self.owner.set_active_users(active_users)
        super().finish()

class ResourceRequestHelper(ClientConnectionHelper):
    def __init__(self, address, owner, username, resource):
        self.resource = resource
        super().__init__(address, owner, username)

    def handle_response(self, response):
        if self.state == 0:
            cookie = response
            ciphertext = encrypt(SERVER_PUBKEY,
                IFS.join([ self.nonce, self.username ])
            )
            self.send(IFS.join([cookie, ciphertext]))
            self.state += 1

        elif self.state == 1:
            n1, n2 = self.decrypt_message(response)
            if not n1 == self.nonce:
                raise NonceVerificationError()
            ciphertext = encrypt(SERVER_PUBKEY,
                IFS.join([ n2, encode(self.resource.value) ])
            )
            self.send(ciphertext)
            self.state += 1

        elif self.state == 2:
            resp = self.decrypt_message(response)
            self.finish(True, resp)

    def finish(self, success, resource=None):
        if success:
            if self.resource == SERVER_RESOURCES.LIST:
                self.owner.set_active_users(resource)
            if self.resource == SERVER_RESOURCES.CRL:
                self.owner.CRL = resource
        super().finish()

#class ChatConnectionHelper():

class ChatClient(ConnectionHandler):

    def __init__(self, address, username, password):
        super().__init__(address)
        self.active_users = {} # name: address
        self.certificate = None
        self.CRL = None

        self.username = username
        self.password = password

        # public and private keys
        self.pubkey = get_public_key('resources/client_public_key')
        self.prikey = get_private_key('resources/client_private_key')

        # start authentication
        self.authenticate()

    # def init_connection(self, address, connection):
    #     super().add_connection(address, connection, self)

    def authenticate(self):
        super().add_connection(SERVER_ADDRESS, AuthenticationHelper, self, self.username, self.password, self.pubkey)

    def request_list(self):
        super().add_connection(SERVER_ADDRESS, ResourceRequestHelper, self, self.username, SERVER_RESOURCES.LIST)

    def set_active_users(self, users_list):
        if not users_list or not users_list[0]:
            self.active_users = {}
            return
        users_arr = [ str(x, 'utf-8').split(',') for x in users_list ]
        self.active_users = { n: (h, int(p)) for n,h,p in users_arr }
        print(self.active_users)

    def request_CRL(self):
        super().add_connection(SERVER_ADDRESS, Resource_Request_Helper, self, self.username, 'CRL')

    def decrypt_message(self, message):
        return decrypt(self.prikey, message).split(IFS)

### Command Line Interface #####################################################

def parse_args():
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__ )
    parser.add_argument('-ip', '--host',
        type=str,
        default='127.0.0.1',
        help='the ip address to run the client on.')
    parser.add_argument('-p', '--port',
        type=int,
        default=8080,
        help='the port to run the client on.')
    args = parser.parse_args()
    return args


### Main #######################################################################

def main():
    options = parse_args()
    username = input('Enter Username: ')
    password = input('Enter Password: ')
    client = ChatClient((options.host, options.port), username, password)
    input('press enter to get list')
    client.request_list()
    print(client.certificate, '\n\nACTIVE\n', client.active_users)



if __name__ == '__main__':
    main()
