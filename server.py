
import time
import sys
from os import urandom
from random import random
from signal import signal, SIGINT
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

from common import ConnectionHandler
from common.config import *
from common.crypto import *
from common.db import *
from common.exceptions import *


### Connection Delegates #######################################################
class ConnectionHelper():
    def __init__(self, address, owner, client_name, client_pubkey, nonce):
        self.address = address
        self.owner = owner
        self.client_name = client_name
        self.client_pubkey = client_pubkey
        self.nonce = urandom(32)
        self.initial_action(nonce)

    def decrypt_message(self, ciphertext):
        return decrypt(self.owner.prikey, ciphertext).split(IFS)

    def send(self, *args):
        """ Encrypts and sends a message """
        message = IFS.join(args)
        ciphertext = encrypt(self.client_pubkey, message)
        self.owner.send(ciphertext, self.address)


class AuthenticationHelper(ConnectionHelper):
    def initial_action(self, nonce):
        try:
            *_, self.passwd_hash, n, _ = fetch_user_record(self.client_name)
        except (UsernameVerificationError, DatabaseError) as e:
            self.owner.handle_exception(e, self.address)
            self.owner.remove_connection(self.address)
        else:
            self.send(nonce, self.nonce, encode(n))

    def handle_response(self, response, status):
        try:
            nonce, passwd_hash = self.decrypt_message(response)
            if not nonce == self.nonce:
                raise NonceVerificationError()
            if not hash_items(passwd_hash) == self.passwd_hash:
                raise PasswordVerificationError()
            # update db with new password hash
            update_user_record(self.client_name, passwd_hash)
        except Exception as e:
            self.owner.handle_exception(e, self.address)
        else:
            # generate resources and send them to the client
            self.send(
                self.owner.add_user(
                    self.client_name,
                    self.address,
                    self.client_pubkey
                ),
                self.owner.get_client_list(),
                self.owner.get_CRL()
            )
        finally:
            # finally, remove the open connection
            self.owner.remove_connection(self.address)


class ResourceRequestHelper(ConnectionHelper):
    def initial_action(self, nonce):
        self.send(nonce, self.nonce)

    def handle_response(self, response, status):
        try:
            nonce, resource = self.decrypt_message(response)
            resource = SERVER_RESOURCES(decode(resource, int))
            if not nonce == self.nonce:
                raise NonceVerificationError()
            if not resource in SERVER_RESOURCES:
                raise ResourceNotFoundError()
        except (ValueError, NonceVerificationError, ResourceNotFoundError) as e:
            self.owner.handle_exception(e, self.address)
        else:
            fetched_resource = None
            user = (self.client_name, self.address)
            if resource is SERVER_RESOURCES.LIST:
                fetched_resource = self.owner.get_client_list()
                print('-> User: "{}" at: {} requested client list.'.format(*user))
            elif resource is SERVER_RESOURCES.CRL:
                fetched_resource = self.owner.get_CRL()
                print('-> User: "{}" at: {} requested CRL.'.format(*user))
            self.send(fetched_resource)
        finally:
            self.owner.remove_connection(self.address)


### Connection Handler #########################################################
class ChatServer(ConnectionHandler):
    def __init__(self, address):
        super().__init__(address)
        self.client_list = {} # address: (name, pubkey, cert_id, cert_expiration)
        self.CRL = {} # certificate_id: certificate_expiration
        # random starting id for certificates
        self.certificate_id = int(random()*10000)
        # public and private keys
        self.pubkey = get_public_key('resources/server_public_key')
        self.prikey = get_private_key('resources/server_private_key')

    def init_connection(self, message, address):
        try:
            m, *items = decrypt(self.prikey, message).split(IFS)
            method = SERVER_METHODS(decode(m, int))
            if method is SERVER_METHODS.AUTHENTICATE:
                name, nonce, pubkey = items
                name = decode(name, str)
                if name in [v[0] for k, v in self.client_list.items()]:
                    raise AlreadyLoggedInError()
                pubkey = decode(pubkey, RSAPublicKey)
                connection_helper_inst = AuthenticationHelper(
                    address, self, name, pubkey, nonce
                )
                super().add_connection(address, connection_helper_inst)
            elif method is SERVER_METHODS.RESOURCE:
                name, nonce = items
                name = decode(name, str)
                self.is_authorized(name, address)
                try:
                    _, pubkey, *_ = self.client_list[address]
                except KeyError:
                    raise UserNotFoundError()
                else:
                    connection_helper_inst = ResourceRequestHelper(
                        address, self, name, pubkey, nonce
                    )
                    super().add_connection(address, connection_helper_inst)
            elif method is SERVER_METHODS.LOGOUT:
                name, *signature = items
                name = decode(name, str)
                self.is_authorized(name, address)
                try:
                    _, pubkey, *_ = self.client_list[address]
                    verify_signature(pubkey, *signature)
                    _, message = signature
                    if not decode(message, str) == FAREWELL:
                        raise InvalidSignatureError()
                except KeyError:
                    raise UserNotFoundError()
                else:
                    self.remove_user(address)
                    self.send(encode("Logout successful."), address)
            else:
                raise MethodNotFoundError()
        except Exception as e:
            self.handle_exception(e, address)

    def handle_exception(self, e, address):
        err_msg = ""
        if type(e) is UserNotFoundError:
            err_msg = "You are not authorized."
        elif type(e) is MethodNotFoundError:
            err_msg = "The requested server method was not found."
        elif type(e) is ResourceNotFoundError:
            err_msg = "The resource requested was not found."
        elif type(e) is ValueError:
            err_msg = "Message improperly formatted, please try again."
        elif type(e) is NonceVerificationError:
            err_msg = "Incorrect nonce value provided."
        elif type(e) is PasswordVerificationError:
            err_msg = "Incorrect password provided."
        elif type(e) is UsernameVerificationError:
            err_msg = "An improper username was provided.  Please try again."
        elif type(e) is InvalidSignatureError:
            err_msg = "Invalid signature provided."
        elif type(e) is CertificateExpirationError:
            err_msg = "Your certificate has expired, please login again."
        elif type(e) is AlreadyLoggedInError:
            err_msg = "User is already logged in."
        elif type(e) is DatabaseError:
            err_msg = "There was a database error.  Please try again."
        else:
            print('Unknown error:', e)
            err_msg = "An unknown error occurred.  Please try again."
        self.send(encode(err_msg), address, MESSAGE_STATUSES.ERROR)

    def is_authorized(self, user, address):
        try:
            name, *_, expiration = self.client_list[address]
            if expiration < int(time.time()):
                self.remove_user(address)
                raise CertificateExpirationError()
            if not user == name:
                raise UsernameVerificationError()
        except KeyError:
            raise UserNotFoundError()

    def get_CRL(self):
        """ Clean out any expired certificates and return CRL """
        self.CRL = {k:v for k,v in self.CRL.items() if v < int(time.time())}
        return encode(','.join(str(k) for k in self.CRL.keys()))

    def get_client_list(self):
        clients = [(v[0], k[0], str(k[1])) for k, v in self.client_list.items()]
        return encode(';'.join(','.join([*x]) for x in clients))

    def add_user(self, username, address, public_key):
        """ Creates a certificate, and adds user to list of active users """
        cert_id = self.certificate_id
        expiration = int(time.time() + 30*60) # 30 minutes from now
        cert_info = [cert_id, username, *address, public_key, expiration]
        message = IFS.join(encode(x) for x in cert_info)
        certificate = IFS.join([sign(self.prikey, message), message])
        self.certificate_id += 1
        self.client_list[address] = (username, public_key, cert_id, expiration)
        print('-> User: "{}" at: {} logged in.'.format(username, address))
        return certificate

    def remove_user(self, address):
        try:
            name, _, cert_id, expiration = self.client_list.pop(address)
            print('-> User: "{}" at: {} logged out.'.format(name, address))
            if expiration > int(time.time()):
                self.CRL[cert_id] = expiration
        except KeyError:
            raise UserNotFoundError()


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
        default=8082,
        help='the port to run the client on.')
    return parser.parse_args()

def signal_handler(signal, frame):
    print("\nScript terminated by user...")
    print("Attempting graceful shutdown...")
    sys.exit(0)


### Main #######################################################################
def main():
    options = parse_args()
    signal(SIGINT, signal_handler)
    address = (options.host, options.port)
    try:
        initialize_db()
    except DatabaseError:
        print('Error initializing database.\n')
        sys.exit(1)
    chat_server = ChatServer(address)
    print('Instant messaging authentication server running at:', address)
    print('Press Ctrl-C to quit...', '\n')
    while True:
        time.sleep(0.01)


if __name__ == '__main__':
    main()
