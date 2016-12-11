"""
    docstring
"""

from os import urandom

import time # TODO; get rid of

from common import ConnectionHandler
from common.config import *
from common.crypto import *
from common.exceptions import *

from cryptography.exceptions import InvalidSignature

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from signal import signal, SIGINT
from sys import exit


### Globals ####################################################################
CHAT_CLIENT = None


### Connection Delegates #######################################################
class ConnectionHelper():
    def __init__(self, address, callback, owner, username, *steps):
        self.state = 0
        self.address = address
        self.callback = callback
        self.owner = owner
        self.nonce = urandom(32)
        self.username = username
        self.pipeline = [*steps]
        self.send(GREETING)

    def send(self, message):
        # print('FOOBAR SENDING', message, "TO", self.address)
        self.owner.send(encode(message), self.address)


    def encrypt_message(self, *args):
        return encrypt(SERVER_PUBKEY, IFS.join(encode(x) for x in args))

    def decrypt_message(self, message):
        return decrypt(self.owner.prikey, message).split(IFS)

    def handle_response(self, response, status):
        if status is MESSAGE_STATUSES.ERROR:
            print(self.address, 'sent the following error:', decode(response, str))
            return self.finish(False)
        try:
            message = self.pipeline[self.state](response, status)
            if message is None:
                return
            if self.state == 0:
                cookie = response
                message = IFS.join([cookie, message])
            self.send(message)
            self.state += 1
        except Exception as e:
            self.finish(False)

    def finish(self, success, *args):
        self.owner.remove_connection(self.address)
        if callable(self.callback):
            self.callback(success, *args)


class AuthenticationHelper(ConnectionHelper):
    def __init__(self, password, pubkey, *args):
        self.password = password
        self.pubkey = pubkey
        super().__init__(*args, self.step0, self.step1, self.step2)

    def step0(self, response, status):
        return self.encrypt_message(
            SERVER_METHODS.AUTHENTICATE.value,
            self.username,
            self.nonce,
            self.pubkey
        )

    def step1(self, response, status):
        n1, n2, n = self.decrypt_message(response)
        if not n1 == self.nonce:
            raise NonceVerificationError()
        passwd_hash = hashn(encode(self.password), decode(n, int)-1)
        return self.encrypt_message(n2, passwd_hash)

    def step2(self, response, status):
        *certificate, active_users, CRL = self.decrypt_message(response)
        self.finish(True, IFS.join([*certificate]), active_users, CRL)


class ResourceRequestHelper(ConnectionHelper):
    def __init__(self, resource, *args):
        self.resource = resource
        super().__init__(*args, self.step0, self.step1, self.step2)

    def step0(self, response, status):
        return self.encrypt_message(
            SERVER_METHODS.RESOURCE.value,
            self.username,
            self.nonce
        )

    def step1(self, response, status):
        n1, n2 = self.decrypt_message(response)
        if not n1 == self.nonce:
            raise NonceVerificationError()
        return self.encrypt_message(n2, self.resource.value)

    def step2(self, response, status):
        resource, = self.decrypt_message(response)
        self.finish(True, resource)


class LogoutRequestHelper(ConnectionHelper):
    def __init__(self, *args):
        super().__init__(*args, self.step0, self.step1)

    def step0(self, response, status):
        return self.encrypt_message(
            SERVER_METHODS.LOGOUT.value,
            self.username,
            sign(self.owner.prikey, FAREWELL),
            FAREWELL
        )

    def step1(self, response, status):
        if status is MESSAGE_STATUSES.OK:
            self.finish(True)
            return
        self.finish(False)


class ChatInitHelper(ConnectionHelper):
    def __init__(self, private_key, certificate, *args):
        self.dh_public_key, self.dh_private_key = generate_dsa_keys()
        self.private_key = private_key
        self.certificate = certificate
        super().__init__(*args, self.step0, self.step1, self.step2)

    def step0(self, response, status):
        print('REQUESTING COMMUNICATION!!!')
        return encode(self.dh_public_key)

    def step1(self, response, status):
        peer_public_key, n1 = response.split(IFS)
        self.peer_public_key = decode(peer_public_key, DSAPublicKey)
        self.shared_key = self.dh_private_key.exchange(peer_public_key)
        signed_msg = IFS.join([encode(self.dh_public_key), n1])
        signature = sign(self.private_key, signed_msg)
        return dh_encrypt(self.shared_key,
            IFS.join([
                encode(self.username),
                self.certificate,
                signature,
                signed_msg,
                self.nonce
            ])
        )

    def step2(self, response, status):
        data = dh_decrypt(self.shared_key, response).split(IFS)
        name, cert_sig, *certificate, sig, peer_public_key, nonce = data
        name = decode(name, str)
        # verify nonce
        if not nonce == self.nonce:
            raise NonceVerificationError()
        # verify certificate
        verify_signature(SERVER_PUBKEY, cert_sig, IFS.join(certificate))
        cid, cname, host, port, pubkey, expiration = certificate
        cid, expiration = decode(cid, int), decode(expiration, int)
        if expiration < int(time.time()) or cid in self.owner.CRL:
            raise CertificateExpirationError()
        cname = decode(cname, str)
        address = (decode(host, str), decode(port, int))
        if not name == cname or not address == self.address:
            raise UsernameVerificationError()
        # verify signed message
        pubkey = decode(pubkey, RSAPublicKey)
        signed_msg = IFS.join([peer_public_key, nonce])
        verify_signature(pubkey, sig, signed_msg)
        peer_public_key = decode(peer_public_key, DSAPublicKey)
        if not peer_public_key == self.peer_public_key:
            raise InvalidSignature
        # everything checks out, set up the persistant connection
        self.finish(True, name, self.address, self.shared_key)


class ChatAuthenticationHelper():
    def __init__(self, address, owner, username, prikey, cert, peer_public_key):
        self.address = address
        self.owner = owner
        self.username = username
        self.private_key = prikey
        self.certificate = cert
        self.peer_public_key = peer_public_key
        self.dh_public_key, self.dh_private_key = generate_dsa_keys()
        self.shared_key = self.dh_private_key.exchange(peer_public_key)
        self.nonce = urandom(32)
        self.initial_action()

    def initial_action(self):
        message = IFS.join([encode(self.dh_public_key), self.nonce])
        self.owner.send(message)

    def handle_response(self, response, status):
        if status is MESSAGE_STATUSES.ERROR:
            print(self.address, 'sent the following error:', decode(response, str))
            return self.finish(False)
        try:
            data = dh_decrypt(self.shared_key, response).split(IFS)
            name, cert_sig, *certificate, sig, peer_public_key, n1, n2 = data
            name = decode(name, str)
            # verify nonce
            if not n1 == self.nonce:
                raise NonceVerificationError()
            # verify certificate
            verify_signature(SERVER_PUBKEY, cert_sig, IFS.join(certificate))
            cid, cname, host, port, pubkey, expiration = certificate
            cid, expiration = decode(cid, int), decode(expiration, int)
            if expiration < int(time.time()) or cid in self.owner.CRL:
                raise CertificateExpirationError()
            cname = decode(cname, str)
            address = (decode(host, str), decode(port, int))
            if not name == cname or not address == self.address:
                raise UsernameVerificationError()
            # verify signed message
            pubkey = decode(pubkey, RSAPublicKey)
            signed_msg = IFS.join([peer_public_key, n1])
            verify_signature(pubkey, sig, signed_msg)
            peer_public_key = decode(peer_public_key, DSAPublicKey)
            if not peer_public_key == self.peer_public_key:
                raise InvalidSignature
        except Exception as e:
            self.finish(False)
        else:
            # everything checks out
            signed_msg = IFS.join([encode(self.dh_public_key), n2])
            signature = sign(self.private_key, signed_msg)
            encrypted_message = dh_encrypt(self.shared_key,
                IFS.join([
                    encode(self.username),
                    self.certificate,
                    signature,
                    signed_msg
                ])
            )
            self.owner.send(encrypted_message)
            self.finish(True, self.username, self.owner, self.shared_key)

    def finish(self, success, *args):
        self.owner.remove_connection(self.address)
        if not success:
            return
        helper_inst = ChatMessagingHelper(self.address, *args)
        self.owner.add_connection(self.address, helper_inst)


class ChatMessagingHelper():
    def __init__(self, address, interlocutor, owner, session_key):
        self.address = address
        self.interlocutor = interlocutor
        self.owner = owner
        self.session_key = session_key

    def send(self, message):
        data = dh_encrypt(self.session_key, encode(message))
        self.owner.send(data, self.address)
        print('You', '>', interlocutor, ':', message)

    def handle_response(self, response, status):
        message = dh_decrypt(session_key, response)
        message = decode(message, str)
        if message == FAREWELL:
            return self.finish()
        print(interlocutor, '>', 'You', ':', message)

    def finish():
        self.owner.remove_connection(self.address)


class ChatClient(ConnectionHandler):
    def __init__(self, address):
        super().__init__(address)
        self._active_users = {} # name: address
        self._CRL = [] # certificate_id
        self.certificate = None
        self.state = CLIENT_STATE.INITIAL
        self.pubkey, self.prikey = generate_rsa_keys()
        self.authenticate()

    @property
    def active_users(self):
        return self._active_users

    @active_users.setter
    def active_users(self, user_list):
        try:
            user_list = [ x.split(',') for x in decode(user_list, str).split(';') ]
            self._active_users = { n: (h, int(p)) for n,h,p in user_list }
        except Exception:
            pass

    @property
    def CRL(self):
        return self._CRL

    @CRL.setter
    def CRL(self, CRL):
        try:
            self._CRL = [int(x) for x in decode(CRL, str).split(',') if x]
        except Exception:
            pass

    def _conn(self, callback, address, helper_cls, *args):
        connection_helper_inst = helper_cls(*args, address, callback, self, self.username)
        super().add_connection(address, connection_helper_inst)

    def request_authentication(self):
        def callback(success, *args):
            if success:
                self.certificate, self.active_users, self.CRL = args
                self.state = CLIENT_STATE.AUTHENTICATED
                print('\nLogin Successful!\n')
                self.update()
                return
            self.state = CLIENT_STATE.UNATHENTICATED
            self.authenticate()
        self._conn(callback, SERVER_ADDRESS, AuthenticationHelper, self.password, self.pubkey)

    def request_list(self):
        def callback(success, *args):
            if success:
                self.active_users, = args
                users_str = ', '.join(
                    x for x in self.active_users.keys() if not x == self.username
                )
                print('\nActive users are:', users_str)
            self.update()
        self._conn(callback, SERVER_ADDRESS, ResourceRequestHelper, SERVER_RESOURCES.LIST)

    def request_CRL(self):
        def callback(success, *args):
            if success:
                self.CRL, = args
            self.update()
        self._conn(callback, SERVER_ADDRESS, ResourceRequestHelper, SERVER_RESOURCES.CRL)

    def request_logout(self):
        def callback(success, *args):
            if not success:
                print('Logout attempt was unsuccessful.\n')
                self.update()
                return
            print('\nYou have been successfully logged out.\n')
            if self.state is CLIENT_STATE.SHUTDOWN:
                self.shutdown()
                return
            self.state = CLIENT_STATE.INITIAL
            self.authenticate()
        self._conn(callback, SERVER_ADDRESS, LogoutRequestHelper)

    def request_communication(self, username, address, initial_message):
        def callback(success, *args):
            if not success:
                print('\nUnable to start a conversation with', username, '\n')
                return
            print('\nStarting conversation with', username, '\n')
            _, _, shared_key = args
            self.send(initial_message, address) # send initial message
            print('You', '>', username, ':', initial_message)
            helper_inst = ChatMessagingHelper(address, username, self, shared_key)
            self.add_connection(address, helper_inst)
        # make sure your CRL is up to date before you initialize the helper
        #self.request_CRL() TODO
        self._conn(callback, address, ChatInitHelper, self.prikey, self.certificate)

    def init_connection(self, message, address):
        try:
            peer_public_key = decode(message, DSAPublicKey)
            # make sure your CRL is up to date before you initialize the helper
            #self.request_CRL() TODO
            helper_inst = ChatAuthenticationHelper(address, self,
                self.username, self.prikey, self.certificate, peer_public_key)
            self.owner.add_connection(self.address, helper_inst)
        except Exception as e:
            print(e)
            self.send(b'Error building session.', address, MESSAGE_STATUSES.ERROR)

    def authenticate(self):
        if self.state is CLIENT_STATE.AUTHENTICATED:
            print('You are already logged in.')
            return self.update()
        if self.state is CLIENT_STATE.UNATHENTICATED:
            print('\nLogin failed.  Please try again.\n')
        self.username = input('Enter Username: ')
        self.password = input('Enter Password: ')
        self.request_authentication()

    def update(self):
        # print()
        # print('CERTIFICATE', self.certificate)
        # print()
        # print('LIST', self.active_users)
        # print()
        # print('CRL', self.CRL)
        # print()
        command = input('>>>  ')
        method, *args = command.split(' ')
        if method == 'list' and not args:
            return self.request_list()
        if method == 'crl' and not args:
            return self.request_CRL()
        if method == 'send':
            user, *rest = args
            if user == self.username:
                print('\nError: You cannot send a message to yourself')
                return self.update()
            if not user in self.active_users.keys():
                print('\nError: The requested user is not online.')
                return self.update()
            message = ' '.join(rest)
            address = self.active_users[user]
            print("ADDRESS", address, type(address))
            print("ADDRESS0", address[0], type(address[0]))
            print("ADDRESS1", address[1], type(address[1]))
            if address in self.open_connections.keys():
                return self.open_connections[address].send(message)
            return self.request_communication(user, address, message)
        if method == 'logout' and not args:
            return self.request_logout()
        if method == 'exit' and not args:
            return self.exit()
        print('Invalid command.')
        self.update()

    def exit(self):
        if self.state is CLIENT_STATE.AUTHENTICATED:
            self.state = CLIENT_STATE.SHUTDOWN
            self.request_logout()
            return
        super().shutdown()



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
    return parser.parse_args()

def signal_handler(signal, frame):
    print("\nScript terminated by user...")
    print("Attempting graceful shutdown...")
    if not CHAT_CLIENT is None:
        CHAT_CLIENT.shutdown()
    exit(0)


### Main #######################################################################
def main():
    options = parse_args()
    signal(SIGINT, signal_handler)
    CHAT_CLIENT = ChatClient((options.host, options.port))



if __name__ == '__main__':
    main()
