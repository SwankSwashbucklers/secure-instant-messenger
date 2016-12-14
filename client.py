
import os

import time

from common import ConnectionHandler
from common.config import *
from common.crypto import *
from common.exceptions import *

from cryptography.exceptions import InvalidSignature

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from signal import signal, SIGINT
import sys


### Connection Delegates #######################################################
class ConnectionHelper():
    def __init__(self, address, callback, owner, username, *steps):
        self.state = 0
        self.address = address
        self.callback = callback
        self.owner = owner
        self.nonce = os.urandom(32)
        self.username = username
        self.pipeline = [*steps]
        self.send(GREETING)

    def send(self, message):
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
            print(e)
            raise e
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
        self.dh_private_key = generate_dh_private_key()
        self.private_key = private_key
        self.certificate = certificate
        super().__init__(*args, self.step0, self.step1, self.step2)

    def step0(self, response, status):
        return encode(self.dh_private_key.public_key())

    def step1(self, response, status):
        peer_public_key, n1 = response.split(IFS)
        self.peer_public_key = decode(peer_public_key, DHPublicKey)
        # created dh shared key and then hash to 256 bits for use with AES
        self.shared_key = self.dh_private_key.exchange(self.peer_public_key)
        self.shared_key = hash_items(self.shared_key)
        signed_msg = IFS.join([encode(self.dh_private_key.public_key()), n1])
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
        if not peer_public_key == encode(self.peer_public_key):
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
        self.dh_private_key = generate_dh_private_key(public_key=peer_public_key)
        # created dh shared key and then hash to 256 bits for use with AES
        self.shared_key = self.dh_private_key.exchange(peer_public_key)
        self.shared_key = hash_items(self.shared_key)
        self.nonce = os.urandom(32)

    def initial_action(self):
        message = IFS.join([encode(self.dh_private_key.public_key()), self.nonce])
        self.owner.send(message, self.address)

    def handle_response(self, response, status):
        if status is MESSAGE_STATUSES.ERROR:
            print(self.address, 'sent the following error:', decode(response, str))
            return self.finish(False)
        try:
            data = dh_decrypt(self.shared_key, response).split(IFS)
            name, cert_sig, *certificate, sig, peer_public_key, n1, n2 = data
            name = decode(name, str)
            self.name = name
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
            if not peer_public_key == encode(self.peer_public_key):
                raise InvalidSignature
        except Exception as e:
            print(e)
            self.finish(False)
        else:
            # everything checks out
            signed_msg = IFS.join([encode(self.dh_private_key.public_key()), n2])
            signature = sign(self.private_key, signed_msg)
            encrypted_message = dh_encrypt(self.shared_key,
                IFS.join([
                    encode(self.username),
                    self.certificate,
                    signature,
                    signed_msg
                ])
            )
            self.owner.send(encrypted_message, self.address)
            self.finish(True, self.name, self.owner, self.shared_key)

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
        print('You > {}: {}\n>>> '.format(self.interlocutor, message), end="")

    def handle_response(self, response, status):
        message = dh_decrypt(self.session_key, response)
        message = decode(message, str)
        if message == FAREWELL:
            return self.finish()
        print('\n{} > You: {}\n>>> '.format(self.interlocutor, message), end="")

    def finish():
        self.owner.remove_connection(self.address)


### Chat Client ################################################################
class ChatClient(ConnectionHandler):
    def __init__(self, address):
        super().__init__(address)
        self._active_users = {} # name: address
        self._CRL = [] # certificate_id
        self.certificate = None
        self.state = CLIENT_STATE.INITIAL
        self.prikey = generate_rsa_private_key()
        self.pubkey = self.prikey.public_key()
        self.username = None
        self.password = None
        print('Username: ', end="")

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
                print('\nLogin Successful!\n\n>>> ', end="")
                return
            self.state = CLIENT_STATE.UNATHENTICATED
            self.username = None
            self.password = None
            print('\nLogin was unsuccessful, please try again.\n\nUsername: ', end="")
        self._conn(callback, SERVER_ADDRESS, AuthenticationHelper, self.password, self.pubkey)

    def request_list(self, verbose=True):
        def callback(success, *args):
            if success:
                self.active_users, = args
                users_str = ', '.join(
                    x for x in self.active_users.keys() if not x == self.username
                )
                if not verbose:
                    return
                if users_str:
                    print('\nActive users are: {}\n\n>>> '.format(users_str), end="")
                else:
                    print('\nThere are no active users.\n\n>>> ', end="")
            else:
                if not verbose:
                    return
                print('>>> ', end="")
        self._conn(callback, SERVER_ADDRESS, ResourceRequestHelper, SERVER_RESOURCES.LIST)

    def request_CRL(self):
        def callback(success, *args):
            if not success:
                print('\nError retrieving CRL.\n')
            else:
                self.CRL, = args
            self.request_list(verbose=False)
        self._conn(callback, SERVER_ADDRESS, ResourceRequestHelper, SERVER_RESOURCES.CRL)

    def request_logout(self):
        def callback(success, *args):
            if not success:
                print('\nLogout attempt was unsuccessful.\n\n>>> ', end="")
                return
            if self.state is CLIENT_STATE.SHUTDOWN:
                print('\nYou have been successfully logged out.\n')
                os._exit(0)
                return
            self.state = CLIENT_STATE.INITIAL
            self.username = None
            self.password = None
            print('\nYou have been successfully logged out.\n\nUsername: ', end="")
        self._conn(callback, SERVER_ADDRESS, LogoutRequestHelper)

    def request_communication(self, username, address, initial_message):
        def callback(success, *args):
            if not success:
                print('\nUnable to start a conversation with {}\n>>> '.format(username), end="")
                return
            print('\nStarting conversation with', username)
            _, _, shared_key = args
            self.send(dh_encrypt(shared_key, encode(initial_message)), address) # send initial message
            print('You > {}: {}\n>>> '.format(username, initial_message), end="")
            helper_inst = ChatMessagingHelper(address, username, self, shared_key)
            self.add_connection(address, helper_inst)
        # make sure your CRL is up to date before you initialize the helper
        self.request_CRL()
        self._conn(callback, address, ChatInitHelper, self.prikey, self.certificate)

    def init_connection(self, message, address):
        try:
            peer_public_key = decode(message, DHPublicKey)
            # make sure your CRL is up to date before you initialize the helper
            self.request_CRL()
            helper_inst = ChatAuthenticationHelper(address, self,
                self.username, self.prikey, self.certificate, peer_public_key)
            super().add_connection(address, helper_inst)
            helper_inst.initial_action() # initial action after listener has been registered
        except Exception as e:
            print(e)
            self.send(b'Error building session.', address, MESSAGE_STATUSES.ERROR)

    def receive_user_input(self, usr_input):
        if self.state is CLIENT_STATE.INITIAL or self.state is CLIENT_STATE.UNATHENTICATED:
            if self.username is None:
                self.username = usr_input
                print('Password: ', end="")
            elif self.password is None:
                self.password = usr_input
                self.request_authentication()
        if self.state is CLIENT_STATE.AUTHENTICATED:
            method, *args = usr_input.split(' ')
            if method == 'list' and not args:
                return self.request_list()
            if method == 'crl' and not args:
                return self.request_CRL()
            if method == 'send':
                user, *rest = args
                if user == self.username:
                    print('\nError: You cannot send a message to yourself.\n>>> ')
                elif not user in self.active_users.keys():
                    print('\nError: The requested user is not online.\n>>> ')
                else:
                    message = ' '.join(rest)
                    address = self.active_users[user]
                    if address in self.open_connections.keys():
                        return self.open_connections[address].send(message)
                    return self.request_communication(user, address, message)
            if method == 'logout' and not args:
                return self.request_logout()
            if method == 'exit' and not args:
                return self.exit()
            print('Invalid command.')

    def exit(self):
        if self.state is CLIENT_STATE.AUTHENTICATED:
            self.state = CLIENT_STATE.SHUTDOWN
            self.request_logout()
            return
        sys.exit(0)



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

def cleanly_exit():
    print("\nScript terminated by user...")
    print("Attempting graceful shutdown...")
    sys.exit(0)

def signal_handler(signal, frame):
    cleanly_exit()


### Main #######################################################################
def main():
    options = parse_args()
    signal(SIGINT, signal_handler)
    chat_client = ChatClient((options.host, options.port))
    while True:
        try:
            usr_input = input('')
            chat_client.receive_user_input(usr_input)
        except KeyboardInterrupt:
            cleanly_exit()

if __name__ == '__main__':
    main()
