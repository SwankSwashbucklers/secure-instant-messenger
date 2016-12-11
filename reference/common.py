from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from os import urandom
from threading import Thread
from socket import socket, AF_INET, SOCK_DGRAM
from functools import reduce, update_wrapper
from enum import Enum





### Exceptions #################################################################

# class FcryptError(Exception):
#     """Base class for script exceptions"""
#     def __init__(self, msg):
#         self.msg = "\nException in script {}:\n\n{}".format(argv[0], msg)
#
#     def __str__(self):
#         return self.msg
#
#
# class ArgParseError(FcryptError):
#     """An error from trying to parse commandline arguments"""
#     def __str__(self):
#         return "{}\ncall {} with flag -h for more info".format(
#             self.msg, argv[0])



### Helpers ####################################################################

class cached_property():
    """ A property that is only computed once per instance and then replaces
        itself with an ordinary attribute. Deleting the attribute resets the
        property. """

    def __init__(self, func):
        update_wrapper(self, func)
        self.func = func

    def __get__(self, obj, cls):
        if obj is None: return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value

def get_public_key(filename):
    with open(filename, 'rb') as public_key_file:
        return serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

def get_private_key(filename):
    with open(filename, 'rb') as private_key_file:
        return serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )

def encrypt(public_key, data):
    """ Returns a symmetrical encryption of the padded input data, with the
        initialization vector and the symmetric key (after being asymmetrically
        encrypted) appended. """

    # generate symmetric key and iv
    symmetric_key = urandom(32)
    iv = urandom(16)

    # pad data
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # symmetrically encrypt data
    encryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # asymmetrically encrypt the key
    encrypted_key = public_key.encrypt(symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # return concatenated message
    return encrypted_key + iv + encrypted_data


def decrypt(private_key, data):
    """ Decrypts ciphertext that contains an asymmetrically encrypted
        symmetric key, an iv, and symmetrically encrypted data. """

    # break up message
    encrypted_key = data[:256]
    iv = data[256:272]
    encrypted_data = data[272:]

    # decrypt symmetric key
    session_key = private_key.decrypt(encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # decrypt message
    decryptor = Cipher(
        algorithms.AES(session_key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # unpad message
    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(padded_data) + unpadder.finalize()

    return unpadded_data


def sign(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signatue(public_key, signature, data):
    """ Function that verifies the signature of the input ciphertext.
        Throws an InvalidSignature if verification fails. """
    public_key.verify(signature, data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def hash_items(*args):
    """ Returns a hash of the provided arguments """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for item in args:
        digest.update(item)
    return digest.finalize()

def hashn(item, n):
    return reduce(lambda x, _: hash_items(x), range(n), item) # TODO: test this

def verify_message(message, verify, handle):
    pass


### Constants ##################################################################

class ServerConfiguration():
    Address = ('127.0.0.1', 8082)
    Resources = Enum('ServerResources', 'LIST CRL')
    Methods = Enum('ServerMethods', 'AUTHENTICATE RESOURCE LOGOUT')
    Public_Key = get_public_key('server_public_key') # TODO: generate this when the server starts up and then put it in a file or something?

class Constants():
    GREETING = 'IWANTTOTALK'
    IFS = b'<break>'



### Classes ####################################################################

class Connection_Helper():
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


class Connection_Handler():

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
            self.open_connections[address].init_connection(data)

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
            if not message == I_WANT_TO_TALK:
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
        self.handle_message(message, address) # TODO: check this
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
