from os import urandom
from functools import reduce

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

__all__ = ['get_public_key', 'get_private_key', 'encrypt', 'decrypt', 'sign', 'verify_signatue', 'hash_items', 'hashn', 'verify_message', 'encode', 'decode_string', 'decode_int']


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


#### HELPERS ###################################################################
# TODO: Maybe move these to their own helpers file
def encode(item):
    if type(item) is str:
        return item.encode('utf-8')
    if type(item) is int:
        return item.to_bytes(4, byteorder='big')

def decode_string(item):
    return str(item, 'utf-8')

def decode_int(item):
    return int.from_bytes(item, byteorder='big')
