"""
    Crypto helpers for the instant messaging system.
"""

from os import urandom
from functools import reduce

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA1
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = [
    'RSAPublicKey', 'RSAPrivateKey', 'DHPublicKey',
    'generate_dh_private_key', 'generate_rsa_private_key',
    'get_public_key', 'get_private_key', # TODO: rename
    'encrypt', 'decrypt', 'dh_encrypt', 'dh_decrypt',
    'sign', 'verify_signature', 'hash_items', 'hashn', 'encode', 'decode']

RSAPublicKey = rsa.RSAPublicKeyWithSerialization
RSAPrivateKey = rsa.RSAPrivateKeyWithSerialization
DHPublicKey = dh.DHPublicKeyWithSerialization

# TODO: put this on a non-blocking thread
#_DHParameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
_p = 29063660661155555259647933408585674439769775463904200444024501214745222026861742245950220550894621194809398247675397137873609330268575282750355082242611727399276533556015264296962860790366972239712347554039917135615843998116603458102312563845196757522625291355808229364120828523603111320521621645811894916544136735486963151182366755820888408558234089664807524147613486288505806797920088012539347872413333061747860336277528917811025552313614501001144935454316899965434454599299929213612672100108984554206631563212601872712283123985614744259085590051838620640784280905642885326022351805783687571499638572345410041634539
_g = 2
_DHParameters = dh.DHParameterNumbers(_p, _g).parameters(backend=default_backend())

_DH_IFS = b'<break-dh-key>'
_MSG_IFS = b'<break-msg-el>'

def generate_rsa_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def generate_dh_private_key(public_key=None):
    parameters = _DHParameters if public_key is None else public_key.parameters()
    return parameters.generate_private_key()

def encode(item):
    if isinstance(item, str):   return item.encode('utf-8')
    if isinstance(item, int):   return item.to_bytes(4, byteorder='big')
    if isinstance(item, bytes): return item
    if isinstance(item, RSAPublicKey):
        # serialize RSA key in PEM encoding
        return item.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    if isinstance(item, DHPublicKey):
        # split public key into p, g and y and encode
        public_numbers = item.public_numbers()
        parameter_numbers = public_numbers.parameter_numbers
        return _DH_IFS.join([
            parameter_numbers.p.to_bytes(300, byteorder='big'),
            parameter_numbers.g.to_bytes(28, byteorder='big'),
            public_numbers.y.to_bytes(300, byteorder='big')
        ])


def decode(data, data_type):
    if data_type is str:   return str(data, 'utf-8')
    if data_type is int:   return int.from_bytes(data, byteorder='big')
    if data_type is bytes: return data
    if data_type is RSAPublicKey:
        return serialization.load_pem_public_key(data, backend=default_backend())
    if data_type is RSAPrivateKey:
        return serialization.load_pem_private_key(data, password=None, backend=default_backend())
    if data_type is DHPublicKey:
        *nums, y = [decode(x, int) for x in data.split(_DH_IFS)]
        public_numbers = dh.DHPublicNumbers(y, dh.DHParameterNumbers(*nums))
        return public_numbers.public_key(backend=default_backend())


def get_public_key(filename):
    with open(filename, 'rb') as f:
        return decode(f.read(), RSAPublicKey)


def get_private_key(filename):
    with open(filename, 'rb') as f:
        return decode(f.read(), RSAPrivateKey)


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key


def hash_items(*args):
    """ Returns a hash of the provided arguments """
    digest = Hash(SHA256(), backend=default_backend())
    for item in args:
        digest.update(item)
    return digest.finalize()


def hashn(item, n):
    return reduce(lambda x, _: hash_items(x), range(n), item)


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
            mgf=padding.MGF1(algorithm=SHA1()),
            algorithm=SHA1(),
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
            mgf=padding.MGF1(algorithm=SHA1()),
            algorithm=SHA1(),
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


def dh_encrypt(session_key, data):
    iv = urandom(16)
    padder = PKCS7(256).padder()
    padded_data = padder.update(data) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(session_key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return _MSG_IFS.join([iv, encrypted_data])


def dh_decrypt(session_key, data):
    iv, encrypted_data = data.split(_MSG_IFS)
    decryptor = Cipher(
        algorithms.AES(session_key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(256).unpadder()
    unpadded_data = unpadder.update(padded_data) + unpadder.finalize()
    return unpadded_data


def sign(private_key, data):
    return private_key.sign(
        encode(data),
        padding.PSS(
            mgf=padding.MGF1(SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        SHA256()
    )


def verify_signature(public_key, signature, data):
    """ Function that verifies the signature of the input ciphertext.
        Throws an InvalidSignature if verification fails. """
    public_key.verify(signature, data,
        padding.PSS(
            mgf=padding.MGF1(SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        SHA256()
    )
