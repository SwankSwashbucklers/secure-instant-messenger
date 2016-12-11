"""
    Python application that encrypts and signs a file to be sent over email.
    On encryption the sender knows the public key of destination, and has a
    private key to sign the file.  The application can also be used to decrypt
    the encrypted file, provided it knows the private key of the destination
    and the public key of the sender.
"""

from sys import exit, argv
from os import urandom
from functools import update_wrapper
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes



### Exceptions #################################################################

class FcryptError(Exception):
    """Base class for script exceptions"""
    def __init__(self, msg):
        self.msg = "\nException in script {}:\n\n{}".format(argv[0], msg)

    def __str__(self):
        return self.msg


class ArgParseError(FcryptError):
    """An error from trying to parse commandline arguments"""
    def __str__(self):
        return "{}\ncall {} with flag -h for more info".format(
            self.msg, argv[0])



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


def read_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

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



### Classes ####################################################################

class Fcipher:
    """ Base class the Fencryptor and Fdecryptor classes inheirit from.
        Defines the key sizes, algorithms, and modes used in the script. """

    @property
    def symmetric_cipher(self):
        return Cipher(
            algorithms.AES(self.symmetric_key),
            modes.CBC(self.iv),
            backend=default_backend()
        )

    @property
    def symmetric_padding(self):
        return PKCS7(128)

    @property
    def asymetric_padding(self):
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )

    @property
    def signing_padding(self):
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )

    @property
    def signing_hash_fn(self):
        return hashes.SHA256()


class Fencryptor(Fcipher):
    def __init__(self,
                 dest_public_key_filename,
                 sender_private_key_filename,
                 input_filename):
        self.dest_public_key = get_public_key(dest_public_key_filename)
        self.sender_private_key = get_private_key(sender_private_key_filename)
        self.input_message = read_from_file(input_filename)

        # generate symmetric key and initialization vector to use during encryption
        self.symmetric_key = urandom(32)
        self.iv = urandom(16)

    @cached_property
    def encrypted_key(self):
        """ Returns an asymmetric encryption of the key used to symmetrically
            encrypt the input message. """
        return self.dest_public_key.encrypt(self.symmetric_key, self.asymetric_padding)

    @cached_property
    def encrypted_msg(self):
        """ Returns a symmetrical encryption of the padded input message, with
            the initialization vector and the encrypted key appended. """
        encryptor = self.symmetric_cipher.encryptor()
        padder = self.symmetric_padding.padder()
        padded_data = padder.update(self.input_message) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return self.encrypted_key + self.iv + encrypted_data

    @cached_property
    def signature(self):
        """ Returns a signature of the encrypted message. """
        return self.sender_private_key.sign(
            self.encrypted_msg, self.signing_padding, self.signing_hash_fn)

    def encrypt(self):
        """ Returns the encrypted message with its signature appended. """
        return self.signature + self.encrypted_msg


class Fdecryptor(Fcipher):
    def __init__(self,
                 dest_private_key_filename,
                 sender_public_key_filename,
                 input_ciphertext_filename):
        self.dest_private_key = get_private_key(dest_private_key_filename)
        self.sender_public_key = get_public_key(sender_public_key_filename)
        self.input_ciphertext = read_from_file(input_ciphertext_filename)

    @cached_property
    def decrypted_key(self):
        """ Returns the decrypted symmetric key. """
        encrypted_key = self.input_ciphertext[256:512]
        return self.dest_private_key.decrypt(encrypted_key, self.asymetric_padding)

    @property
    def decrypted_msg(self):
        """ Returns the decrypted and unpadded symmetrically encrypted
            message. """
        self.symmetric_key = self.decrypted_key
        self.iv = self.input_ciphertext[512:528]
        encrypted_msg = self.input_ciphertext[528:]
        decryptor = self.symmetric_cipher.decryptor()
        unpadder = self.symmetric_padding.unpadder()
        padded_data = decryptor.update(encrypted_msg) + decryptor.finalize()
        unpadded_data = unpadder.update(padded_data) + unpadder.finalize()
        return unpadded_data

    def verify_signature(self):
        """ Function that verifies the signature of the input ciphertext.
            Throws an InvalidSignature if verification fails. """
        signature = self.input_ciphertext[:256]
        message = self.input_ciphertext[256:]
        self.sender_public_key.verify(
            signature, message, self.signing_padding, self.signing_hash_fn)

    def decrypt(self):
        """ Verifies the signature of the input ciphertext and then returns
            the decrypted message. """
        try:
            self.verify_signature()
        except InvalidSignature:
            raise
        else:
            return self.decrypted_msg



### Command Line Interface #####################################################

def parse_args():
    encrypt_args = (
        'destination_public_key_filename',
        'sender_private_key_filename',
        'input_plaintext_file',
        'ciphertext_file'
    )
    decrypt_args = (
        'destination_private_key_filename',
        'sender_public_key_filename',
        'ciphertext_file',
        'output_plaintext_file'
    )
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__ )
    parser.add_argument("-e", type=str, nargs=4, metavar=encrypt_args)
    parser.add_argument("-d", type=str, nargs=4, metavar=decrypt_args)
    args = parser.parse_args()

    # ensure that the script arguments are correct
    if not args.e and not args.d:
        raise ArgParseError("you must provide either option -e or -d")
    if args.e and args.d:
        raise ArgParseError("only one of -e and -d can be provided")

    if args.e:
        output_file = args.e.pop()
        return (True, output_file, tuple(args.e))
    output_file = args.d.pop()
    return (False, output_file, tuple(args.d))



### Main #######################################################################

def main():
    output = ""

    try: # parse commandline arguments
        encrypt, output_filename, options = parse_args()
    except ArgParseError as e:
        print(e)
        exit(1)

    if encrypt:
        print("\nEncrypting file... ")
        try:
            my_encryptor = Fencryptor(*options)
        except OSError as e:
            print(e)
            exit(1)
        else:
            output = my_encryptor.encrypt()
    else:
        print("\nDecrypting file...")
        try:
            my_decryptor = Fdecryptor(*options)
            output = my_decryptor.decrypt()
        except OSError as e:
            print(e)
            exit(1)
        except InvalidSignature as e:
            print(e)
            exit(1)

    if not output: # exit if no output
        print("Error: no output generated.")
        exit(1)

    # write result to output file
    with open(output_filename, 'wb') as output_file:
        output_file.write(output)
    print("Process complete.\n")
    exit(0)

if __name__ == "__main__":
    main()
