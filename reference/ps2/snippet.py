def generate_sender_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def get_keys(public_key_filename, private_key_filename):
    """Returns (public_key, private_key) for the filenames where the keys are stored"""
    with open(private_key_filename, 'rb') as private_key_file, \
         open(public_key_filename, 'rb') as public_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )
        print()
        print("Private Key")
        print(private_key)
        print()
        print("Public Key")
        print(public_key)
        print()
        return (public_key, private_key)


def encrypt(dest_public_key, sender_private_key, input, output_filename):
    print("encrypt")
    print(public_key, private_key, input, output)

    # temp message here
    message = b'a secret message'

    # First encrypt the message with a symmeteric key
    key = urandom(32)
    iv = urandom(16)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()

    # Then encrypt the key

    public, private = get_keys(public_key, private_key)

    ciphertext = public.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


    # decrypt the key
    plaintext = private.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # decrypt the message
    new_iv = urandom(16) #
    decrypt_cipher = Cipher(
        algorithms.AES(plaintext),
        modes.CBC(new_iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    to_print_out = decryptor.update(ct) + decryptor.finalize()

    print("\n\n\nPlaintext")
    print(to_print_out)


def decrypt(private_key, public_key, input, output):
    print("decrypt")
    print(private_key, public_key, input, output)


    # if mode is ProgramMode.encrypt:
    #     try:
    #         dest_public_key = get_public_key(options[0])
    #         sender_private_key = get_private_key(options[1])
    #         input_message = read_file(options[2])
    #         output_filename = options[3]
    #     except OSError as e:
    #         print(e)
    #         exit(1)
    #     else:
    #
    # elif mode is ProgramMode.decrypt:
    #     try:
    #         dest_private_key = get_private_key(options[0])
    #         sender_public_key = get_public_key(options[1])
    #         input_cipher = read_file(options[2])
    #         output_filename = options[3]
    #     except OSError as e:
    #         print(e)
    #         exit(1)
    #
    # else:
    #     exit(0)

        # method, args, output_filename = parse_args()
        # with open(output_filename, 'wb') as output_file:
        #     output_file.write(
        #         method(*args)
        #     )



    #
    # output_file = options.pop()
    # options = map(read_file, options)
    #
    # input_file = options.pop()
    #
    # if encrypt:
    #     method = encrypt_msg
    #     public_key, private_key = tuple(options)
    # else:
    #     method = decrypt_msg
    #     private_key, public_key = tuple(options)
    #
    # method = encrypt_msg if args.e else decrypt_msg
    # options = args.e if args.e else args.d

    # if args.e:
    #     return (
    #         encrypt_msg,
    #         (
    #             get_public_key(args.e[0]),
    #             get_private_key(args.e[1]),
    #             get_input(args.e[2])
    #         ),
    #         args.e[3]
    #     )
    # return (
    #     decrypt_msg,
    #     (
    #         get_private_key(args.d[0]),
    #         get_public_key(args.d[1]),
    #         get_input(args.d[2])
    #     ),
    #     args.d[3]
    # )
