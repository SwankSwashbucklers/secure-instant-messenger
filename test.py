#from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.asymmetric import dh

from common.crypto import *
from common.crypto import generate_dh_private_key
import sys

# p = parameters.parameter_numbers().p
# print('p:', p)

#print(parameters)
print("START")

# peer_public_key = parameters.generate_private_key().public_key()
# print("RSA", isinstance(peer_public_key, RSAPublicKey))
# print("DSA", isinstance(peer_public_key, DSAPublicKey))
# print("DH", isinstance(peer_public_key, DHPublicKey))
# print("TYPE", type(peer_public_key))

print()

# Alice
private_key1 = generate_dh_private_key()

# public key 1 gets sent across
e = encode(private_key1.public_key())
print("ENCODED", e)
peer_public_key1 = decode(e, DHPublicKey)
print("DECODED", peer_public_key1)

# Bob
private_key2 = generate_dh_private_key(public_key=peer_public_key1)
shared_key2 = private_key2.exchange(peer_public_key1)

# public key 2 gets sent across
e2 = encode(private_key2.public_key())
print("ENCODED", e2)
peer_public_key2 = decode(e2, DHPublicKey)
print("DECODED", peer_public_key2)

# Alice
shared_key1 = private_key1.exchange(peer_public_key2)

print("KEYS EQUAL", shared_key1 == shared_key2)

print()
print("SHARED KEY", shared_key1)
print()

print("SIZE OF SHARED KEY", sys.getsizeof(shared_key1))
print("LEN SHARED KEY", len(shared_key1))
hashed_key = hash_items(shared_key1)
print("SIZE OF HASHED KEY", sys.getsizeof(hashed_key))
print("LEN HASHED KEY", len(hashed_key))


# p = p1.parameter_numbers().p
# g = p1.parameter_numbers().g
# y = private_key1.public_key().public_numbers().y
#
# print("TYPE OF P", type(p))
# print("SIZE OF P", sys.getsizeof(p))
#
# print("TYPE OF G", type(g))
# print("SIZE OF G", sys.getsizeof(g))
#
# print("TYPE OF Y", type(y))
# print("SIZE OF Y", sys.getsizeof(y))

# # p g y get sent across
# private_key2 = gen_pri_from_nums(p, g)
# peer_public_key2 = gen_pub_from_nums(p, g, y)
# shared_key1 = private_key2.exchange(peer_public_key2)
#
# y2 = private_key2.public_key().public_numbers().y
#
# # y gets sent across
# peer_public_key1 = gen_pub_from_nums(p, g, y2)
# shared_key2 = private_key1.exchange(peer_public_key1)





# from common.crypto import *
#
# dh_public_key, dh_private_key = generate_dsa_keys()
# #public_key, private_key = generate_rsa_keys()
# dh_public_key2, dh_private_key2 = generate_dsa_keys()
#
# try:
#     sy = dh_private_key.exchange()
# except Exception as e:
#     print(e)
#
#
# # print('ENCODE RSA')
# # print(decode(encode(public_key), RSAPublicKey))
# # print(decode(encode(private_key), RSAPrivateKey))
#
# print('ENCODE DSA')
# print(decode(encode(dh_public_key), DSAPublicKey))
# print(decode(encode(dh_private_key), DSAPrivateKey))
#
# # from cryptography.hazmat.backends.interfaces import DHBackend
# #
# # print(DHBackend().dh_exchange_algorithm_supported())
#
# print()
# print()
# pnums = dh_private_key.parameters().parameter_numbers()
#
# print('p:',pnums.p)
# print()
# print('g:', pnums.g)
# print()
# print('q:', pnums.q)
# print()




# def foo(x, *args):
#     pass
#

# class Foo():
#
#     pipeline = []
#     def __init__(self):
#         self.v = 3
#         #self.pipeline = []
#
#     @classmethod
#     def add_step(cls):
#         def add_pipe(fn):
#             cls.pipeline.append(fn)
#             return fn
#         return add_pipe
#         # return lambda fn: cls.pipeline.append(fn)
#         # self.pipeline.append(fn)
#         # return fn
#
#     # @add_step(Foo)
#     # def fn1(self, x):
#     #     return x + self.v
#
#
# class Bar(Foo):
#
#     def fn1(self, x):
#         return x + self.v
#
#     def test(self, x, *args):
#         foobar = [*args]
#         print()
#         print(args)
#         print(foobar)
#         if not self.test2:
#             print("FOOBAR")
#
#
#
#
# bar = Bar()
# bar.test(1, 0)
# bar.test(1)
# bar.test(1,2,3)

# i = 0
# while i < 4:
#     if i == 2:
#         i += 1
#         continue
#     print(i)
#     i += 1
