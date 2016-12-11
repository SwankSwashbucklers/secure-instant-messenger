

from common.crypto import *

dh_public_key, dh_private_key = generate_dsa_keys()
#public_key, private_key = generate_rsa_keys()
dh_public_key2, dh_private_key2 = generate_dsa_keys()

try:
    sy = dh_private_key.exchange()
except Exception as e:
    print(e)


# print('ENCODE RSA')
# print(decode(encode(public_key), RSAPublicKey))
# print(decode(encode(private_key), RSAPrivateKey))

print('ENCODE DSA')
print(decode(encode(dh_public_key), DSAPublicKey))
print(decode(encode(dh_private_key), DSAPrivateKey))

# from cryptography.hazmat.backends.interfaces import DHBackend
#
# print(DHBackend().dh_exchange_algorithm_supported())

print()
print()
pnums = dh_private_key.parameters().parameter_numbers()

print('p:',pnums.p)
print()
print('g:', pnums.g)
print()
print('q:', pnums.q)
print()




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
