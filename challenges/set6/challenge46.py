"""Cryptopals set 6 challenge 46: RSA parity oracle
This one is so good!
The binary search uses REAL intervals not integer arithmetic,
so we'll use the decimal module to get floats of sufficient precision.
The lower and upper bounds both converge on the answer, one rounds up the other down."""

from decimal import Decimal, getcontext
from math import ceil

from challenges.set5.challenge39 import (rsa_encrypt, rsa_decrypt,
                                         generate_rsa_key, int2bytes)


class RSAParityOracle:
    def __init__(self, bits):
        self.public, self.private = generate_rsa_key(bits)

    def parity_check(self, cipher):
        plain = rsa_decrypt(cipher, self.private, return_type=int)
        return plain % 2

    def encrypt_message(self, message):
        return rsa_encrypt(message, self.public)

    def get_public_key(self):
        return self.public

if __name__ == "__main__":
    oracle = RSAParityOracle(512)
    import binascii
    msg = binascii.a2b_base64("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFy"
                              "b3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
    msg_hash = hash(msg)
    cipher = oracle.encrypt_message(msg)
    register = cipher
    n = oracle.get_public_key().modulo
    e = oracle.get_public_key().key
    multiplier = oracle.encrypt_message(2)
    getcontext().prec = n.bit_length() # set precision to be sufficient
    lower_bound = Decimal(0)
    upper_bound = Decimal(n)
    for _ in range(n.bit_length()):
        register = multiplier * register % n
        mid = (upper_bound + lower_bound) / Decimal(2)
        if oracle.parity_check(register) == 1:
            lower_bound = mid
        else:
            upper_bound = mid
    assert int(ceil(lower_bound)) == int(upper_bound)
    assert hash(int2bytes(int(upper_bound))) == msg_hash
    print("Challenge complete")