"""Cryptopals set 6 challenge 46: RSA parity oracle
This one is so good!"""

from challenges.set5.challenge39 import (rsa_encrypt, rsa_decrypt,
                                         generate_rsa_key, int2bytes)
from challenges.set5.challenge40 import rounded_integer_division


class RSAParityOracle:
    def __init__(self):
        self.public, self.private = generate_rsa_key(512)

    def parity_check(self, cipher):
        plain = rsa_decrypt(cipher, self.private, return_type=int)
        return plain % 2

    def encrypt_message(self, message):
        return rsa_encrypt(message, self.public)

    def get_public_key(self):
        return self.public

if __name__ == "__main__":
    oracle = RSAParityOracle()
    import binascii
    cipher = oracle.encrypt_message(
        binascii.a2b_base64("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3"
                            "VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
    )
    #cipher = oracle.encrypt_message(b"hello")
    register = cipher
    n = oracle.get_public_key().modulo
    e = oracle.get_public_key().key
    multiplier = oracle.encrypt_message(2)
    lower_bound = 0
    upper_bound = n
    while lower_bound != upper_bound:
        print(int2bytes(lower_bound))
        print(int2bytes(upper_bound))
        #register = (2**e)*register % n
        register = multiplier * register % n
        if oracle.parity_check(register):
            lower_bound += rounded_integer_division(upper_bound - lower_bound, 2)
        else:
            upper_bound -= rounded_integer_division(upper_bound - lower_bound, 2)
    print(int2bytes(upper_bound))