"""Cryptopals set 6 challenge 43: DSA key recovery from nonce
Int-hex-string-bytes-hex chain and a phantom newline, what an annoying one this is"""

import hashlib
import random
from collections import namedtuple

from challenges.set5.challenge36 import sha256
from challenges.set5.challenge39 import (generate_prime, miller_rabin, bytes2int, modinv)

DSAParams = namedtuple("DSAParams", ["p", "q", "g", "hash_function"])
DSAKey = namedtuple("DSAKey", ["private_key", "public_key", "params"])


def generate_dsa_params(key_len_L=3072, key_len_N=256, hash_function=sha256):
    hash_length = len(hash_function(0))*8
    if not key_len_N <= hash_length:
        raise ValueError("Key length N must be less than hash function output size")
    if not key_len_N < key_len_L:
        raise ValueError("Key length N must be less than key length L")
    q = generate_prime(key_len_N)
    k = 2**(key_len_L-key_len_N)
    while not miller_rabin(q*k + 1):
        k += 1
    p = q*k + 1
    h = 2
    while pow(h, k, p) == 1:
        h = random.randint(2, p-2)
    g = pow(h, k, p)
    return DSAParams(p, q, g, hash_function)


def generate_dsa_key(dsa_params=None):
    if dsa_params is None:
        dsa_params = generate_dsa_params()
    x = random.randint(2, dsa_params.q-2)
    return DSAKey(x, pow(dsa_params.g, x, dsa_params.p), dsa_params)


def dsa_sign(dsa_key, msg):
    dsa_params = dsa_key.params
    hash_function = dsa_params.hash_function
    r = 0
    while r == 0:
        k = random.randint(1, dsa_params.q-1)
        r = pow(dsa_params.g, k, dsa_params.p) % dsa_params.q
    s = 0
    while s == 0:
        s = (modinv(k, dsa_params.q)
             * (bytes2int(hash_function(msg)) + dsa_key.private_key * r)) % dsa_params.q
    return (r, s)


def dsa_verify(dsa_key, msg, signature):
    dsa_params = dsa_key.params
    hash_function = dsa_params.hash_function
    r, s = signature
    if not (0 < r < dsa_params.q and 0 < s < dsa_params.q):
        raise ValueError("Invalid signature")
    w = modinv(s, dsa_params.q)
    u1 = (bytes2int(hash_function(msg)) * w) % dsa_params.q
    u2 = (r * w) % dsa_params.q
    v = ((pow(dsa_params.g, u1, dsa_params.p)
          * pow(dsa_key.public_key, u2, dsa_params.p)) % dsa_params.p) % dsa_params.q
    if not v == r:
        raise ValueError("Invalid signature")
    else:
        return True


def unsafe_dsa_sign(dsa_key, msg, k=None):
    dsa_params = dsa_key.params
    hash_function = dsa_params.hash_function
    r = pow(dsa_params.g, k, dsa_params.p) % dsa_params.q
    if r == 0:
        raise ValueError("Supplied k is unsuitable (g**k % p == 0)")
    s = 0
    while s == 0:
        s = (modinv(k, dsa_params.q)
             * (bytes2int(hash_function(msg)) + dsa_key.private_key * r)) % dsa_params.q
    return (r, s)


def recover_dsa_key_from_k(dsa_params, msg, signature, k):
    r, s = signature
    hash_function = dsa_params.hash_function
    return ((s * k - bytes2int(hash_function(msg))) * modinv(r, dsa_params.q)
            % dsa_params.q)


def check_private_key_guess_by_public(guess, public, dsa_params):
    if public == pow(dsa_params.g, guess, dsa_params.p):
        return True
    else:
        return False


def check_private_key_guess_by_signature(guess, k, msg, signature, dsa_params):
    test_key = DSAKey(guess, 0, dsa_params)
    if unsafe_dsa_sign(test_key, msg, k) == signature:
        return True
    else:
        return False


def sha1(message):
    if not isinstance(message, bytes):
        try:
            message = message.encode("utf-8")
        except AttributeError:
            message = str(message).encode("utf-8")
    return hashlib.sha1(message).digest()

if __name__ == "__main__":
    dsa_params = generate_dsa_params(key_len_L=512)
    dsa_key = generate_dsa_key(dsa_params)
    msg = b"Rough winds do shake the darling buds of May, and Summer's lease hath all too short a date"
    signature = dsa_sign(dsa_key, msg)
    assert dsa_verify(dsa_key, msg, signature)
    try:
        dsa_verify(dsa_key, b"totally fake malicious message", signature)
        assert False
    except ValueError:
        pass
    compromised_signature = unsafe_dsa_sign(dsa_key, msg, 0xdeadbeef)
    assert recover_dsa_key_from_k(dsa_params, msg, compromised_signature, 0xdeadbeef) == dsa_key.private_key
    """Params for attacking cpals key"""
    p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac"
            "698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3"
            "bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4"
            "deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    g = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046"
            "c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7"
            "f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c88789287"
            "8480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
    public_key = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4ab"
                     "ab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e449"
                     "84e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec56"
                     "8280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e66"
                     "33451e535c45513b2d33c99ea17", 16)
    msg = (b"For those that envy a MC it can be hazardous to your health\n"
           b"So be friendly, a matter of life and death, just like a etch-a-sketch\n")
    assert sha1(msg).hex() == "d2d0714f014a9784047eaeccf956520045c45265"
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    signature = (r, s)
    dsa_params = DSAParams(p, q, g, sha1)
    answer = None
    for k_guess in range(2**16+1):
        private_guess = recover_dsa_key_from_k(dsa_params, msg, signature, k_guess)
        if (check_private_key_guess_by_public(private_guess, public_key, dsa_params)
            and check_private_key_guess_by_signature(private_guess, k_guess, msg, signature, dsa_params)):
            answer = private_guess
            break
    assert answer is not None
    print("Answer is {0}".format(answer))
    assert sha1(hex(answer)[2:]).hex() == "0954edd5e0afe5542a4adf012611a91912a3ec16"
    print("Challenge complete")