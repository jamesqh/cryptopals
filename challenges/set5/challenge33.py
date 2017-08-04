"""Cryptopals set 5 challenge 33: Implement Diffie-Hellman
Very basic implementation. Just key exchange as ints, no ciphering.
Would involve byte conversions in real world and probably will later."""

import random
from collections import namedtuple

DHParams = namedtuple("DHParams", ("p", "g"))
DHKey = namedtuple("DHKey", ("private", "public", "params"))


def gen_DH_keypair(params, key=None):
    """Generate Diffie Hellman keypair as integers."""
    if key is None:
        key = random.randint(2, params.p-2)
    elif not 0 < key < params.p:
        raise ValueError("Diffie Hellman key must satisfy 0 < key < p")
    return DHKey(private=key, public=pow(params.g, key, params.p),
                 params=params)


def gen_DH_session_key(params, private, public):
    """Generate Diffie Hellman session key as integer."""
    return pow(public, private, params.p)


if __name__ == "__main__":
    p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc7402"
            "0bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1"
            "356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386b"
            "fb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da4836"
            "1c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5290770"
            "96966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
    g = 2
    params = DHParams(p=p, g=g)
    alice_key = gen_DH_keypair(params)
    bob_key = gen_DH_keypair(params)
    assert (gen_DH_session_key(params, alice_key.private, bob_key.public)
            == gen_DH_session_key(params, bob_key.private, alice_key.public))
    print("Diffie Hellman appears to work properly")
    print("Challenge complete")