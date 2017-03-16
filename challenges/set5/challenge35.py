"""Cryptopals set 5 challenge 35: Implement DH with negotiated groups
and break with malicious g parameter. Rehash of the last, really."""

from challenges.set5.challenge34 import (AES_CBC_decrypt, SHA1, ToyDHClient, DHParams)

if __name__ == "__main__":
    """g = 1 attack"""
    p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc7402"
            "0bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1"
            "356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386b"
            "fb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da4836"
            "1c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5290770"
            "96966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
    g = 1
    params = DHParams(p=p, g=g)
    alice = ToyDHClient()
    bob = ToyDHClient()
    """We've interfered with the DH params to set g = 1, nothing else will be molested"""
    alice.recv_params(params)
    bob.recv_params(params)
    alice.recv_friend_key(bob.send_public_key())
    bob.recv_friend_key(alice.send_public_key())
    true_msg = b"I been wondering what is freedom is it checking out from all" \
               b" you're feeling is it feeling okay cause you're not running" \
               b"_________"
    """Session key = public^private mod p
    Public = g^private mod p
    g = 1 hence public = 1 regardless of private
    So we know session key = 1 as well.
    Alice sends some Miike Snow lyrics to Bob and we can decrypt them."""
    alice_cipher, iv = alice.send_message(true_msg)
    assert AES_CBC_decrypt(SHA1(1)[:16], iv, alice_cipher) == true_msg
    print("g = 1 attack works")
    """g = p attack"""
    g = p
    params = DHParams(p=p, g=g)
    alice = ToyDHClient()
    bob = ToyDHClient()
    """We've interfered with the DH params to set g = 1, nothing else will be molested"""
    alice.recv_params(params)
    bob.recv_params(params)
    alice.recv_friend_key(bob.send_public_key())
    bob.recv_friend_key(alice.send_public_key())
    """Session key = public^private mod p
    Public = g^private mod p
    g = p = 0 mod p hence public = 0 and session key = 0. We decrypt the lyrics:"""
    alice_cipher, iv = alice.send_message(true_msg)
    assert AES_CBC_decrypt(SHA1(0)[:16], iv, alice_cipher) == true_msg
    print("g = p attack works")
    """g = p-1 attack"""
    g = p-1
    params = DHParams(p=p, g=g)
    alice = ToyDHClient()
    bob = ToyDHClient()
    """We've interfered with the DH params to set g = 1, nothing else will be molested"""
    alice.recv_params(params)
    bob.recv_params(params)
    """But we will make sure to intercept Bob's and Alice's public keys"""
    bob_public = bob.send_public_key()
    alice.recv_friend_key(bob_public)
    alice_public = alice.send_public_key()
    bob.recv_friend_key(alice_public)
    """Session key = bob_public^alice_private mod p = alice_public^bob_private mod p
    We immediately see that if either public key is 1 (or both), then the session key must be 1.
    And since each public = g^private mod p and g = -1 mod p, clearly each public is += 1.
    So what if both public keys are -1? The parity of the session key depends on the private keys,
    and the parity of the private keys determines the parity of the public keys.
    We can observe that public = g^private = (-1)^private = -1 mod p if and only if private is odd.
    So if both public keys = -1 mod p then both private keys are odd,
    and the session key is clearly -1^odd = -1 mod p.
    Alice will send a message and we'll use the above information to decrypt it."""
    alice_cipher, iv = alice.send_message(true_msg)
    if alice_public or bob_public == 1:
        """Session key = 1 so"""
        assert AES_CBC_decrypt(SHA1(1)[:16], iv, alice_cipher) == true_msg
    else:
        """Session key = -1 mod p = p-1 so"""
        assert AES_CBC_decrypt(SHA1(p-1)[:16], iv, alice_cipher) == true_msg
    """And we'll just quickly check that it works the other way too:"""
    bob_cipher, iv = bob.echo_message(alice_cipher, iv)
    if alice_public or bob_public == 1:
        """Session key = 1 so"""
        assert AES_CBC_decrypt(SHA1(1)[:16], iv, bob_cipher) == true_msg
    else:
        """Session key = -1 mod p = p-1 so"""
        assert AES_CBC_decrypt(SHA1(p-1)[:16], iv, bob_cipher) == true_msg
    print("g = p-1 attack works")
    print("Challenge complete")