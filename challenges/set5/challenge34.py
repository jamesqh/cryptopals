import hashlib
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from challenges.set5.challenge33 import gen_DH_keypair, gen_DH_session_key, DHParams

"""I could use my own DIY CBC but I'd prefer to keep the number of
moving parts to a minimum."""

def AES_CBC_encrypt(key, iv, plain):
    cryptor = Cipher(algorithms.AES(key), modes.CBC(iv),
                     default_backend()).encryptor()
    return cryptor.update(plain) + cryptor.finalize()


def AES_CBC_decrypt(key, iv, cipher):
    cryptor = Cipher(algorithms.AES(key), modes.CBC(iv),
                     default_backend()).decryptor()
    return cryptor.update(cipher) + cryptor.finalize()


def SHA1(message):
    if not isinstance(message, bytes):
        try:
            message = message.encode("utf-8")
        except AttributeError:
            message = str(message).encode("utf-8")
    return hashlib.sha1(message).digest()


class ToyDHClient:
    def __init__(self):
        self.params = None
        self.keypair = None
        self.friend_key = None
        self.session_key = None

    def recv_params(self, params):
        self.params = params
        self.keypair = gen_DH_keypair(params)

    def recv_friend_key(self, friend_key):
        self.friend_key = friend_key
        self.session_key = gen_DH_session_key(self.params,
                                              self.keypair.private,
                                              friend_key)

    def send_public_key(self):
        return self.keypair.public

    def send_message(self, message):
        iv = urandom(16)
        return (AES_CBC_encrypt(SHA1(self.session_key)[:16], iv, message), iv)

    def echo_message(self, cipher, iv):
        msg = self.decrypt_message(cipher, iv)
        iv = urandom(16)
        return (AES_CBC_encrypt(SHA1(self.session_key)[:16], iv, msg), iv)

    def decrypt_message(self, cipher, iv):
        msg = AES_CBC_decrypt(SHA1(self.session_key)[:16], iv, cipher)
        return msg

if __name__ == "__main__":
    p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc7402"
            "0bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1"
            "356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386b"
            "fb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da4836"
            "1c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5290770"
            "96966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
    g = 2
    params = DHParams(p=p, g=g)
    alice = ToyDHClient()
    bob = ToyDHClient()
    alice.recv_params(params)
    bob.recv_params(params)
    """Alice sends her public key to Bob"""
    bob.recv_friend_key(alice.send_public_key())
    """And Bob sends his in return"""
    alice.recv_friend_key(bob.send_public_key())
    """Alice will send Bob some Miike Snow lyrics"""
    true_msg = b"I been wondering what is freedom is it checking out from all" \
               b" you're feeling is it feeling okay cause you're not running" \
               b"_________"
    """Bob will echo it"""
    bob_echo = bob.echo_message(*alice.send_message(true_msg))
    """And we check whether they match"""
    assert true_msg == alice.decrypt_message(*bob_echo)
    print("DH echo bots talking to each other correctly")
    """Begin attack"""
    """Send Bob a fake key in place of Alice's public key"""
    bob.recv_friend_key(p)
    """And send Alice the same"""
    alice.recv_friend_key(p)
    """Alice will send Bob some Miike Snow lyrics"""
    alice_cipher, iv = alice.send_message(true_msg)
    """Session key = public^private mod p
    We've forced public key to 0, hence the session key is 0 regardless of the private key
    Hence we know the session key and can simply decrypt her message."""
    assert true_msg == AES_CBC_decrypt(SHA1(0)[:16], iv, alice_cipher)
    """We'll pass it on to Bob and he'll echo it back, and we'll do the same again"""
    bob_cipher, iv = bob.echo_message(alice_cipher, iv)
    assert true_msg == AES_CBC_decrypt(SHA1(0)[:16], iv, bob_cipher)
    """Job done"""
    print("Challenge complete")