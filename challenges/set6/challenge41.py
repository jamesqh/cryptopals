"""
Cryptopals set 6 challenge 41: Implement unpadded RSA message recovery oracle.
"""

import random
import time

from challenges.common_functions import (rsa_encrypt, rsa_decrypt,
                                         generate_rsa_key, modinv, int2bytes,
                                         bytes2int)


class ToyRSAServer:
    def __init__(self):
        self.rsa_key = generate_rsa_key(1024)
        self.liveness_interval = 500
        self.previous_message_hashes = {}

    def get_public_key(self):
        pub_key, _ = self.rsa_key
        return pub_key

    def clear_hashes(self):
        for hash_, timestamp in self.previous_message_hashes.items():
            if time.time() - timestamp > self.liveness_interval:
                del self.previous_message_hashes[hash_]

    def encrypt_message(self, message):
        pub_key, _ = self.rsa_key
        return rsa_encrypt(message, pub_key)

    def decrypt_message(self, cipher):
        self.clear_hashes()
        _, priv_key = self.rsa_key
        message = rsa_decrypt(cipher, priv_key)
        if hash(message) in self.previous_message_hashes.keys():
            raise ValueError("Message already decrypted")
        else:
            self.previous_message_hashes[hash(message)] = int(time.time())
            return message


if __name__ == "__main__":
    server = ToyRSAServer()
    msg = (b"It's a long, a long way down on your own, "
           b"it's a long, a long way out")
    cipher = server.encrypt_message(msg)
    assert server.decrypt_message(cipher) == msg
    try:
        server.decrypt_message(cipher)
        # We want the server to raise an exception here, since the message
        # has already been decrypted once.
        assert False
    except ValueError:
        print("Server seems to work correctly")
    server_pub_key = server.get_public_key()
    C = cipher
    N, E = server_pub_key.modulo, server_pub_key.key
    S = random.randint(2, N-1)
    C_ = (pow(S, E, N) * C) % N
    P_ = bytes2int(server.decrypt_message(C_))
    P = int2bytes((P_ * modinv(S, N)) % N)
    assert P == msg
    print("Challenge complete. Not much to work out in that one. "
          "That final % N is a nasty tripwire though!")