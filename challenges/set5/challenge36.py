"""Cryptopals set 5 challenge 36: Implement Secure Remote Password (SRP)"""

import hashlib
import hmac
import random
from operator import itemgetter

p = int("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc7402"
        "0bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1"
        "356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386b"
        "fb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da4836"
        "1c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5290770"
        "96966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)


def sha256(message):
    if not isinstance(message, bytes):
        try:
            message = message.encode("utf-8")
        except AttributeError:
            message = str(message).encode("utf-8")
    return hashlib.sha256(message).digest()


class ToySRPServer:
    def __init__(self, N=p, g=2, k=3):
        self.N, self.g, self.k = N, g, k
        self.server_private_key = random.randint(2, N - 2)
        """It's a toy and should only ever have one user but heck why not"""
        self.users = {}

    def create_user(self, email, password):
        if email in self.users.keys():
            raise RuntimeError("User already exists")
        salt = random.randint(0, 2**16)
        x = int.from_bytes(sha256(str(salt) + password), "big")
        v = pow(self.g, x, self.N)
        server_public_key = (self.k * v
                                   + pow(self.g, self.server_private_key,
                                         self.N)) % self.N
        self.users[email] = {"salt": salt,
                             "verifier": v,
                             "server_public_key": server_public_key}
        return True

    def get_email_verifier(self, email):
        try:
            salt, server_public_key = itemgetter("salt",
                                                 "server_public_key"
                                                 )(self.users[email])
            return {"salt": salt,
                    "server_public_key": server_public_key}
        except KeyError:
            """We don't want to give away that a username doesn't exist
            for some reason. So we make up invalid parameters and allow
            verification failure to be deferred to the password stage."""
            return {"salt": random.randint(0, 2**16),
                    "server_public_key": random.randint(0, self.N)}

    def verify_email(self, email, user_public_key, token):
        try:
            salt, v, server_public_key = itemgetter("salt",
                                                    "verifier",
                                                    "server_public_key"
                                                    )(self.users[email])
        except KeyError:
            """See get_email_verifier"""
            salt, v, server_public_key = (random.randint(0, 2**16),
                                          random.randint(0, self.N),
                                          random.randint(0, self.N))
        u = int.from_bytes(sha256(str(user_public_key)
                                  + str(server_public_key)), "big")
        S = pow(user_public_key * pow(v, u, self.N),
                self.server_private_key, self.N)
        K = sha256(str(S))
        if hmac.compare_digest(token,
                               hmac.new(K,
                                        str(salt).encode("utf-8")).hexdigest()):
            return True
        else:
            return False


class ToySRPClient:
    def __init__(self, email, password, N=p, g=2, k=3):
        self.N, self.g, self.k = N, g, k
        self.user_private_key = random.randint(2, N - 2)
        self.email = email
        self.password = password
    def register_with_server(self, server):
        server.create_user(self.email, self.password)
    def login_to_server(self, server):
        salt, server_public_key = itemgetter("salt","server_public_key")\
            (server.get_email_verifier(self.email))
        user_public_key = pow(self.g, self.user_private_key, self.N)
        u = int.from_bytes(sha256(str(user_public_key)
                                  + str(server_public_key)), "big")
        x = int.from_bytes(sha256(str(salt) + self.password), "big")
        S = pow(server_public_key - self.k * pow(self.g, x, self.N),
                self.user_private_key + u * x, self.N)
        K = sha256(str(S))
        if server.verify_email(self.email, user_public_key,
                               hmac.new(K, str(salt)
                                       .encode("utf-8")).hexdigest()):
            return True
        else:
            return False

if __name__ == "__main__":
    server = ToySRPServer()
    client = ToySRPClient("user@example.com", "myweakpassword1234")
    client.register_with_server(server)
    if client.login_to_server(server):
        print("Login successful")
        print("Challenge complete")
    else:
        print("Login failed")