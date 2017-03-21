"""Cryptopals set 5 challenge 38: Offline dictionary attack on simplified SRP.
This one seems quite open to interpretation to me. But this is how I've done it.
Costs one modexp and one SHA256 per guess, so about as expensive as an attack
on a very basic salted SHA256 password system."""

import hmac
import itertools
import random
import time
from operator import itemgetter

from nltk.corpus import words

from challenges.set5.challenge36 import SHA256, p

word_list = words.words()
password_list = [word for word in word_list if len(word) > 5]


def get_password_iterator():
    return itertools.filterfalse(lambda word: len(word) < 5, word_list)


class SimplifiedToySRPServer:
    def __init__(self, N=p, g=2, k=3):
        self.N, self.g, self.k = N, g, k
        self.server_private_key = random.randint(2, N - 2)
        """It's a toy and should only ever have one user but heck why not"""
        self.users = {}

    def create_user(self, email, password):
        if email in self.users.keys():
            raise RuntimeError("User already exists")
        salt = random.randint(0, 2**16)
        x = int.from_bytes(SHA256(str(salt) + password), "big")
        v = pow(self.g, x, self.N)
        server_public_key = pow(self.g, self.server_private_key, self.N)
        ephemeral_u = random.getrandbits(128)
        self.users[email] = {"salt": salt,
                             "verifier": v,
                             "server_public_key": server_public_key,
                             "ephemeral_u": ephemeral_u}
        return True

    def get_email_verifier(self, email):
        try:
            salt, server_public_key, u = itemgetter("salt",
                                                    "server_public_key",
                                                    "ephemeral_u"
                                                    )(self.users[email])
            return {"salt": salt,
                    "server_public_key": server_public_key,
                    "ephemeral_u": u}
        except KeyError:
            """We don't want to give away that a username doesn't exist
            for some reason. So we make up invalid parameters and allow
            verification failure to be deferred to the password stage."""
            return {"salt": random.randint(0, 2**16),
                    "server_public_key": random.randint(0, self.N),
                    "ephemeral_u": random.getrandbits(128)}

    def verify_email(self, email, user_public_key, token):
        try:
            salt, v, server_public_key, u = itemgetter("salt",
                                                       "verifier",
                                                       "server_public_key",
                                                       "ephemeral_u"
                                                       )(self.users[email])
            self.users[email]["ephemeral_u"] = random.getrandbits(128)
        except KeyError:
            """See get_email_verifier"""
            salt, v, server_public_key, u = (random.randint(0, 2**16),
                                             random.randint(0, self.N),
                                             random.randint(0, self.N),
                                             random.getrandbits(128))
        S = pow(user_public_key * pow(v, u, self.N),
                self.server_private_key, self.N)
        K = SHA256(str(S))
        if hmac.compare_digest(token,
                               hmac.new(K,
                                        str(salt).encode("utf-8")).hexdigest()):
            return True
        else:
            return False


class SimplifiedToySRPClient:
    def __init__(self, email, password, N=p, g=2, k=3):
        self.N, self.g, self.k = N, g, k
        self.user_private_key = random.randint(2, N - 2)
        self.email = email
        self.password = password

    def register_with_server(self, server):
        server.create_user(self.email, self.password)

    def login_to_server(self, server):
        # what I'm about to do is absolutely horrible, why is PEP8 so short.
        (salt,
         server_public_key,
         u) = itemgetter("salt",
                         "server_public_key",
                         "ephemeral_u"
                         )(server.get_email_verifier(self.email))
        user_public_key = pow(self.g, self.user_private_key, self.N)
        x = int.from_bytes(SHA256(str(salt) + self.password), "big")
        S = pow(server_public_key, self.user_private_key + u*x, self.N)
        K = SHA256(str(S))
        if server.verify_email(self.email, user_public_key,
                               hmac.new(K, str(salt)
                                       .encode("utf-8")).hexdigest()):
            return True
        else:
            return False


class AttackServer:
    def __init__(self, true_server, N=p, g=2, k=3):
        self.N, self.g, self.k = N, g, k
        self.true_server = true_server
        self.users = {}

    def get_email_verifier(self, email):
        return {"salt": 0, "server_public_key": self.g, "ephemeral_u": 1}

    def verify_email(self, email, user_public_key, token):
        """Pretend this is a proper multi-threaded client server thing
        and we just passed through the login to the actual server
        so it doesn't take a suspiciously long time."""
        for password in password_list:
            x = int.from_bytes(SHA256(str(0) + password), "big")
            v = pow(self.g, x, self.N)
            A = user_public_key
            K = SHA256((A*v)%self.N)
            test_token = hmac.new(K, str(0).encode("utf-8")).hexdigest()
            """No need to worry about timing attacks here!"""
            if test_token == token:
                client = SimplifiedToySRPClient(email, password)
                assert client.login_to_server(self.true_server)
                self.users[email] = client
                print("Cracked password")
                return
        print("Failed to crack password")

if __name__ == "__main__":
    server = SimplifiedToySRPServer()
    secret_password = random.choice(password_list)
    print("true password", secret_password)
    client = SimplifiedToySRPClient("user@example.com", secret_password)
    client.register_with_server(server)
    if client.login_to_server(server):
        print("Login successful")
    else:
        print("Login failed")
    attack_server = AttackServer(server)
    start = time.time()
    client.login_to_server(attack_server)
    print("Attack took", time.time() - start, "seconds")
    guessed_password = attack_server.users["user@example.com"].password
    assert guessed_password == secret_password
    print("Found password: ", guessed_password)
    print("Challenge complete")