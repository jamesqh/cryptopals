"""Cryptopals set 5 challenge 37: Break SRP with a zero key."""

import hmac

from challenges.common_functions import ToySRPClient, ToySRPServer, sha256

if __name__ == "__main__":
    server = ToySRPServer()
    email, password = "user@example.com", "ljklajsfiu29po29qu89ouo"
    client = ToySRPClient(email, password)
    server.create_user(email, password)
    assert client.login_to_server(server)
    # We'll tell the server our public key is 0. The server calculates S as
    # a power of a multiple our public key, so clearly S will be 0. We don't
    # need to know either of the real secrets.
    salt = server.get_email_verifier(email)["salt"]
    S = 0
    K = sha256(str(S))
    token = hmac.new(K, str(salt).encode("utf-8")).hexdigest()
    assert server.verify_email(email, 0, token)
    print("Logged in with 0 key")
    # If 0 doesn't work, possibly N^i for some integer i might work.
    # It would be horrible maths to check for 0 but not 0 mod N.
    # But there you go. Apparently people do it.
