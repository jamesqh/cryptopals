"""Cryptopals set 6 challenge 48: Bleichenbacher's RSA padding oracle again.
This is literally the exact same code but with a 768 bit keypair instead.
All questions referred to challenge 47.
This takes a LONG TIME. 90 minutes on my last execution with a weak oracle.
Definitely room for optimisation."""

from challenges.common_functions import (int2bytes, bytes2int)
from challenges.set6.challenge47 import (RSAPaddingOracle, pkcs_1_5_pad,
                                         bleichenbacher_attack)


if __name__ == "__main__":
    import time
    oracle = RSAPaddingOracle(384)
    true_message = pkcs_1_5_pad(b'kick it, CC', oracle.public.modulo)
    c = oracle.encrypt_message(true_message)
    start = time.time()
    decrypted_message = bleichenbacher_attack(c, oracle)
    end = time.time()
    print(int2bytes(decrypted_message))
    assert decrypted_message == bytes2int(true_message)
    print("Challenge complete in {0} seconds".format(round(end - start, 2)))