"""Cryptopals set 5 challenge 44: DSA nonce recovery from repeated nonce"""

import itertools
import re

from challenges.set5.challenge39 import modinv
from challenges.set6.challenge43 import sha1, DSAParams, recover_dsa_key_from_k

if __name__ == "__main__":
    try:
        with open("44.txt", "r") as f:
            data = f.read()
    except FileNotFoundError:
        import requests
        r = requests.get("https://cryptopals.com/static/challenge-data/44.txt")
        if r.status_code != 200:
            raise RuntimeError("Can't find data file 44.txt or fetch from internet")
        data = r.text
        with open("44.txt", "w") as f:
            f.write(data)
    pattern = re.compile(r'msg: (.+)\ns: (.+)\nr: (.+)\nm: (.+)\n?')
    matches = re.findall(pattern, data)
    signatures = []
    for match in matches:
        msg, s, r, m = match
        signatures.append({"msg": msg, "s": int(s), "r": int(r), "m": int(m, 16)})
    y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105"
            "d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6"
            "581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d827"
            "9ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)
    p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac"
            "698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3"
            "bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4"
            "deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    g = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046"
            "c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7"
            "f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c88789287"
            "8480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
    params = DSAParams(p, q, g, sha1)
    """Clearly for the signatures with repeated k, r will be identical.
    So that's what we look for."""
    attack_pairs = [(sig1, sig2) for sig1, sig2
                    in itertools.combinations(signatures, 2)
                    if sig1["r"] == sig2["r"]]
    """Then we trivially recover the k from each pair and get the key!"""
    key_guesses = []
    for sig1, sig2 in attack_pairs:
        m1, m2 = sig1["m"], sig2["m"]
        s1, s2 = sig1["s"], sig2["s"]
        k = ((m1 - m2) * modinv((s1 - s2), q)) % q
        key_guess_1 = recover_dsa_key_from_k(params, sig1["msg"], (sig1["r"], s1), k)
        key_guess_2 = recover_dsa_key_from_k(params, sig2["msg"], (sig2["r"], s2), k)
        assert key_guess_1 == key_guess_2
        key_guesses.append(key_guess_1)
    """They should all be duplicates, or something has gone horribly wrong"""
    assert len(set(key_guesses)) == 1
    """And then hopefully we can verify its hash matches."""
    assert sha1(hex(key_guesses[0])[2:]).hex() == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    print("Challenge complete")