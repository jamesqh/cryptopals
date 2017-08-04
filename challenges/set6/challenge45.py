"""Cryptopals set 6 challenge 45: DSA parameter tampering"""

from challenges.common_functions import (DSAParams, generate_dsa_key,
                                         dsa_verify, sha1, modinv)


def make_magic_signature(dsa_key):
    y = dsa_key.public_key
    params = dsa_key.params
    # Not sure why we might want to change z, but just in case
    z = 1
    r = pow(y, z, params.p) % params.q
    s = (r * modinv(z, params.q)) % params.q
    return (r, s)

if __name__ == "__main__":
    p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac"
            "698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3"
            "bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4"
            "deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    # We're told to try g = 0, which is meant to produce a signature with r = 0,
    # which would mean v, which is a multiple of g, is also 0
    # and so v == r is achieved trivially for any signature and any message
    # under these parameters. But my implementation correctly fails to sign
    # anything with these parameters and also rejects attempts to verify
    # using these parameters. Anyway we'll jump straight to g = p + 1.
    g = p + 1
    params = DSAParams(p, q, g, sha1)
    key = generate_dsa_key(params)
    magic_signature = make_magic_signature(key)
    assert dsa_verify(key, b"Hello world", magic_signature)
    assert dsa_verify(key, b"Goodbye world", magic_signature)
    # Not hard to see why that works, since p + 1 == 1 mod p. s is r/z,
    # w is z/r, u2 is r*w = r*z/r = z, v is g^u1 * y^u2 = 1 * y^z,
    # so to achieve v == r we just need to make sure r = y^z,
    # which is exactly what we set it to!
    print("Challenge complete!")