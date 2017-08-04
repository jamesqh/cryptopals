"""Cryptopals set 6 challenge 42: Bleichenbacher's e=3 RSA attack.
This one is very clever, Bleichenbacher is a smart smart man.
I'm not a fan of implementing it though. Oh well."""

import hashlib

from challenges.common_functions import (rsa_decrypt, rsa_encrypt, int2bytes,
                                         bytes2int, integer_cube_root,
                                         generate_rsa_key)


def pkcs_1_5_digest(message, blocksize=256):
    hash_ = hashlib.new('sha256', message).digest()
    # 00 01 and 00 A S N . 1 for eight extra bytes.
    ff_block_length = blocksize - len(hash_) - 8
    digest = b'\x00\x01' + b'\xff'*ff_block_length + b'\x00ASN.1' + hash_
    return digest


def rsa_sign(message, priv_key):
    return rsa_decrypt(pkcs_1_5_digest(message), priv_key)


def rsa_verify(message, signature, pub_key, blocksize=256):
    plain_digest = pkcs_1_5_digest(message)
    sig_digest = int2bytes(rsa_encrypt(signature, pub_key))
    sig_digest = b'\x00' * (blocksize - len(sig_digest)) + sig_digest
    return sig_digest == plain_digest


def bad_rsa_verify(message, signature, pub_key, blocksize=256):
    hash_ = hashlib.new('sha256', message).digest()
    sig_digest = int2bytes(rsa_encrypt(signature, pub_key))
    sig_digest = b'\x00' * (blocksize - len(sig_digest)) + sig_digest
    return (sig_digest.startswith(b'\x00\x01\xff')
            and sig_digest.endswith(b'\xff\x00ASN.1' + hash_))


def really_bad_rsa_verify(message, signature, pub_key, blocksize=256):
    # Why would anybody ever write this
    sig_digest = int2bytes(rsa_encrypt(signature, pub_key))
    print(len(sig_digest))
    sig_digest = b'\x00' * (blocksize - len(sig_digest)) + sig_digest
    print(sig_digest)
    head, sig_digest = sig_digest[:2], sig_digest[2:]
    if not head == b'\x00\x01':
        return False
    hash_ = hashlib.new('sha256', message).digest()
    while sig_digest[0] == 255: # FF = 255
        sig_digest = sig_digest[1:]
    if sig_digest.startswith(b'\x00ASN.1' + hash_):
        return True
    else:
        return False

if __name__ == "__main__":
    msg = b'Neunundneunzig Luftballons auf ihrem Weg zum Horizont'
    pub_key, priv_key = generate_rsa_key()
    sig = rsa_sign(msg, priv_key)
    assert rsa_verify(msg, sig, pub_key)
    assert bad_rsa_verify(msg, sig, pub_key)
    assert really_bad_rsa_verify(msg, sig, pub_key)
    print("Signing works")
    fake_msg = b'Bad evil message that has a virus in it'
    assert not rsa_verify(fake_msg, sig, pub_key)
    assert not bad_rsa_verify(fake_msg, sig, pub_key)
    assert not really_bad_rsa_verify(fake_msg, sig, pub_key)
    print("Malicious message accurately detected")
    # The lazy way, I'm afraid
    cube = bytes2int(b'\x00\x01\xff\x00ASN.1'
                     + hashlib.new('sha256', fake_msg).digest())\
           << (2048 - len(b'\x00\x01\xff\x00ASN.1'
                          + hashlib.new('sha256', fake_msg).digest())*8)
    print(len(b'\x00\x01\xff\x00ASN.1'
              + hashlib.new('sha256', fake_msg).digest()))
    cube -= 1
    close_cube_root = integer_cube_root(cube)
    print(int2bytes(close_cube_root**3))
    assert really_bad_rsa_verify(fake_msg, close_cube_root, pub_key)
    print("Challenge complete but nasty")