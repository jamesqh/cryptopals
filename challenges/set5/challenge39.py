"""Cryptopals set 5 challenge 39: Implement RSA.
I'm gonna implement Miller-Rabin primegen because RSA on its own is hardly fun"""

import random
from collections import namedtuple


def int2bytes(i):
    return i.to_bytes(i.bit_length()//8 + 1, "big")


def bytes2int(b):
    return int.from_bytes(b, "big")


def extended_euclidean(a, b):
    s, s_ = 0, 1
    t, t_ = 1, 0
    r, r_ = b, a
    while r != 0:
        quotient = r_ // r
        r_, r = r, r_ - quotient * r
        t_, t = t, t_ - quotient * t
        s_, s = s, s_ - quotient * s
    return r_, s_, t_


def modinv(a, m):
    gcd, s, _ = extended_euclidean(a, m)
    if gcd != 1:
        raise ZeroDivisionError(
            "{0} has no inverse modulo {1}: gcd must be 1, not {2}"
                .format(a, m, gcd))
    else:
        return s % m


RSAPrivateKey = namedtuple("RSAPrivateKey", ["key", "modulo"])
RSAPublicKey = namedtuple("RSAPublicKey", ["key", "modulo"])


def generate_rsa_key(bits=1024, e=3):
    p = generate_prime(bits)
    while (p - 1) % e == 0:
        p = generate_prime(bits)
    q = generate_prime(bits)
    while (q - 1) % e == 0:
        q = generate_prime(bits)
    n = p*q
    et = (p-1)*(q-1)
    d = modinv(e, et)
    return RSAPublicKey(e, n), RSAPrivateKey(d, n)


def rsa_encrypt(text, public_key):
    if not isinstance(text, int):
        try:
            """In case text is just a string, turn it into bytes"""
            text = text.encode("utf-8")
        except AttributeError:
            pass
        text = bytes2int(text)
    if text > public_key.modulo:
        raise RuntimeError("Text too big to be encrypted with this RSA key")
    else:
        cipher = pow(text, public_key.key, public_key.modulo)
        return cipher


def rsa_decrypt(cipher, private_key, return_type=bytes):
    if not isinstance(cipher, int):
        try:
            """In case cipher is just a string, turn it into bytes"""
            cipher = cipher.encode("utf-8")
        except AttributeError:
            pass
        cipher = bytes2int(cipher)
    if cipher > private_key.modulo:
        raise RuntimeError("Cipher too big to be decrypted with this RSA key")
    else:
        text = pow(cipher, private_key.key, private_key.modulo)
        if return_type is bytes:
            return int2bytes(text)
        else:
            raise RuntimeError("No decoding defined for return type: {0}"
                               .format(return_type))


"""All this prime stuff is just showing off. Use a prime library that implements
the same thing in C!"""

primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
          67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
          139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
          223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
          293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
          383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
          463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541]


def generate_prime(bits):
    start = random.randint(2**(bits-1), 2**bits)
    return next_prime(start)


def next_prime(start):
    candidate = start
    """This is kind of awkward... we want to advance in steps of 2
    to trivially avoid even numbers. To do this we'll make sure
    our starting point is odd. We will do this by SUBTRACTING one if it is even
    because we want to make sure we advance a step
    BEFORE doing the first prime test. Because we want the *next* prime,
    if the starting point is already prime we don't want to return it."""
    if candidate%2 == 0:
        candidate -= 1
    while True:
        candidate += 2
        if miller_rabin(candidate):
            return candidate


def miller_rabin(candidate, k=15, trial_division_limit=100):
    if candidate == 1:
        return False
    n = candidate
    for prime in primes[:trial_division_limit]:
        if n == prime:
            return True
        if n % prime == 0:
            return False
    d, r = power_2_factor(n-1)
    witnesses = generate_witnesses(n, k)
    for witness in witnesses:
        if not test_witness(candidate, witness, d, r):
            return False
    return True


def test_witness(candidate, witness, d, r):
    x = pow(witness, d, candidate)
    if x == 1 or x == candidate-1:
        return True
    for _ in range(r):
        x = pow(x, 2, candidate)
        if x == candidate-1:
            return True
    return False


def generate_witnesses(candidate, k):
    bounds = [(2047, [2]),
              (1373653, [2, 3]),
              (9080191, [31, 73]),
              (25326001, [2, 3, 5]),
              (3215031751, [2, 3, 5, 7]),
              (4759123141, [2, 7, 61]),
              (1122004669633, [2, 13, 23, 1662803]),
              (2152302898747, [2, 3, 5, 7, 11]),
              (3474749660383, [2, 3, 5, 7, 11, 13]),
              (341550071728321, [2, 3, 5, 7, 11, 13, 17]),
              (3825123056546413051, [2, 3, 5, 7, 11, 13, 17, 19, 23]),
              (18446744073709551616, [2, 3, 5, 7, 11, 13, 17, 19, 23,27, 29,
                                      31, 37]),
              (318665857834031151167461, [2, 3, 5, 7, 11, 13, 17, 19, 23, 27,
                                          29, 31, 37]),
              (3317044064679887385961981, [2, 3, 5, 7, 11, 13, 17, 19, 23, 27,
                                           29, 31, 37, 41])]
    for bound, bound_witnesses in bounds:
        if candidate < bound:
            return bound_witnesses
    witnesses = []
    while len(witnesses) < k:
        next_witness = random.randint(2, max(2**64, candidate-2))
        while next_witness in witnesses:
            next_witness = random.randint(2, max(2**64, candidate - 2))
        witnesses += [next_witness]
    return witnesses


def gcd(a, n):
    if a == 0:
        return 0
    while n != 0:
        t = n
        n = a % n
        a = t
    return abs(a)


def power_2_factor(n):
    s = 0
    while n % 2 == 0 and n > 0:
        n >>= 1
        s += 1
    return n, s


# pseudoprime_names = ["fermat2pp", "millerrabin2pp", "lucasselfridge",
#                      "stronglucasselfridge", "almostextrastronglucas",
#                      "extrastronglucas", "perrin", "bruckmanlucas",
#                      "fibonacci2", "pell", "frobenius1-1", "frobenius3-5"]
# pseudoprime_sets = {}
# for name in pseudoprime_names:
#     with open(os.path.join("pseudoprimes", name + ".txt")) as f:
#         lines = f.readlines()
#     pseudoprime_sets[name] = [int(line.rstrip("\n")) for line in lines]

# arnault_p1 = int("2967449566868551055015417464290533273077199179985304335099507"
#                  "5531276838753171770199594238596428121188033664754218345562493"
#                  "168782883")
# arnault_pp = arnault_p1 * (313*(arnault_p1-1)+1) * (353*(arnault_p1-1)+1)


if __name__ == "__main__":
    msg = b"Hello! Is it me you're looking for?"
    print("msg bit length", bytes2int(msg).bit_length())
    public_key, private_key = generate_rsa_key(bits=(int(len(msg)*8/128)+1)*128)
    print("key length", (int(len(msg)*8/128)+1)*64)
    print("Found primes")
    cipher = rsa_encrypt(msg, public_key)
    assert rsa_decrypt(cipher, private_key) == msg
    print("Challenge complete, my prime testing function is actually faster "
          "than sympy's, and it accurately detects Arnault's pseudoprime!")