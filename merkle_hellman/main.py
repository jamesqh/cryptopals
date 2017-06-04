import itertools
import math
import random

MULTIPLIER = 2


def get_superincreaser():
    sum = 0
    while True:
        next_term = random.randint(sum + 1, MULTIPLIER * sum + 1)
        sum += next_term
        yield sum


def get_superincreasing_sequence(length):
    superincreaser = get_superincreaser()
    return list(itertools.islice(superincreaser, length))


def generate_key(n):
    w = get_superincreasing_sequence(n)
    q = random.randint(sum(w), MULTIPLIER*sum(w))
    r = q
    while math.gcd(r, q) != 1:
        r = random.randint(2, q)
    B = [r*w_i % q for w_i in w]
    return B, (w, q, r)


def encrypt_message(message, public_key):
    bits = [message >> n & 1 for n in range(message.bit_length())]
    return sum([a_i * B_i for (a_i, B_i) in zip(bits, public_key)])


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


def solve_superincreasing_subset_sum(A, b):
    selectors = []
    for A_i in reversed(A):
        if A_i <= b:
            selectors = [1] + selectors
            b -= A_i
        else:
            selectors = [0] + selectors
    return selectors


def decrypt_cipher(cipher, private_key):
    w, q, r = private_key
    s = modinv(r, q)
    c_ = cipher * s % q
    a = solve_superincreasing_subset_sum(w, c_)
    return sum([a_i * 2**i for (a_i, i) in zip(a, range(len(a)))])


message = random.randint(2**2048, 2**2049)
public, private = generate_key(2*message.bit_length())
c = encrypt_message(message, public)
print(decrypt_cipher(c, private) == message)