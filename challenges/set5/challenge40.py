"""Cryptopals set 5 challenge 40: Implement an e=3 RSA broadcast attack."""

from functools import reduce
from operator import mul

from challenges.common_functions import (rsa_encrypt, generate_rsa_key, gcd,
                                         modinv, int2bytes)

try:
    from gmpy2 import mpz
except ImportError:
    mpz = int
    print("gymp2 not found, integer cube root will be much slower.")
    print("You really should have gmpy2!")


def rounded_integer_division(a, b):
    floordiv, remainder = divmod(a, b)
    if remainder >= (b >> 1):
        return floordiv + 1
    else:
        return floordiv


def integer_cube_root(a):
    # Binary search is easy and surprisingly fast for even very large numbers.
    if a == 0 or a == 1:
        return a
    a = mpz(a)
    high = mpz(2)
    tmp = high**3
    while tmp < a:
        high <<= 1
        tmp = high**3
    low = high >> 1
    mid = None # just to placate the machine
    while low < high:
        mid = rounded_integer_division(low + high, 2)
        tmp = mid**3
        if low < mid and tmp < a:
            low = mid
        elif mid < high and tmp > a:
            high = mid
        else:
            break
    return int(mid)

def chinese_remainder_solve(congruences):
    N = reduce(mul, [modulo for soln, modulo in congruences], 1)
    assert all([gcd(soln, N) == 1 for soln, modulo in congruences])
    crt_sum = sum([soln * N//modulo * modinv(N//modulo, modulo)
                   for soln, modulo in congruences])
    return crt_sum % N


if __name__ == "__main__":
    msg = (b"I'm a bright white egg and I incubate "
           b"in a warm yellow light in the winter")
    prime_size = (int(len(msg)*8/128)+1)*64
    keys = [generate_rsa_key(prime_size)[0] for _ in range(3)]
    ciphers = [rsa_encrypt(msg, key) for key in keys]
    congruences = [(cipher, key.modulo) for cipher, key in zip(ciphers, keys)]
    decrypted_msg = int2bytes(integer_cube_root(
        chinese_remainder_solve(congruences)))
    print(decrypted_msg)
    assert decrypted_msg == msg
    print("Challenge complete")