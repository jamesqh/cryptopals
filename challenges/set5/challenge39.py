"""Cryptopals set 5 challenge 39: Implement RSA.
I'm gonna implement Baillie-PSW primegen because RSA on its own is hardly fun"""

import math

from pdb import set_trace

primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
          67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
          139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
          223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
          293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
          383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
          463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541]


def baillie_psw(candidate, trial_division_limit=541):
    if candidate == 2:
        return True
    for prime in [x for x in primes if x <= trial_division_limit]:
        if candidate % prime == 0:
            print("trial division false")
            return False
    if not strong_fermat_test(candidate):
        print("fermat false")
        return False

    def find_jacobi_thing(candidate):
        for i in range(100):
            if jacobi((-1)**i * (5 + 2*i), candidate) == -1:
                return i
        for i in range(int(math.sqrt(candidate))):
            if i**2 == candidate:
                print("a sqrt")
                raise RuntimeError
        print("not a sqrt but didn't find")
    try:
        i = find_jacobi_thing(candidate)
    except RuntimeError as e:
        print(e)
        print("impossible false")
        return False
    D = (-1)**i * (5 + 2*i)
    P = 1
    Q = (1 - D) // 4
    if lucas_test(candidate, D, P, Q):
        return True
    else:
        print("lucas false")
        return False


def strong_fermat_test(candidate, base=2):
    n = candidate
    a = base
    # register = n - 1
    # s = 0
    # while register % 2 == 0:
    #     register >>= 1
    #     s += 1
    # d = (n - 1) // 2**s
    d, s = power_2_factor(n-1)
    if pow(a, d, n) == 1:
        return True
    for r in range(s):
        if pow(a, d*2**r, n) == -1 % n:
            return True
    return False


def lucas_test(candidate, D, P, Q):
    set_trace()
    assert D == P**2 - 4*Q
    assert gcd(candidate, Q) == 1, (Q, gcd(candidate, Q))
    n = candidate
    delta_n = n - jacobi(D, n)
    U_delta_n, _ = get_Un_and_Vn(delta_n, P, Q)
    if U_delta_n % candidate == 0:
        return True
    return False


lucas = {}


def get_Un_and_Vn(n, P, Q):
    try:
        lucas_PQ = lucas[(P, Q)]
    except KeyError:
        # lucas_PQ = {"U": {0: 0, 1: 1},
        #             "V": {0: 2, 1: P}}
        lucas_PQ = {0: (0, 2), 1: (1, P)}
        lucas[(P, Q)] = lucas_PQ
    try:
        return lucas_PQ[n]
    except KeyError:
        if n % 2 == 0:
            half_n = n >> 1
            U_half_n, V_half_n = get_Un_and_Vn(half_n, P, Q)
            U_n = U_half_n * V_half_n
            V_n = V_half_n**2 -2*Q**half_n
            lucas_PQ[n] = (U_n, V_n)
            return lucas_PQ[n]
        else:
            n_minus_1 = n - 1
            U_n_minus_1, V_n_minus_1 = get_Un_and_Vn(n_minus_1, P, Q)
            U_n = (P*U_n_minus_1 + V_n_minus_1)//2
            V_n = ((P**2 - 4*Q)*U_n_minus_1 + P*V_n_minus_1)//2
            lucas_PQ[n] = (U_n, V_n)
            return lucas_PQ[n]

# TODO: THIS JACOBI SYMBOL IS MESSED UP
def jacobi(a, n):
    a = a % n
    if a == 0:
        return 0
    if a == -1 % n:
        if n == 1 % 4:
            return 1
        if n == 3 % 4:
            return -1
    if a == 2 % n:
        if n == 1 % 8 or n == 7 % 8:
            return 1
        if n == 3 % 8 or n == 5 % 8:
            return -1
    if a == 1:
        return 1
    if gcd(a, n) != 1:
        return 0
    n, s = power_2_factor(n)  # such that old_n = n * 2**s
    if s != 0:
        return jacobi(2, n) ** s * jacobi(a, n)
    else:
        return jacobi(n, a)


def gcd(a, n):
    while n != 0:
        t = n
        n = a % n
        a = t
    return abs(a)


def power_2_factor(n):
    s = 0
    while n % 2 == 0:
        n >>= 1
        s += 1
    return n, s


assert baillie_psw(11, trial_division_limit=1)

for prime in primes:
    assert baillie_psw(prime, trial_division_limit=1), prime