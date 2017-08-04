"""Cryptopals set 6 challenge 47: Bleichenbacher's RSA padding oracle
Ladies and gentlemen... fasten your seatbelts.
Cryptopals assert that "Your step 3 code is probably not going to need to
handle multiple ranges." All of my experiments suggest that that is false.
And implementing multiple ranges isn't that hard anyway, the interval unionising
is fun. So I do it the proper way here as well as in 48 and the code is
identical except for the size of the modulus.

With a strong oracle and pseudo-random padding, execution times can be
wildly variable. If possible gmpy2 will be used for the RSA exponentiation
in the oracle, which is twice as fast as native pow(), and usually it's about
2 minutes for a 256 bit keypair. But perverse cases could take a long time."""

from os import urandom
from random import randint

from challenges.set5.challenge39 import (rsa_decrypt, rsa_encrypt, int2bytes,
                                         bytes2int, generate_rsa_key, modinv)


try:
    from gmpy2 import mpz

    def fast_rsa_encrypt(text_int, public_key):

        return pow(mpz(text_int), mpz(public_key.key), mpz(public_key.modulo))

    def fast_rsa_decrypt(cipher_int, private_key):

        return int2bytes(int(pow(mpz(cipher_int), mpz(private_key.key), mpz(private_key.modulo))))

except ImportError:
    print("gymp2 not found, reverting to slow native exponentiation for oracle.")
    print("You really should have gmpy2!")
    fast_rsa_encrypt = rsa_encrypt
    fast_rsa_decrypt = rsa_decrypt


class IntervalUnion:
    def __init__(self):
        self.intervals = set()

    def __len__(self):
        return len(self.intervals)

    def add_interval(self, new_interval):
        overlap = None # no overlapping interval we know of
        for interval in self.intervals:
            if self.contains(interval, new_interval):
                return # if candidate is contained within an existing interval
                       # we can just do nothing and return
            if not overlap: # if no overlapping interval found yet
                union = self.union_two_intervals(interval, new_interval)
                if union is not None: #check whether this is one and record it
                    overlap = interval
        if overlap is None: # if we didn't find an overlap in all intervals
            self.intervals.add(new_interval) # the new interval is disjoint
            return # with all and we can simply add it and return
        else:
            # otherwise we remove the overlapped interval and add the
            # union of the overlapped and the candidate as a new interval
            # going through the same function as above
            union = self.union_two_intervals(overlap, new_interval)
            self.intervals.remove(overlap)
            self.add_interval(union)
            return

    def union_two_intervals(self, interval0, interval1):
        a0, a1 = interval0
        b0, b1 = interval1
        if a1 < b0 or b1 < a0:
            return None
        else:
            return (min(a0, b0), max(a1, b1))

    def contains(self, outset, inset):
        a0, a1 = outset
        b0, b1 = inset
        if a0 <= b0 and a1 >= b1:
            return True
        else: return False

    def __iter__(self):
        return iter(self.intervals)

    def __repr__(self):
        return "IntervalUnion({0})".format(self.intervals)


class RSAPaddingOracle:
    def __init__(self, bits=1024):
        self.public, self.private = generate_rsa_key(bits)
        self.message_len = ((self.public.modulo.bit_length()-1)//8)+1

    def encrypt_message(self, message):
        return rsa_encrypt(message, self.public)

    def strong_padding_oracle(self, cipher):
        """This oracle checks that the padding exists, is of sufficient length
        and that it terminates with a zero byte."""
        plain_bytes = fast_rsa_decrypt(cipher, self.private)
        padded_bytes = b'\x00'*(self.message_len-len(plain_bytes)) + plain_bytes
        return (padded_bytes.startswith(b'\x00\x02')
                and b'\x00' not in padded_bytes[2:10]
                and b'\x00' in padded_bytes[10:])

    def weak_padding_oracle(self, cipher):
        """This oracle simply checks that the padding starts correctly.
        It doesn't ensure that it ends, so there might be no message at all.
        Just padding."""
        plain_bytes = fast_rsa_decrypt(cipher, self.private)
        padded_bytes = b'\x00'*(self.message_len-len(plain_bytes)) + plain_bytes
        return (padded_bytes.startswith(b'\x00\x02'))

    def padding_oracle(self, cipher):
        """Function that points towards the strong or weak padding oracle.
        Attack should work with both, but is significantly faster with
        a weak oracle."""
        return self.strong_padding_oracle(cipher)


def pkcs_1_5_pad(data, modulus):
    k = ((modulus.bit_length()-1)//8)+1
    assert 2**(8*k - 8) <= modulus < 2**(8*k)
    if len(data) > k - 11:
        raise ValueError("Data too long for given modulus")
    padding_string = urandom(k-3-len(data))
    def zero_replacer(x):
        if x == 0:
            return randint(1, 255)
        else:
            return x
    padding_string = bytes(map(zero_replacer, padding_string))

    # PKCS 1.5 intends use of pseudorandomly generated non-zero octets
    # as padding. But for testing purposes we might want our padded message
    # to be consistent each execution. Easiest way to do that is to uncomment
    # the following line.

    # padding_string = b'\xff'*len(padding_string)
    return bytes([0, 2]) + padding_string + bytes([0]) + data


def ceiling_division(numerator, denominator):
    """Fast integer-based ceiling division."""

    # We want ceil(a/b). This is clearly a//b + 1, except for when a%b = 0,
    # when ceil and floor should be the same. So if we can find f such that
    # f(a, b) = a//b when a%b != 0 and f(a, b) = a//b - 1 when a%b = 0,
    # we can just use f(a, b) + 1.
    # (a-1)//b is suitable - it is unchanged from a//b
    # except if a%b = 0, when the subtraction pushes us over the
    # floor division boundary to a//b - 1. Hence ceil(a/b) = (a-1)//b + 1.

    return ((numerator-1)//denominator) + 1

def step1(e, n, c, B, oracle):
    s = 1
    while not oracle.padding_oracle((c * pow(s, e, n)) % n):
        s = randint(2, n-1)
    return s

def step_2ab(e, n, c, B, oracle, last_s=None):
    if last_s is None:
        last_s = n//(3*B)
    s = last_s + 1
    while not oracle.padding_oracle((c * pow(s, e, n)) % n):
        s += 1
    return s


def step_2c(e, n, c, B, oracle, last_s, M):
    assert len(M) == 1
    a, b = list(M)[0]
    r = 2*ceiling_division(b*last_s - 2*B, n)
    while True:
        for s in range(ceiling_division(2*B + r*n, b),
                       ceiling_division(3*B + r*n, a)):
            if oracle.padding_oracle((c * pow(s, e, n)) % n):
                return s
        r += 1


def step3(e, n, s, B, M):
    new_M = IntervalUnion()
    for a, b in M:
        for r in range(ceiling_division(a * s - 3 * B + 1, n),
                       (b * s - 2 * B) // n + 1):
            new_M.add_interval((max(a, ceiling_division(2*B + r*n, s)),
                  min(b, (3*B - 1 + r*n)//s)))
    return new_M


def bleichenbacher_attack(c, oracle):
    k = oracle.message_len
    e, n = oracle.public
    B = 2 ** (8 * (k - 2))
    M = IntervalUnion()
    M.add_interval((2 * B, 3 * B - 1))
    s0 = step1(e, n, c, B, oracle)
    s = None
    c = c * pow(s0, e, n) % n
    while len(M) > 1 or abs(list(M)[0][0] - list(M)[0][1]) >= 1:
        if s is None or len(M) > 1:
            s = step_2ab(e, n, c, B, oracle, s)
        else:
            s = step_2c(e, n, c, B, oracle, s, M)
        M = step3(e, n, s, B, M)
    a, b = list(M)[0]
    return a * modinv(s0, n) % n


if __name__ == "__main__":
    import time
    oracle = RSAPaddingOracle(128)
    true_message = pkcs_1_5_pad(b'kick it, CC', oracle.public.modulo)
    c = oracle.encrypt_message(true_message)
    start = time.time()
    decrypted_message = bleichenbacher_attack(c, oracle)
    end = time.time()
    print(int2bytes(decrypted_message))
    assert decrypted_message == bytes2int(true_message)
    print("Challenge complete in {0} seconds".format(round(end - start, 2)))