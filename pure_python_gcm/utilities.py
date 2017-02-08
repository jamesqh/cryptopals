import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def print_polynomial(coefs, zero, one, letter="x"):
    """Convert a polynomial in dict form to a pretty string.

    Takes the zero and one of the coefficient ring of the polynomial
    as parameters.
    """
    if len(coefs.keys()) == 0:
        return "0"
    str_coefs = {}
    for deg, coef in coefs.items():
        if coef == zero:
            continue
        if coef == one and deg > 0:
            str_coefs[deg] = ""
        elif coef == one and deg == 0:
            str_coefs[deg] = str(one)
        else:
            str_coefs[deg] = str(coef)
    out = " + ".join(["{0}{1}^{2}".format(str_coefs[deg], letter, deg)
                      for deg in sorted(str_coefs.keys(), reverse=True)])
    out = " " + out + " "
    deg1 = re.compile(re.escape(letter) + r'\^1 ')
    deg0 = re.compile(re.escape(letter) + r'\^0 ')
    minus = re.compile(r"\+ -")
    out = deg1.sub(letter + " ", out)
    out = deg0.sub(" ", out)
    out = minus.sub("- ", out)
    out = out.strip(" ")
    return out


def reverse_bits(n):
    """Function to invert endianness of one byte on a bit level.

    Uses clever bit magic, swapping half of the bits at each step.
    """
    # 1234|5678 -> 5678|1234
    n = (n & 0xF0) >> 4 | (n & 0x0F) << 4
    # 56|78|12|34 -> 78|56|34|12
    n = (n & 0xCC) >> 2 | (n & 0x33) << 2
    # 7|8|5|6|3|4|1|2 -> 8|7|6|5|4|3|2|1
    n = (n & 0xAA) >> 1 | (n & 0x55) << 1
    return n


def encrypt_block(key, block):
    """Primitive function to AES encrypt one block."""
    if len(block) != 16:
        raise ValueError("encrypt_block only works on single 16 byte blocks")
    if len(key) != 16:
        raise ValueError("encrypt_block only uses a 16 byte key")
    encryptor = Cipher(algorithms.AES(key), modes.ECB(),
                       backend=default_backend()).encryptor()
    return encryptor.update(block) + encryptor.finalize()
