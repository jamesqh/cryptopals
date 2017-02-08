from pure_python_gcm.gf2_polynomials import PolynomialGF2
from .field import GF2k

# GF(2^128), defined by x^128 + x^7 + x^2 + x + 1
GF2_128 = GF2k(128, PolynomialGF2((7 + (1 << 7) + (1 << 128))))
