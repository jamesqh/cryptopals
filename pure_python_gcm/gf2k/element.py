from pure_python_gcm.gf2_polynomials import PolynomialGF2
from pure_python_gcm.utilities import reverse_bits


class GF2kElement:
    """Wrapper class for a PolynomialGF2 representing an element in GF(2^k).

    Uses a parent GF2k field object to track an irreducible polynomial P
    to use as a modulo parameter in order to turn multiplication into
    multiplication within the field GF(2^k).
    Also uses the field object to generate new elements.
    All arithmetic other than modulo is deferred to PolynomialGF2.
    """
    def __init__(self, value, field):
        # We may occasionally want to get a new element direct from a bitrep.
        # Hence we test for the type of the initialising value and handle it.
        if isinstance(value, PolynomialGF2):
            self.poly = value
        elif isinstance(value, int):
            if value >= 2**field.k:
                raise ValueError("Initialising element too large to be an"
                                 "element of GF(2^{0}".format(field.k))
            self.poly = PolynomialGF2(value)
        else:
            raise ValueError("Initialising value not understood: {0}"
                             .format(value))
        self.field = field

    def __repr__(self):
        return self.poly.__repr__()

    def __eq__(self, other):
        """Equality of field elements.

        Field elements are equal only if their parent field objects
        and their underlying polynomials are equal.
        """
        return self.field == other.field and self.poly == other.poly

    def __add__(self, other):
        """Add field elements.

        Addition needs no special handling, we simply defer to PolynomialGF2k
        and promote the result to a field element.
        """
        return self.field.getElement(self.poly + other.poly)

    def __radd__(self, other):
        """Add field elements.

        Addition is commutative.
        """
        return self + other

    def __neg__(self):
        """Additive inverse of a field element is the element itself."""
        return self

    def __sub__(self, other):
        """Subtract one field element from another.

        Equivalent to addition, but we'll defer.
        """
        return self + -other

    def __rsub__(self, other):
        """Subtract one field element from another.

        Equivalent to addition, but we'll defer.
        """
        return other + -self

    def __mul__(self, other):
        """Multiplication of field elements.

        Here we ask the parent field object for the defining polynomial
        and do multiplication mod that.
        """
        return self.field.getElement(self.poly.modmul(other.poly, self.field.P))

    def __rmul__(self, other):
        """Multiplication of field elements.

        Multiplication is commutative.
        """
        return self * other

    def __pow__(self, power):
        """Exponential of field multiplication.

        We defer to PolynomialGF2k __pow__ with modulo P.
        """
        return self.field.getElement(pow(self.poly, power, self.field.P))

    def __invert__(self):
        """Multiplicative inverse of this element.

        PolynomialGF2k has a method for this using extended Euclidean.
        """
        return self.field.getElement(self.poly.modinv(self.field.P))

    def __truediv__(self, other):
        """Division: a/b == a * b^-1."""
        return self * ~other

    def __rtruediv__(self, other):
        """Division: a/b == a * b^-1."""
        return other * ~self

    def toBytes(self):
        """Return element as a block of ceil(k/8) bytes.

        Uses the convention that the leftmost bit of the bytestring
        represents the coefficient of the x^0 term.
        """
        return bytes([reverse_bits(byte)
                      for byte in self.poly.bitrep.to_bytes(
                        int(self.field.k/8), 'little')])
