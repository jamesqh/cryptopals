from pure_python_gcm.utilities import print_polynomial


class PolynomialGF2:
    """Represents a polynomial with coefficients in GF(2).

    Internally represents the polynomial as an integer,
    using the convention that the least significant bit
    represents the coefficient of the x^0 term and so on.
    All meaningful arithmetic operators overridden
    """
    def __init__(self, bitrep):
        self.bitrep = bitrep

    def __repr__(self):
        coefs = {deg: (self.bitrep & 2**deg)//2**deg
                 for deg in range(self.deg() + 1)}
        coefs = {key: val for key, val in coefs.items() if val != 0}
        return print_polynomial(coefs, 0, 1)

    def __eq__(self, other):
        """Polynomial equality. No awareness of equivalent types."""
        return isinstance(other, type(self)) and self.bitrep == other.bitrep

    def __add__(self, other):
        """Add two polynomials together.

        Addition in GF(2) is just xor.
        """
        return self.__class__(self.bitrep ^ other.bitrep)

    def __radd__(self, other):
        """Add two polynomials together.

        Addition is commutative in this ring."""
        return self + other

    def __neg__(self):
        """Return the additive inverse of a polynomial.

        f ^ f == 0 so additive inverse of f is f.
        """
        return self

    def __sub__(self, other):
        """Subtract one polynomial from another.

        Subtraction is just xor as well, but we'll defer.
        """
        return self + -other

    def __rsub__(self, other):
        """Subtract one polynomial from another."""
        return other + -self

    def __mul__(self, other):
        """Multiply two polynomials.

        We use a clever bitshifting algorithm to find the product
        of each pair of terms.
        """
        a, b, p = self.bitrep, other.bitrep, 0
        # At each step we use a >> 1 to drop the rightmost term of a,
        # Then leftshift b << 1 to "keep both sides equal".
        # Essentially at each step we set a = a/x and b = b*x.
        # So the algo is basically: while we haven't dropped all terms of a
        # If the rightmost term of a is nonzero, add b to the result
        # Then drop the rightmost term of a, multiply b by x to compensate
        # Which is a smart way to do: for each term of a from right to left,
        # Add term * b to result.
        while a > 0:
            if a & 1:
                p = p ^ b
            a = a >> 1
            b = b << 1
        return self.__class__(p)

    def __rmul__(self, other):
        """Multiply two polynomials.

        Multiplication is commutative in this ring.
        """
        return self * other

    def __divmod__(self, other):
        """Euclidean division of polynomials.

        Returns:
            q, r such that self = q*other + r
        """
        # Define local deg function
        # So we don't have to promote intermediate results to objects
        def _deg(n):
            if n == 0:
                return -1
            else:
                return n.bit_length() - 1
        # Basically implementing https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FPolynomial_greatest_common_divisor%23Euclidean_division
        # With the simplification that leading coefficients are always 1
        # Because the only other element is 0!
        # Remember xor is addition and subtraction
        # (1 << d) creates polynomial x^d
        # and (b << d) multiplies b by that polynomial
        q, r, b = 0, self.bitrep, other.bitrep
        while _deg(r) >= _deg(b):
            d = _deg(r) - _deg(b)
            q = q ^ (1 << d)
            r = r ^ (b << d)
        return self.__class__(q), self.__class__(r)

    def __floordiv__(self, other):
        """Floor division of polynomials, using q of divmod."""
        q, _ = divmod(self, other)
        return q

    def __rfloordiv__(self, other):
        """Floor division of polynomials, using q of divmod."""
        q, _ = divmod(other, self)
        return q

    def __mod__(self, other):
        """Polynomial modulo, using r of divmod."""
        _, r = divmod(self, other)
        return r

    def modmul(self, other, modulo):
        """Multiplication of polynomials mod some other polynomial.

        If f and g have the same degree, f % g = f - g = f ^ g.
        We use this to interleave modulo with multiplication,
        using the same algorithm as __mul__.
        """
        # Local def function for bitreps
        def _deg(n):
            if n == 0:
                return -1
            else:
                return n.bit_length() - 1
        # If a or b are bigger than modulo, we need to do explicit mod first
        if self.deg() >= modulo.deg():
            self = self % modulo
        if other.deg() >= modulo.deg():
            other = other % modulo
        a, b, p, m = self.bitrep, other.bitrep, 0, modulo.bitrep
        while a > 0:
            if a & 1:
                p = p ^ b
            a = a >> 1
            b = b << 1
            if _deg(b) == _deg(m):
                b = b ^ m  # modulo step, works because deg(b) <= deg(m)
        return self.__class__(p)

    def __pow__(self, power, modulo=None):
        """Exponentiation of polynomial multiplication with optional mod.

        Uses a square and multiply algorithm and a modulo-aware mul function.
        """
        # Locally define mul function based on whether it needs to be modulo
        if modulo is None:
            def mul(a, b): return a * b
        else:
            def mul(a, b): return a.modmul(b, modulo)
        register, result = self, self.__class__(1)
        while power > 0:
            if power % 2 == 1:
                result = mul(result, register)
            register = mul(register, register)
            power = power >> 1
        return result

    def deg(self):
        """Degree of the polynomial."""
        if self.bitrep == 0:
            return -1
        else:
            return self.bitrep.bit_length() - 1

    def extended_euclidean(self, other):
        """Polynomial extended Euclidean algorithm. Returns GCD and Bezouts.

        If a, b = self, other then extended_euclidean calculates and returns:
        r, s, t such that r = gcd(a, b) and r = a*s + b*t.
        If r == 1 then s is the inverse of a modulo b.
        """
        zero, one = self.__class__(0), self.__class__(1)
        s, s_ = zero, one
        t, t_ = one, zero
        r, r_ = other, self
        while r.deg() != -1:
            quotient = r_//r
            r_, r = r, r_ - quotient * r
            s_, s = s, s_ - quotient * s
            t_, t = t, t_ - quotient * t
        return r_, s_, t_

    def gcd(self, other):
        """Polynomial GCD of self and other."""
        gcd_, _, _ = self.extended_euclidean(other)
        return gcd_

    def modinv(self, other):
        """Returns inverse mod other, such that self*inverse == 1 mod other.

        Uses extended Euclidean.
        """
        gcd_, s, _ = self.extended_euclidean(other)
        if gcd_ == self.__class__(1):
            return s
        else:
            raise ArithmeticError("No inverse in {0} for {1}"
                                  ".format(other, self")
