from pure_python_gcm.gf2k.defined_fields import GF2_128


def get_random_element():
    return GF2_128.getRandomElement()

zero = GF2_128.getElement(0)
one = GF2_128.getElement(1)
a = get_random_element()
b = get_random_element()
c = get_random_element()


class TestPolynomialArithmetic:
    def test_addition_identity(self):
        assert zero + a == a

    def test_addition_commutative(self):
        assert a + b == b + a

    def test_addition_associative(self):
        assert (a + b) + c == a + (b + c)

    def test_multiplication_identity(self):
        assert a * one == a

    def test_multiplication_commutative(self):
        assert a*b == b*a

    def test_multiplication_associative(self):
        assert (a*b)*c == a*(b*c)

    def test_distributivity(self):
        assert a*(b+c) == a*b + a*c
        assert (a+b)*c == a*c + b*c

    def test_zero_property(self):
        assert zero * a == zero

    def test_additive_inverse(self):
        assert a - a == a + -a == zero

    def test_square(self):
        assert a**2 == a*a

    def test_cube(self):
        assert a**3 == a*a*a
