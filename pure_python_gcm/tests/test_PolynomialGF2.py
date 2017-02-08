from random import randint

from pure_python_gcm.gf2_polynomials import PolynomialGF2

def get_random_element():
    return PolynomialGF2(randint(0, 2**128))


zero = PolynomialGF2(0)
one = PolynomialGF2(1)
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

    def test_divmod(self):
        q, r = divmod(a, b)
        assert a == q*b + r
        assert b.deg() > r.deg()

    # can't decide if this should work or not
    # def test_mod_one(self):
    #     assert a % one == one

    def test_ext_euclid(self):
        r, s, t = a.extended_euclidean(b)
        assert r == s*a + t*b

    def test_modsquare(self):
        a_, b_ = a, b
        if a.deg() >= b.deg():
            a_, b_ = b_, a_
        assert a_**2 % b_ == pow(a_, 2, b_)
