from random import randint

from pure_python_gcm.gf2k import GF2kElement
from pure_python_gcm.utilities import reverse_bits


class GF2k:
    def __init__(self, k, P, element_class=GF2kElement):
        if P.deg() != k:
            raise ValueError("Defining polynomial must have degree {0}: {1}"
                             .format(k, P))
        self.P = P
        self.k = k
        self.element_class = element_class
        self.zero = self.getElement(0)
        self.one = self.getElement(1)

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.k == other.k

    def getElement(self, value):
        return self.element_class(value, self)

    def getRandomElement(self):
        return self.getElement(randint(0, 2**self.k))

    def getElementFromBytes(self, byte_block):
        """Convert a byte string into a field element.

        Uses the convention that the first bit in the string corresponds
        to the coefficient of the x^0 term.
        For GF(2^k), will accept blocks of length ceil(k/8) bytes.
        But if k is not a multiple of 8, the final byte must end with
        an appropriate number of zeros.
        ie there must be only k significant bits.
        All of this is irrelevant for the basic use case of 2^128: 16 bytes.
        """
        val = int.from_bytes(bytes([reverse_bits(byte) for byte in byte_block])
                             , 'little')
        if val.bit_length() > self.k:
            raise ValueError("Byte block must have only {0} significant bits"
                             .format(self.k))
        return self.getElement(val)
