# Pure Python GCM

Basic implementation of the AES-128-GCM (Galois Counter Mode) authenticated encryption standard.

## Code example

```py
from pure_python_gcm import encrypt, decrypt

## Feed bytes directly into the function
key = b'YELLOW SUBMARINE'
text = b'Whatever message you want to encrypt, of any length, including 0. No padding necessary.'
assoc_data = b'Optionally include additional data, which will not be encrypted but will be authenticated.'

cipher, assoc_data, tag, iv = encrypt(key, text, assoc_data)

## Send that package to another party who knows the key...

try:
    text, assoc_data = decrypt(key, cipher, assoc_data, iv, tag)
    print("Decrypted message:", text)
    print("Authenticated additional message:", assoc_data)
except ValueError:
    print("Could not validate with supplied parameters.")

## You can also use regular strings for key OR text OR assoc_data
## The function will encode them to bytes using utf-8 by default, but you can specify your preferred encoding.
text = "Like this"
cipher, assoc_data, tag, iv = encrypt(key, text, assoc_data, encoding="ascii")

## Decoding from bytes to strings is the responsibility of whoever is receiving the message.
```

## About

I wanted to implement GCM as part of a [cryptopals](https://cryptopals.com/) challenge. The bare bones of the algorithm are quite simple, but some of the details are a bit strange. I wanted to confirm my code's validity by matching a reference implementation, and that turned out to be quite a chore, in no small part because the reference implementations I found were mostly either dense, confusing C code or beautifully Pythonic ways to import GCM from a module written in dense, confusing C code. In the end I just followed the [NIST specification](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) as I should have from the start, but those documents are never as clearly unambiguous as working code is, in my experience. And this one in particular is hamstrung by the insistence of the writer on treating the data as strings of bits, rather than bytes.

So that's what this is, for anybody who might find it helpful. A (hopefully) transparent and correct implementation of GCM to serve as a reference for any of the details of the algorithm you might be unclear on - what order the bits are in (it's the wrong one), whether the length block counts bits or bytes, how the counter works, or anything else. All imports are from the Python standard library, except those for a function that AES encrypts one block of bytes.

It is **not** meant to be used to actually encrypt anything you care about. The functions enforce the constraints recommended by NIST, and the user-facing encryption generates its own IV with ```os.urandom()```, which is meant to be suitable for cryptography, rather than allowing you to set the IV, because if you use the same key and IV pair *one time* an attacker who recovers those messages can completely compromise that key pretty trivially. But I'm not a professional, attackers can be very clever, there could easily be a timing attack or some other kind of side channel leak, or some fundamental break somewhere that I haven't spotted. It's always better to use a library written by a group of people who know what they're doing and which is heavily scrutinised for faults.

It also won't be nearly as fast as such a library.

## Installation

You aren't really meant to - see above. But if you insist, you can install it the old fashioned way - copy the directory pure_python_gcm to the location of a script, or into the Python module search path, and do ```import pure_python_gcm```

## Dependencies

['''cryptography'''](https://pypi.python.org/pypi/cryptography) - Only necessary for single-block AES encryption in ```utilities.py```, should be easy to refactor to your choice.

## A word on polynomials

GCM works by representing blocks of data as elements of GF(2^128), the finite field with 2^128 elements. The most natural way to represent those elements is as polynomials with coefficients in GF(2) (that is, the integers modulo 2: 0 and 1) and degree strictly less than 128. Addition is then simply polynomial addition, and multiplication is polynomial multiplication modulo some 128 degree irreducible polynomial. Such a polynomial is completely defined by a series of 128 1s and 0s - I hope you see the obvious connection.

NIST's writer does this conversion implicitly - he simply splits his data into strings of 128 bits, then uses XOR to do field addition, and a recursively defined function on the bitstrings and their least significant bits to do field multiplication, hardcoding the field's defining polynomial into the function.

I think this is quite ugly, and have defined Python objects to represent these field elements and their corresponding field, and to handle conversion to and from 16 byte blocks. With my object ```GF2_128``` representing the field GF(2^128), I can generate a field element f or g or h with ```f = GF2_128.getElementFromBytes(b'YELLOW SUBMARINE'```, do field addition and multiplication with just ```f + g * h```, and convert back to bytes with ```f.toBytes()```.

The algorithms hidden behind these objects are, nonetheless, almost identical to the ones NIST describes. You may prefer his approach.

This means this code could be easily refactored to use a different field for a cipher with a different blocksize, as long as that blocksize is suitable for GCM - its length in bits a power of 2. 64, 256, 512, the possibilities are endless! Just means using a different ```GF2k``` field object.

Anyway, that means this package comes with a couple of bonus modules. **Most of this is not necessary to understand GCM.** GCM needs only field addition and field multiplication, which are the ```__add__``` and ```__mul__``` methods of ```GF2kElement``` instances. Along with the conversions to and from bytes, obviously.

```pure_python_gcm.gf2_polynomials``` lets you generate and do arithmetic on polynomials with coefficients in GF(2), using an underlying representation of them as binary integers with the least significant bit representing the coefficient of the x^0 term, the second least for the coefficient of the x^1 term, and etc. If you have a representation of a polynomial as a dictionary of coefficients keyed by the degrees of their corresponding terms, you can turn that into a ```gf2_polynomials.PolynomialGF2``` with ```PolynomialGF2(sum([coef*2**deg for (deg, coef) in poly.items()])```, as an example.

```pure_python_gcm.gf2k``` is a module that uses ```PolynomialGF2``` instances to represent elements of a finite field GF(2^k). The main party trick here is that ```*``` and ```**``` and ```pow``` implicitly do multiplication or exponentiation modulo the defining irreducible polynomial for the field in question, but the elements also come equipped with an ```__invert__``` method (```f.__invert()__``` is aliased by ```~f```) that returns the multiplicative inverse of the element's polynomial modulo the field's defining polynomial, hence allowing division (```f/g = f * ~g```) in the field, as long as the element is non-zero.

```gf2k.GF2kElement``` instances, representing field elements, are generated from a ```gf2k.GF2k``` field object instantiated with (if you want GF(2^k) for some fixed k) ```GF2_k = GF2k(k, P)``` where ```P``` is a ```PolynomialGF2``` representing some irreducible polynomial of degree k. You're on your own finding those polynomials, I'm afraid. Once the field is instantiated you can get elements with ```GF2_k.getElement(e)``` where ```e``` is either a ```PolynomialGF2``` of degree less than k, or an ```int``` representative as described above (and less than 2^k). You can also generate random elements with ```GF2_k.getRandomElement()``` or generate elements from blocks of log2(k) bytes with ```GF2_k.getElementFromBytes(block)```

If this code is helpful for reasons unrelated to GCM, I am delighted and you are welcome to it!