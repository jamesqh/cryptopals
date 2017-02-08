import pure_python_gcm.constants as const
from pure_python_gcm.gf2k.defined_fields import GF2_128
from pure_python_gcm.utilities import encrypt_block


def incr(counter_block):
    """Returns int(counter_block) + 1, holding the first four bytes constant."""
    return (counter_block[:-4] + ((int.from_bytes(counter_block[-4:], 'big') + 1
                                   ) % 2**(8*4)).to_bytes(4, 'big'))


def xor(bytes1, bytes2):
    """xor two strings of bytes, dropping bytes from the end of the longer."""
    return bytes([b1 ^ b2 for (b1, b2) in zip(bytes1, bytes2)])


def gcm_pad(assoc_data, cipher):
    """Forms padded string (AD + AD_pad + C + C_pad + length_block) for GCM."""
    c_pad_len, a_pad_len = (16 - len(cipher)) % 16, (16 - len(assoc_data)) % 16
    return (assoc_data + bytes([0]*a_pad_len) + cipher + bytes([0]*c_pad_len)
            + (len(assoc_data)*8).to_bytes(8, 'big')
            + (len(cipher)*8).to_bytes(8, 'big'))


def GHASH(subkey, bytes_string):
    """Calculates Galois hash polynomial per NIST 800-38D."""
    if len(bytes_string) % 16 != 0:
        raise ValueError("Input bytes_string length must be"
                         "an even multiple of 16, not {0}"
                         .format(len(bytes_string)))
    # Split bytes_string into 16-byte blocks.
    blocks = [bytes_string[i:i+16] for i in range(0, len(bytes_string), 16)]
    # Convert bytes key to field element.
    subkey_element = GF2_128.getElementFromBytes(subkey)
    g = GF2_128.zero
    for b in blocks:
        g = g + GF2_128.getElementFromBytes(b)  # field addition
        g = g * subkey_element  # field multiplication
    return g.toBytes()


def GCTR(key, initial_counter_block, bytes_string):
    """Counter mode AES cipher per NIST 800-38D."""
    if len(bytes_string) == 0:
        return bytes_string
    # Split bytes_string into 16-byte blocks.
    blocks = [bytes_string[i:i + 16] for i in range(0, len(bytes_string), 16)]
    out_blocks = []
    counter_block = initial_counter_block
    for block in blocks:
        out_blocks.append(xor(block, encrypt_block(key, counter_block)))
        counter_block = incr(counter_block)
    return b''.join(out_blocks)


def GCM_AE(key, initial_value, plain_text, assoc_data, tag_length=16):
    """GCM authenticated encryption per NIST 800-38D. HAZMAT!"""
    if len(plain_text) > const.PLAINTEXT_MAX_LENGTH:
        raise ValueError("Plaintext exceeds max length {0} bytes"
                         .format(const.PLAINTEXT_MAX_LENGTH))
    if len(assoc_data) > const.ASSOC_DATA_MAX_LENGTH:
        raise ValueError("Associated data exceeds max length {0} bytes."
                         .format(const.ASSOC_DATA_MAX_LENGTH))
    if len(initial_value) < const.IV_MIN_LENGTH:
        raise ValueError("Initialising value doesn't meed minimum length {0}"
                         "bytes".format(const.IV_MIN_LENGTH))
    elif len(initial_value) > const.IV_MAX_LENGTH:
        raise ValueError("Initialising value exceeds max length {0} bytes."
                         .format(const.IV_MAX_LENGTH))
    if tag_length not in const.PERMITTED_TAG_LENGTHS:
        raise ValueError("Tag length {0} bytes not allowed.".format(tag_length))
    subkey = encrypt_block(key, bytes([0]*16))
    if len(initial_value) == 12:
        nonce_block = initial_value + int(1).to_bytes(4, 'big')
    else:
        pad_len = (16 - len(initial_value)) % 16
        nonce_block = GHASH(subkey, initial_value
                            + bytes([0]*(pad_len+8))
                            + len(initial_value).to_bytes(8, 'big'))
    cipher = GCTR(key, incr(nonce_block), plain_text)
    # c_pad_len, a_pad_len = (16 - len(cipher)) % 16, (16 - len(assoc_data)) % 16
    # hash_block = GHASH(subkey, assoc_data + bytes([0]*a_pad_len)
    #                          + cipher + bytes([0]*c_pad_len)
    #                          + len(assoc_data).to_bytes(8, 'big')
    #                          + len(cipher).to_bytes(8, 'big'))
    hash_block = GHASH(subkey, gcm_pad(assoc_data, cipher))
    return cipher, GCTR(key, nonce_block, hash_block)[:tag_length]


def GCM_AD(key, initial_value, cipher, assoc_data, tag, tag_length=16):
    """GCM authenticated decryption mdoe per NIST 800-38D."""
    if (len(tag) != tag_length
        or len(cipher) > const.PLAINTEXT_MAX_LENGTH
        or len(assoc_data) > const.ASSOC_DATA_MAX_LENGTH
        or len(initial_value) < const.IV_MIN_LENGTH
        or len(initial_value) > const.IV_MAX_LENGTH
        or tag_length not in const.PERMITTED_TAG_LENGTHS):
            raise ValueError("Tag failed to validate cipher")
    subkey = encrypt_block(key, bytes([0] * 16))
    if len(initial_value) == 12:
        nonce_block = initial_value + int(1).to_bytes(4, 'big')
    else:
        pad_len = (16 - len(initial_value)) % 16
        nonce_block = GHASH(subkey, initial_value
                            + bytes([0] * (pad_len + 8))
                            + len(initial_value).to_bytes(8, 'big'))
    plain_text = GCTR(key, incr(nonce_block), cipher)
    hash_block = GHASH(subkey, gcm_pad(assoc_data, cipher))
    derived_tag = GCTR(key, nonce_block, hash_block)[:tag_length]
    if tag == derived_tag:
        return plain_text, assoc_data
    else:
        raise ValueError("Tag failed to validate cipher")
