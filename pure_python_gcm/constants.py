

PLAINTEXT_MAX_LENGTH = (2**39 - 256)//8
ASSOC_DATA_MAX_LENGTH = (2**64 - 1)//8
IV_MIN_LENGTH = 1
IV_MAX_LENGTH = (2**64 - 1)//8
PERMITTED_TAG_LENGTHS = [bit_length//8 for bit_length in (128, 120, 112, 104, 96)]
