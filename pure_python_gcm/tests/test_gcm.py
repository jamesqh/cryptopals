from binascii import unhexlify

from pure_python_gcm.aes_gcm_128 import GCM_AE, GHASH, gcm_pad
from pure_python_gcm.utilities import encrypt_block


def test_54_byte_packet_authentication():
    k = unhexlify("AD7A2BD03EAC835A6F620FDCB506B345")
    p = b''
    a = unhexlify("D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E810800"
                  "0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C"
                  "2D2E2F30313233340001")
    iv = unhexlify("12153524C0895E81B2C28465")
    H = encrypt_block(k, bytes([0]*16))
    ghash = GHASH(H, gcm_pad(a, p))
    c, tag = GCM_AE(k, iv, p, a)
    assert H == unhexlify("73A23D80121DE2D5A850253FCF43120E")
    assert ghash == unhexlify("1BDA7DB505D8A165264986A703A6920D")
    assert c == b''
    assert tag == unhexlify("F09478A9B09007D06F46E9B6A1DA25DD")


def test_60_byte_packet_encryption():
    k = unhexlify("AD7A2BD03EAC835A6F620FDCB506B345")
    p = unhexlify("08000F101112131415161718191A1B1C1D1E1F202122232425262728292A"
                  "2B2C2D2E2F303132333435363738393A0002")
    a = unhexlify("D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81")
    iv = unhexlify("12153524C0895E81B2C28465")
    H = encrypt_block(k, bytes([0] * 16))
    c, tag = GCM_AE(k, iv, p, a)
    ghash = GHASH(H, gcm_pad(a, c))
    assert H == unhexlify("73A23D80121DE2D5A850253FCF43120E")
    assert ghash == unhexlify("A4C350FB66B8C960E83363381BA90F50")
    assert c == unhexlify("701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C993"
                          "1DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D")
    assert tag == unhexlify("4F8D55E7D3F06FD5A13C0C29B9D5B880")
