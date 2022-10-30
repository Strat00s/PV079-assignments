from typing import Final, Optional
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
import secrets


#taken from referential encryption example
BLOCK_LEN: Final[int] = 16

def pad(msg: bytes) -> bytes:
    """
    Implements zero-byte padding. Will not pad message if BLOCK_LEN divides its length
    Else will append necessary number of zero bytes

    :param bytes msg: message to pad
    :return bytes: padded message
    """
    n_bytes_to_padd = 0 if not len(msg) % BLOCK_LEN else BLOCK_LEN - (len(msg) % BLOCK_LEN)
    return msg + bytes([0] * n_bytes_to_padd)

def encrypt_ctr(key: bytes, nonce: bytes, msg: bytes) -> bytes:
    """
    AES-CTR encryption

    :param bytes key: 16-byte long key
    :param bytes nonce: 16-byte long nonce
    :param bytes msg: plaintext to encrypt
    :return bytes: the resulting ciphertext
    """
    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return encryptor.update(msg) + encryptor.finalize()

def decrypt_ctr(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    AES-CTR decryption

    :param bytes key: 16-byte long key
    :param bytes nonce: 16-byte long nonce
    :param bytes ciphertext: ciphertext to decrypt
    :return bytes: the resulting plaintext
    """
    decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def get_cbc_mac(key: bytes, iv: bytes, msg: bytes) -> bytes:
    """
    Custom implementation of CBC-MAC driven by AES-128 cipher.

    :param bytes key: 16-byte long key
    :param bytes iv: 16-byte long IV
    :param bytes msg: message to compute the MAC for
    :return bytes: Resulting MAC, i.e. last 16 bytes of AES-CBC ciphertext
    """
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(pad(msg)) + encryptor.finalize()
    return ciphertext[-16:]

def oracle_encrypt(key: bytes, msg: bytes, iv: Optional[bytes] = None) -> bytes:
    """
    This is a function that is run when `/encrypt` endpoint is called on pv079.fi.muni.cz

    :param bytes key: Secret key, not an endpoint parameter.
    :param bytes msg: message to encrypt
    :param Optional[bytes] iv: IV to use, defaults to None
    :return bytes: ciphertext
    """
    if not iv:
        iv = secrets.token_bytes(BLOCK_LEN)

    nonce = secrets.token_bytes(BLOCK_LEN)
    ciphertext = encrypt_ctr(key, nonce, msg)
    mac_tag = get_cbc_mac(key, iv, msg)
    return nonce + ciphertext + iv + mac_tag


#byte array xoring taken from: https://programming-idioms.org/idiom/238/xor-byte-arrays/4146/python
def arrayXor(array_a, array_b):
    return bytes([a ^ b for a, b in zip(array_a, array_b)])


m2 = bytearray("This is sooooooooooome interesting message crafted for a person with UCO: 492875", "utf-8")
m3 = bytearray("This is a completely unrelated message, again for someone with UCO: 492875", "utf-8")
t2 = bytearray.fromhex("72182255a4e75ccc1f6aed0e7b444ea3")
t3 = bytearray.fromhex("dc866868c1f9ad8669aefd90f9d1fa2a")


print(f"m2: {m2.hex()}")
print(f"m3: {m3.hex()}")
print(f"t2: {t2.hex()}")
print(f"t3: {t3.hex()}")
print("")

m4 = m2 + m3
print(f"m4: {m4.hex()}")

#m5
#iv = t2
#key = ?
#msg = m3[-16:]
#-> input = iv xor msg

m5 = arrayXor(t2, m3[:16]) + m3[16:]
print(f"m5: {m5.hex()}")


print("\n---------------------------------------------\nTest with known key:")
key = bytearray.fromhex("00" * 16)
t2 = get_cbc_mac(key, key, m2)
t3 = get_cbc_mac(key, key, m3)

print(f"key:    {key.hex()}")
print(f"m2:     {m2.hex()}")
print(f"m3:     {m3.hex()}")
print(f"new t2: {t2.hex()}")
print(f"new t3: {t3.hex()}")

m4 = m2 + m3
m5 = arrayXor(t2, m3[:16]) + m3[16:]
print(f"\nm4: {m4.hex()}")
print(f"m5: {m5.hex()}")

print(f"\nm4 MAC: {get_cbc_mac(key, key, m4).hex()}")
print(f"m5 MAC: {get_cbc_mac(key, key, m5).hex()}")

#print(m4)
#print(m5)
#print(m4.hex())
#print(m5.hex())
