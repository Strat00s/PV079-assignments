import requests
from typing import Final, Optional
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
import secrets
import time

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



def printHex(byte_data):
    for byte in byte_data:
        print(f"{byte:02x}", end="")
    print("")

def arrayXor(array_a, array_b):
    return bytes([a ^ b for a, b in zip(array_a, array_b)])


encrypted_command = bytearray.fromhex("77546837aa048d02e1d82739f9e48bbaeb51e89a688afb20f4a2b520708049047eed9bddaddb10a648afe49bb5033835675c93a96e9804c0e9ae3ed0695ba41e33aa5997395d097e2c44fd9bdf3619568acd5b7416da3fe42d1bc78fb60d2841f810279ba27adb9de7c20c0459987c4aa8579af443c9cde1f6c9485c97")

nonce = encrypted_command[:16]
ctr   = encrypted_command[16:-32]
iv    = encrypted_command[-32:-16]
mac   = encrypted_command[-16:]

print(f"Nonce ({len(nonce)}):")
printHex(nonce)
print(f"CTR ({len(ctr)}):")
printHex(ctr)
print(f"IV ({len(iv)}):")
printHex(iv)
print(f"MAC ({len(mac)}):")
printHex(mac)

#send last nonce with counter 0
#we should get hash of it in MAC -> xor with first block of msg -> raw text?

blocks = -(-len(ctr)//16)
print(f"Blocks: {blocks}")

#decrypt message
decrypted_msg = ""
for i in range(0, blocks):
    response = requests.get("https://pv079.fi.muni.cz/encrypt", params={"msg":nonce.hex(), "iv":"00" * 16},)
    time.sleep(0.25)

    if response.status_code != 200:
        print(f"Error ({response.status_code}): {response.raw}")
        exit(0)
    
    #extract nonce hash
    nonce_hash = bytearray.fromhex(response.json()["result"])[-16:]
    start = i * 16
    end   = (i + 1) * 16
    if end > len(ctr):
        end = len(ctr)
    #xor it with nth block of ctr hash to get plaintext
    decrypted_block = arrayXor(nonce_hash, ctr[start:end])
    decrypted_msg += f"{decrypted_block.decode()}"

    #increment counter (nonce with counter)
    nonce = int(nonce.hex(), 16)
    nonce += 1
    nonce = bytearray.fromhex(f"{nonce:x}")

forged_msg = decrypted_msg[:10] + "492875" + decrypted_msg[16:]

print(f"Decrypted msg: {decrypted_msg}")
print(f"Forged msg:    {forged_msg}")

response = requests.get("https://pv079.fi.muni.cz/encrypt", params={"msg":forged_msg.encode("utf-8").hex(), "iv":iv.hex()},)
if response.status_code != 200:
    print(f"Error ({response.status_code}): {response.raw}")
    exit(0)

encrypted_msg = response.json()['result']
print(f"Encrypted: {encrypted_msg}")

send_response = requests.post(
    "https://pv079.fi.muni.cz/send",
    data={"encrypted_command":encrypted_msg},)
print(send_response.json())

print("\ndone")
