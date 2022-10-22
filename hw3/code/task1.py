from Crypto.Cipher import AES
import binascii

def printHex(byte_data):
    for byte in byte_data:
        print(f"{byte:02x}", end="")
    print("")

#byte array xoring taken from: https://programming-idioms.org/idiom/238/xor-byte-arrays/4146/python
def arrayXor(array_a, array_b):
    return bytes([a ^ b for a, b in zip(array_a, array_b)])

iv  = bytearray.fromhex("00" * 16)
key = bytearray.fromhex("74a8ed356dc1a828645a6c12fcf9a1b1")
msg = ""
h1  = bytearray.fromhex("dcae4a1993b9a13eb52d99fde7701f35")

print("IV:  ", end="")
printHex(iv)
print("key: ", end="")
printHex(key)
print("h1:  ", end="")
printHex(h1)

aes = AES.new(key, AES.MODE_CBC, iv)
msg = aes.decrypt(h1)
printHex(msg)
print(msg.decode("utf-8"))

