# Import AES from pycryptodome package (needs to be installed first)
# You can use a different package for the AES computation
from Crypto.Cipher import AES

#byte array xoring taken from: https://programming-idioms.org/idiom/238/xor-byte-arrays/4146/python
def arrayXor(array_a, array_b):
    return bytes([a ^ b for a, b in zip(array_a, array_b)])

class X931State:
    def __init__(self, seed):
        seed     = str(seed)                                    #convert to string
        seed     = seed * (-(-16//len(seed)))                   #repeate the seed to fill 16bytes (aes128); -(-x//y) == ceil
        self.V   = bytearray([int(i) for i in [*seed[:16]]])    #create bytearray of length 16 from sead
        self.K   = bytearray(reversed(self.V))                  #key is reversed vector
        self.dt  = 0                                            #date time
        self.aes = AES.new(self.K, AES.MODE_ECB)                #aes encryptor

    def next(self):
        I        = self.aes.encrypt(self.dt.to_bytes(16, 'big'))
        R        = self.aes.encrypt(arrayXor(I, self.V))
        self.V   = self.aes.encrypt(arrayXor(I, R))
        self.dt += 1
        return R

def generate_bytes(seed: int, length: int) -> bytes:
    x931 = X931State(seed)
    result = bytearray()

    while length > len(result):
        result.extend(x931.next()[:length - len(result)])   #copy only the remaining number of wanted bytes

    return bytes(result)

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print(f"USAGE: python {sys.argv[0]} <OUTPUT FILE> <SEED> <OUTPUT BYTES>")
    out_file = sys.argv[1]
    seed = int(sys.argv[2])
    length = int(sys.argv[3])
    with open(out_file, "wb") as out_file:
        out_file.write(generate_bytes(seed, length))

