a = 1664525
c = 1013904223
m = 2**32

class LCGState:
    def __init__(self, seed):
        self.state = seed % m

    # TODO implement LCG generator
    def next(self):
        self.state = (a * self.state + c) % m

def generate_bytes(seed: int, length: int) -> bytes:
    result = bytearray()
    lcg = LCGState(seed)
    for i in range(0, length):
        lcg.next()
        result.append(lcg.state.to_bytes(4, 'big')[-2])

    # TODO return byte array of given length from the generator

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

