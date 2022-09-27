a = 1664525
c = 1013904223
m = 2**32


class LCGState:
    def __init__(self, seed):
        self.state = seed % m

    def next(self):
        self.state = (a * self.state + c) % m   #skip first state
        return self.state


def generate_bytes(seed: int, length: int) -> bytes:
    generator = LCGState(seed)
    result    = bytearray()

    for i in range(0, length): 
        result.append((generator.next() & 0x0000ff00) >> 8) #get 2nd byte

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

