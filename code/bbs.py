# 512-bit primes
p = 6070186730910479310918815191840163587634827602441835781625018423574917227762047548183164111199826067360243865009867508398917120094583722287922451025975767
q = 5340312989465584099871463955436845940135320986603689391470576059268871866982316459236849963576848007087188105130926608734906024678241674028940333669236459

M = p * q


class BBSState:
    def __init__(self, seed: int):
        seed **= 100
        self.state = (seed * seed) % M

    def generateBit(self):
        self.state = (self.state * self.state) % M  #skip first state
        return (0 if self.state % 2 == 0 else 1)    #odd numbers have LSB 1, even 0; we want LSB


def generate_bytes(seed: int, length: int) -> bytes:
    generator = BBSState(seed)
    result    = bytearray()

    for i in range(0, length):
        byte = 0
        #create byte from subsequent generator calls
        for j in range(0, 8):
            byte += generator.generateBit() << (7 - j % 8)  #first bit from generator is MSB

        result.append(byte)

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
