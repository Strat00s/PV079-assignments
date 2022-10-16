# -*- coding: utf-8 -*-
# Implementation by Gilles Van Assche, hereby denoted as "the implementer".
#
# For more information, feedback or questions, please refer to our website:
# https://keccak.team/
#
# To the extent possible under law, the implementer has waived all copyright
# and related or neighboring rights to the source code in this file.
# http://creativecommons.org/publicdomain/zero/1.0/

#Entire Keccak implementation taken from: https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202_numpy.py

import numpy as np
import string
import binascii


KECCAK_BYTES = 200
KECCAK_LANES = 25
KECCAK_PLANES_SLICES = 5

THETA_REORDER = ((4, 0, 1, 2, 3), (1, 2, 3, 4, 0))

#Iota Step Round Constants For Keccak-p(1600, 24)
IOTA_CONSTANTS = np.array([0x0000000000000001,0x0000000000008082, 0x800000000000808A,
                            0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
                            0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
                            0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                            0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
                            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
                            0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
                            0x8000000000008080, 0x0000000080000001, 0x8000000080008008],
                          dtype=np.uint64)

#Lane Shifts for Rho Step
RHO_SHIFTS = np.array([[0, 36, 3, 41, 18],
                       [1, 44, 10, 45, 2],
                       [62, 6, 43, 15, 61],
                       [28, 55, 25, 21, 56],
                       [27, 20, 39, 8, 14]], dtype=np.uint64)

#Lane Re-order Mapping for Chi Step
CHI_REORDER = ((1, 2, 3, 4, 0), (2, 3, 4, 0, 1))

#Row Re-order Mapping for Pi Step
PI_ROW_REORDER = np.array([[0, 3, 1, 4, 2],
                           [1, 4, 2, 0, 3],
                           [2, 0, 3, 1, 4],
                           [3, 1, 4, 2, 0],
                           [4, 2, 0, 3, 1]])

#Column Re-order Mapping for Pi Step
PI_COLUMN_REORDER = np.array([[0, 0, 0, 0, 0],
                              [1, 1, 1, 1, 1],
                              [2, 2, 2, 2, 2],
                              [3, 3, 3, 3, 3],
                              [4, 4, 4, 4, 4]])


def KeccakF1600(state):
    state = np.copy(np.frombuffer(state, dtype=np.uint64, count=25).reshape([5, 5], order='F'))
    for round_num in range(24):
        # theta_step:
        # Exclusive-or each slice-lane by state based permutation value
        array_shift = state << 1 | state >> 63
        state ^= np.bitwise_xor.reduce(state[THETA_REORDER[0], ], 1, keepdims=True) ^ np.bitwise_xor.reduce(array_shift[THETA_REORDER[1], ], 1, keepdims=True)

        # rho_step:
        # Left Rotate each lane by pre-calculated value
        state = state << RHO_SHIFTS | state >> np.uint64(64 - RHO_SHIFTS)

        # pi_step:
        # Shuffle lanes to pre-calculated positions
        state = state[PI_ROW_REORDER, PI_COLUMN_REORDER]

        # chi_step:
        # Exclusive-or each individual lane based on and/invert permutation
        state ^= ~state[CHI_REORDER[0], ] & state[CHI_REORDER[1], ]

        # iota_step:
        # Exclusive-or first lane of state with round constant
        state[0, 0] ^= IOTA_CONSTANTS[round_num]

    return bytearray(state.tobytes(order='F'))

def Keccak(rate, capacity, inputBytes, delimitedSuffix, outputByteLen):
    outputBytes = bytearray()
    state = bytearray([0 for i in range(200)])
    rateInBytes = rate//8
    blockSize = 0
    a_state = 0
    input_copy = bytearray(inputBytes)
    if (((rate + capacity) != 1600) or ((rate % 8) != 0)):
        return
    inputOffset = 0

    # === Absorb all the input blocks ===
    while(inputOffset < len(inputBytes)):
        blockSize = min(len(inputBytes)-inputOffset, rateInBytes)
        for i in range(blockSize):
            state[i] = state[i] ^ inputBytes[i+inputOffset]
        inputOffset = inputOffset + blockSize
        if (blockSize == rateInBytes):
            state = KeccakF1600(state)
            blockSize = 0

    a_state = state

    # === Do the padding and switch to the squeezing phase ===
    state[blockSize] = state[blockSize] ^ delimitedSuffix
    if (((delimitedSuffix & 0x80) != 0) and (blockSize == (rateInBytes-1))):
        state = KeccakF1600(state)
    state[rateInBytes-1] = state[rateInBytes-1] ^ 0x80
    state = KeccakF1600(state)

    # === Squeeze out all the output blocks ===
    while(outputByteLen > 0):
        blockSize = min(outputByteLen, rateInBytes)
        outputBytes = outputBytes + state[0:blockSize]
        outputByteLen = outputByteLen - blockSize
        if (outputByteLen > 0):
            state = KeccakF1600(state)
    return outputBytes, a_state, input_copy

def CUSTOM_KECCAK(inputBytes, capacity, hash_len):
    #capacity = 32
    return Keccak(1600 - capacity, capacity, inputBytes, 0x06, hash_len//8)


def printHex(byte_data):
    for byte in byte_data:
        print(f"{byte:02x}", end="")
    print("")


#byte array xoring taken from: https://programming-idioms.org/idiom/238/xor-byte-arrays/4146/python
def arrayXor(array_a, array_b):
    return bytes([a ^ b for a, b in zip(array_a, array_b)])


CAPACITY = 16
HASH_LEN = 1600 - CAPACITY

ms          = bytes("\x00" * (HASH_LEN//8), "utf-8")

#7084ab35216254284a4ced1ac077a99bc4cd37147d22e550091be122de54d9d8ff0264c5ee062c8606d05fb19caf7ebd13eb5125fb639be8d12924fc5ae083123d3d5fbd67e21e9dc717fe34c525dc7213ebe2f1f415f720a6d0c4f58eb14e415ede6a0fe9ac7861f8c6699b8aeb59d386f83969f477adcd80d6dc71923a26921d06fd3e9b070663d73c32b83369b30ba208f46869d2370ae0e0822bdc6e4a2a1351c5e24e82692e2186b006273f303e7fce5bcc18ee17accf94111d8bd7a254398e370000000000
#0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
#4edb3e00ce963267191c4e9bc72c79050a02a6bdc7481259c273495ca734b4e3bd2bf866412517b17978acd830581d1b168a3e92b07030dea2fd6746393e57fa93530213dba85d762e865b851564488f047c6174f5f44977d6a5538495daa5982aa68d701ce786874151b3ef043ec14c5606d83a20a58bfc3e67f88dfb3ecfaa2ab9eb9d546324d2116ad20ae9033f18fa41e70a3b32d46c9d971be7ec598201fcd2abb1a8b6990704898af63e7cf30a2dfa251092db5d73b2c21b1fbc1579376aad

#832efc9c4e178534ee9d40bd3c8c4cd709e97551b5ec0287c8267c101298e32f95ba4042b0314b4c38d6c13dfb2865df5f2da731ee5e7463476e4347ffad8740a47b43dc320c18d88d7d77bd02774c7b53bd3721f8cd74fc1b1ebc5658f488149b870a7b211412ce0d51c225ab3417249fc84f5ecd7be8a88971ac7d04d29e4c768e2738d291aa0440baba47b9faa32b17216fc1be0a706255c5eb407174f32de13f6c8512d87ec0525cb49781a41fce76a2233bcf16b94aee320ac51ad06b486c94e6003b9a66db8716931cce4d50dbb91b0bc33ffc0ca5cf475baf0ed9c8a8f3a5fe6f18d326a4d5b856d57417feacbc005b7c88988ebbacb3977ecfda87c2237915b9ba45ddc36746255d9dd543883e60dddcf81f844c86a5afcd33c1f2a21f9de65e789e84851946581a
#8716931cce4d50dbb91b0bc33ffc0ca5cf475baf0ed9c8a8f3a5fe6f18d326a4d5b856d57417feacbc005b7c88988ebbacb3977ecfda87c2237915b9ba45ddc36746255d9dd543883e60dddcf81f844c86a5afcd33c1f2a21f9de65e789e84851946581a4c887c26e10b8ee0258257696932163282960fca50f3dfb6a5ef78a4e85bbe83b60fec5feda6f65cefb684464c9aa45e36bbd7fbe1c403ae768ca343d74ccea8ab0487f640b6b59b9693cd55a85de7eec81280917d966562000000000000
#4edb3e00ce963267191c4e9bc72c79050a02a6bdc7481259c273495ca734b4e3bd2bf866412517b17978acd830581d1b168a3e92b07030dea2fd6746393e57fa93530213dba85d762e865b851564488f047c6174f5f44977d6a5538495daa5982aa68d701ce786874151b3ef043ec14c5606d83a20a58bfc3e67f88dfb3ecfaa2ab9eb9d546324d2116ad20ae9033f18fa41e70a3b32d46c9d971be7ec598201fcd2abb1a8b6990704898af63e7cf30a2dfa251092db5d73b2c21b1fbc1579376aad

#o_tortoise = ms
#o_hare = ms
o_h1 = ms
ms_dict = dict()

print(f"Capacity: {CAPACITY}")

while True:
    data = []
    data.append(CUSTOM_KECCAK(o_h1,        CAPACITY, HASH_LEN))
    data.append(CUSTOM_KECCAK(data[-1][0], CAPACITY, HASH_LEN))
    data.append(CUSTOM_KECCAK(data[-1][0], CAPACITY, HASH_LEN))
    data.append(CUSTOM_KECCAK(data[-1][0], CAPACITY, HASH_LEN))
    data.append(CUSTOM_KECCAK(data[-1][0], CAPACITY, HASH_LEN))
    data.append(CUSTOM_KECCAK(data[-1][0], CAPACITY, HASH_LEN))

    for item in reversed(data):
        c = binascii.hexlify(item[1][-(CAPACITY//8):])
        if c in ms_dict and item[2] != ms_dict[c]:
            print("Found same state???")
            ms2 = item[2]
            ms1 = ms_dict[c]
            break
        else:
            ms_dict[c] = item[2]
    else:
        o_h1 = data[-1][0]
        continue
    break

state1 = CUSTOM_KECCAK(ms1, CAPACITY, HASH_LEN)[1]
state2 = CUSTOM_KECCAK(ms2, CAPACITY, HASH_LEN)[1]


#create some suffix for first message
suffix1 = b'\x37'
suffix1 = suffix1 + bytes("\x00" * (200 - len(suffix1)), "utf-8")  #pad the sufix

#xor state of first message with random message -> internal state after second xor
new_state = arrayXor(suffix1, state1)

#xor result ^ with state from second message -> what we need to xor the second message state with
suffix2 = arrayXor(new_state, state2)

new_state = arrayXor(suffix2, state2)

ms1 = ms1 + suffix1
ms2 = ms2 + suffix2

print("Results:")
print("msg1:")
hash = CUSTOM_KECCAK(ms1, CAPACITY, HASH_LEN)[0]
printHex(ms1)
printHex(hash)

print("")

print("msg2:")
hash = CUSTOM_KECCAK(ms2, CAPACITY, HASH_LEN)[0]
printHex(ms2)
printHex(hash)

print(len(ms1))
print(len(ms2))
