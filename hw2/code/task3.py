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
    return outputBytes, a_state

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


CAPACITY = 32
HASH_LEN = 1600 - CAPACITY

ms          = bytes("\x00" * (HASH_LEN//8), "utf-8")
c_list      = list()
states      = list()
hashes      = list()
messages    = list()

while True:
    hash, state = CUSTOM_KECCAK(ms, CAPACITY, HASH_LEN)
    c = state[-(CAPACITY//8):]

    if c in c_list:
        print(f"Found same state!")
        break
    
    hashes.append(hash)
    c_list.append(c)
    states.append(state)
    messages.append(ms)
    ms = hash


#print("Message 1:\n")
index = c_list.index(c)
#printHex(messages[index])
#printHex(hashes[index])
#printHex(c_list[index])
#printHex(states[index])
#
#
#print("")
#
#print("Message 2:\n")
#printHex(ms)
#printHex(hash)
#printHex(c)
#printHex(state)


ms1    = messages[index]
state1 = states[index]
ms2    = ms
state2 = state

#create some suffix for first message
suffix1 = b'\x37'
suffix1 = suffix1 + bytes("\x00" * (200 - len(suffix1)), "utf-8")  #pad the sufix
#print("suffix1:")
#printHex(suffix1)

#xor state of first message with random message -> internal state after second xor
new_state = arrayXor(suffix1, state1)
#print("New state:")
#printHex(new_state)

#xor result ^ with state from second message -> what we need to xor the second message state with
suffix2 = arrayXor(new_state, state2)
#print("suffix2:")
#printHex(suffix2)

ms1 = ms1 + suffix1
ms2 = ms  + suffix2

print("Results:")
print("msg1:")
hash, state = CUSTOM_KECCAK(ms1, CAPACITY, HASH_LEN)
printHex(ms1)
printHex(hash)

print("")

print("msg2:")
hash, state = CUSTOM_KECCAK(ms2, CAPACITY, HASH_LEN)
printHex(ms2)
printHex(hash)

