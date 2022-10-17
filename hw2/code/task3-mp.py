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
import binascii

from multiprocessing import Pool
from os import urandom
from functools import reduce


CAPACITY = 16
RATE = 1600 - CAPACITY
HASH_LEN = RATE


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
    return outputBytes, a_state[-(CAPACITY//8):], a_state

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


def multiprocessing_func(messages):
    result = list()
    for message in messages:
        result.append((message, CUSTOM_KECCAK(message, CAPACITY, HASH_LEN)[1]))
    return result


#inspired by a pretty much same problem https://github.com/p4-team/ctf/blob/117e8da28f3d3e0ce95ea3d2f18bb9d78dd157bb/2019-03-23-0ctf-quals/crypto_keccak/README.md
#mostly just to get the multirpocessing to work properly and the lambda reduction
if __name__=='__main__':
    NPROC = 12 #Numer of available processors
    pool = Pool(NPROC)
    
    ms_dict = dict()
    step = 0

    print(f"Capacity: {CAPACITY}")

    while True:
        step += 2000
        results = pool.map(multiprocessing_func, [[urandom(RATE//8) for j in range(step)] for i in range(NPROC + 1)])
        results = reduce(lambda x, y: x + y, results)
        for msg, c in results:
            c = binascii.hexlify(c)
            if c in ms_dict:        #we got a match if c is already a key
                print(len(ms_dict))
                print("Done")
                ms1 = ms_dict[c]
                ms2 = msg
                break
            else:
                ms_dict[c] = msg    #store message
        else:
            print(len(ms_dict))     #"progress"
            continue
        break

    state1 = CUSTOM_KECCAK(ms1, CAPACITY, HASH_LEN)[2]
    state2 = CUSTOM_KECCAK(ms2, CAPACITY, HASH_LEN)[2]

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

    with open("ms1.txt", "w") as f:
        f.write(ms1.hex())
    with open("hash1.txt", "w") as f:
        f.write(hash.hex())

    print("")

    print("msg2:")
    hash = CUSTOM_KECCAK(ms2, CAPACITY, HASH_LEN)[0]
    printHex(ms2)
    printHex(hash)

    with open("ms2.txt", "w") as f:
        f.write(ms2.hex())
    with open("hash2.txt", "w") as f:
        f.write(hash.hex())

