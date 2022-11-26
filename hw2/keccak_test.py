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
    return outputBytes
def CUSTOM_KECCAK(inputBytes, capacity):
    #capacity = 32
    return Keccak(1600 - capacity, capacity, inputBytes, 0x06, 1600//8)


CAPACITY = 56

ms1 = bytearray.fromhex("bbebd040ecf16c12c26770052cb4ad9aab3df7b7be2e8bd37fef020a23ef622310e37a33ca5b588f41653308ea0c612d1e2c65ac62844ed1e9a4b161b6232fb418cec3ddaf7492c55375613c117b0548e20183d79709a8fe1171f5ba77018ab6c7c94db4b6923747ae4541575086670dde861eb10c31e97afff4a14036c650e4189a0e4cb48186f9656984975c766e727cc0bf962caa4216377adf65e7336314554050843f39f4695a298b42ebcd1b9ac205ec4f753f8d439d4dc6c398a486fc3a3700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
ms2 = bytearray.fromhex("feedcfb6a69a4cfe57046de84811108ed8a1f7022f346284dd285a1f9ef56570c27b6e0e5ee72ecdbe2f2668c5bee88d07343774c43ddd1b3d94e8c2a3c3dcd5063cd4724f226cb8b4100e3129e450129c5b3034d1b51f8b7a0839834ccd23e4612c34d8d578c2b503de4555395505c7c0b9a9d538f8b6d8d40c0324fe7d8e3c91c0662a344ac08b963d61202349e1da28445c5f983b3c79c7f44333c96fc7d8fb75609aff57696b5fd516c8880ff96b9af480a685ba52db3ed1477b031bd4bc46b1254b3f3f732c9f91771e47b40be6ef5b7c18e232d9868ee2ecdfc412a960df22a82281bcdeca18f921a20f6b2036fbe51d0eafd5c494ff42a9a4416e59ea66025c2d29c303c4afc649e0c5e01f3e92782187b3570dacf0960f74ce1f4ed57947865a9e21cc56158b4fb48b974a7bbf4605ccf7e61e3abc57a5b12d65d7d29e16bb76d70da3009c0d66705bff0f31f50e5d949083eea0b6dad837e49f2f8cd9781d1d8067d483ffe27288787211afb66ba97ca864ab5459a13fab71560e47670700000000000000")

hash1 = CUSTOM_KECCAK(ms1, CAPACITY) 
hash2 = CUSTOM_KECCAK(ms2, CAPACITY) 

if hash1 == hash2:
    print("GG EZ")
else:
    print("UH OH")
