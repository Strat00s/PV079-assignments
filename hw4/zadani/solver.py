#!/usr/bin/env python3
import argparse
import csv
from fpylll import LLL, BKZ, IntegerMatrix
from typing import List, Tuple, Set
from hashlib import sha1


from mod import Mod
from ecdsa import Curve, Point, scalarmult, curve_secp256r1


class Solver(object):
    curve: Curve
    public_key: Point
    msg_hash: int
    signatures: List[Tuple[Mod, Mod]]
    total_signatures: int
    lattice: IntegerMatrix
    tried: Set[int]
    
    def __init__(self, curve: Curve, public_key: Point, msg: bytes, signatures: List[Tuple[Mod, Mod]], total_signatures: int):
        self.curve = curve
        self.public_key = public_key
        self.msg_hash = int(sha1(msg).hexdigest(), 16) >> (0 if 160 <= curve.n.bit_length() else 160 - curve.n.bit_length())
        self.signatures = signatures
        self.total_signatures = total_signatures
        self.tried = set()
        self._build_lattice()

    def _build_lattice(self):
        def bound(index):
            i = 1
            while (self.total_signatures) / (2 ** i) >= index + 1:
                i += 1
            i -= 1
            if i <= 1:
                return 0
            return i
        dim = len(self.signatures)
        b = IntegerMatrix(dim + 2, dim + 2)
        for i in range(dim):
            r, s = signatures[i]
            sinv = s.inverse()
            t = int(sinv * r)
            u = int(-sinv * self.msg_hash)
            li = bound(i) + 1
            b[i, i] = (2 ** li) * self.curve.n
            b[dim, i] = (2 ** li) * t
            b[dim + 1, i] = (2 ** li) * u + self.curve.n
        b[dim, dim] = 1
        b[dim + 1, dim + 1] = self.curve.n
        self.lattice = b

    def _reduce(self, lattice, block_size=None):
        if block_size is None:
            print("Doing LLL...")
            return LLL.reduction(lattice)
        else:
            print(f"Doing BKZ-{block_size}...")
            return BKZ.reduction(lattice, BKZ.Param(block_size=block_size, strategies=BKZ.DEFAULT_STRATEGY, auto_abort=True))

    def _try(self, guess, pubkey):
        if guess in self.tried:
            return False
        self.tried.add(guess)
        pubkey_guess = scalarmult(self.curve.g, guess, self.curve)
        return pubkey_guess == pubkey

    def _found(self, lattice, pubkey):
        for row in lattice:
            guess = abs(int(row[-2]))
            if self._try(guess, pubkey):
                return guess % self.curve.n
            if self._try(self.curve.n - guess, pubkey):
                return (self.curve.n - guess) % self.curve.n
        return None

    def solve(self):
        for block_size in (None, 10, 15, 20, 25, 30, 35):
            self.lattice = self._reduce(self.lattice, block_size)
            found = self._found(self.lattice, self.public_key)
            if found:
                print(f"*** Found the private key: {found} ***")
                return True
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--meta-file", dest="meta", type=str,
                        help="The file with the public key and message (<UCO>_meta.txt).", required=True)
    parser.add_argument("-s", "--signatures", dest="sigs", type=str,
                        help="The file with filtered and ordered signatures (a selection from <UCO>_data.txt).", required=True)
    parser.add_argument("-t", "--total", dest="total", type=int, default=10000)

    curve = curve_secp256r1

    args = parser.parse_args()
    with open(args.meta) as f:
        reader = csv.reader(f)
        pubx, puby, msg = next(reader)
        public = Point(Mod(int(pubx), curve.p), Mod(int(puby), curve.p))
        msg = msg.encode("ascii")
    with open(args.sigs) as f:
        reader = csv.reader(f)
        signatures = [(Mod(int(r), curve.n), Mod(int(s), curve.n)) for time, r, s in reader]

    solver = Solver(curve, public, msg, signatures, args.total)
    if solver.solve():
        exit(0)
    else:
        exit(1)
