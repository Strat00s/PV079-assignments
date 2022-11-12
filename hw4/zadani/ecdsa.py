#!/usr/bin/env python3
from mod import Mod
from hashlib import sha1
from typing import Tuple
from dataclasses import dataclass


@dataclass
class Point(object):
    """A point on an elliptic curve."""
    x: Mod
    y: Mod


@dataclass
class Curve(object):
    """An elliptic curve."""
    p: int
    a: Mod
    b: Mod
    g: Point
    n: int

    def __init__(self, p: int, a: int, b: int, gx: int, gy: int, n: int):
        self.p = p
        self.a = Mod(a, p)
        self.b = Mod(b, p)
        self.g = Point(Mod(gx, p), Mod(gy, p))
        self.n = n


curve_secp128r1 = Curve(0xfffffffdffffffffffffffffffffffff,
                        0xfffffffdfffffffffffffffffffffffc,
                        0xe87579c11079f43dd824993c2cee5ed3,
                        0x161ff7528b899b2d0c28607ca52c5b86,
                        0xcf5ac8395bafeb13c02da292dded7a83,
                        0xfffffffe0000000075a30d1b9038a115)
curve_secp256r1 = Curve(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                        0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
                        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
                        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
curve_toy = Curve(0xfb, 0xf6, 0x86, 0xbc, 0xdd, 0xef)


def scalarmult(point: Point, scalar: int, curve: Curve) -> Point:
    """
    Perform scalar multiplication of the `point` with the `scalar` on the elliptic curve given by `curve`.
    See <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication> for some methods.
    This code implements a Montgomery ladder-like method.
    Returns `[scalar]G`.
    """
    def add(p: Point, q: Point):
        """
        Add two points on an elliptic curve (If the points are equal, the result is erroneous).
        See <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition>.
        """
        λ = (q.y - p.y) / (q.x - p.x)
        x = λ**2 - p.x - q.x
        y = λ * (p.x - x) - p.y
        return Point(x, y)
    def dbl(p: Point):
        """
        Double a point on an elliptic curve.
        See <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling>.
        """
        λ = (3 * p.x**2 + curve.a) / (2 * p.y)
        x = λ**2 - p.x - p.x
        y = λ * (p.x - x) - p.y
        return Point(x, y)

    r0 = point
    r1 = dbl(point)
    for i in range(scalar.bit_length() - 2, -1, -1):
        if scalar & (1 << i) == 0:
            r1 = add(r0, r1)
            r0 = dbl(r0)
        else:
            r0 = add(r0, r1)
            r1 = dbl(r1)
    return r0


def keygen(curve: Curve) -> Tuple[Mod, Point]:
    """
    Generate an ECC keypair on the `curve`.
    Returns a tuple of `private key, public key`.
    """
    private = Mod.random(curve.n)
    public = scalarmult(curve.g, int(private), curve)
    return private, public


def sign(message: bytes, private: Mod, curve: Curve) -> Tuple[Mod, Mod]:
    """
    Sign the `message` using the `private` key on the `curve`.
    Returns the signatur tuple `r, s`.
    """
    # h = SHA1(message) and then the ECDSA trimming.
    h = int(sha1(message).hexdigest(), 16) >> (0 if 160 <= curve.n.bit_length() else 160 - curve.n.bit_length())
    # k = random integer from ℤₙ, the Mod.random function should be considered constant-time.
    k = Mod.random(curve.n)
    # r = ([k]G)_x mod n
    r = Mod(int(scalarmult(curve.g, int(k), curve).x), curve.n)
    # s = k^-1 * (H(message) + r * x) mod n
    s = k**(-1) * (h + r * private)
    return r, s
