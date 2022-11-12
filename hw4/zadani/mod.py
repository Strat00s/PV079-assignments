from functools import wraps
import secrets

def check(func):
    @wraps(func)
    def method(self, other):
        if type(other) is type(self):
            if self.n != other.n:
                raise ValueError
        elif isinstance(other, int):
            other = self.__class__(other, self.n)
        else:
            raise ValueError
        return func(self, other)

    return method


def extgcd(a, b):
    """Extended Euclid's greatest common denominator algorithm."""
    if abs(b) > abs(a):
        (x, y, d) = extgcd(b, a)
        return y, x, d

    if abs(b) == 0:
        return 1, 0, a

    x1, x2, y1, y2 = 0, 1, 1, 0
    while abs(b) > 0:
        q, r = divmod(a, b)
        x = x2 - q * x1
        y = y2 - q * y1
        a, b, x2, x1, y2, y1 = b, r, x1, x, y1, y

    return x2, y2, a


class Mod(object):
    """An element x of ℤₙ."""

    def __init__(self, x: int, n: int):
        self.x: int = x % n
        self.n: int = n

    @check
    def __add__(self, other):
        return Mod((self.x + other.x) % self.n, self.n)

    @check
    def __radd__(self, other):
        return self + other

    @check
    def __sub__(self, other):
        return Mod((self.x - other.x) % self.n, self.n)

    @check
    def __rsub__(self, other):
        return -self + other

    def __neg__(self):
        return Mod(self.n - self.x, self.n)

    def inverse_gcd(self):
        x, y, d = extgcd(self.x, self.n)
        return Mod(x, self.n)

    def inverse_pow(self):
        return self**(self.n - 2)

    def inverse(self):
        return self.inverse_pow()

    def __invert__(self):
        return self.inverse()

    @check
    def __mul__(self, other):
        return Mod((self.x * other.x) % self.n, self.n)

    @check
    def __rmul__(self, other):
        return self * other

    @check
    def __truediv__(self, other):
        return self * ~other

    @check
    def __rtruediv__(self, other):
        return ~self * other

    @check
    def __floordiv__(self, other):
        return self * ~other

    @check
    def __rfloordiv__(self, other):
        return ~self * other

    @check
    def __div__(self, other):
        return self.__floordiv__(other)

    @check
    def __rdiv__(self, other):
        return self.__rfloordiv__(other)

    @check
    def __divmod__(self, divisor):
        q, r = divmod(self.x, divisor.x)
        return Mod(q, self.n), Mod(r, self.n)

    def __bytes__(self):
        return self.x.to_bytes((self.n.bit_length() + 7) // 8, byteorder="big")

    @staticmethod
    def random(n: int):
        return Mod(secrets.randbelow(n), n)

    def __int__(self):
        return self.x

    def __eq__(self, other):
        if type(other) is int:
            return self.x == (other % self.n)
        if type(other) is not Mod:
            return False
        return self.x == other.x and self.n == other.n

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return str(self.x)

    def __pow__(self, n):
        if type(n) is not int:
            raise TypeError
        if n == 0:
            return Mod(1, self.n)
        if n < 0:
            return self.inverse()**(-n)
        if n == 1:
            return Mod(self.x, self.n)

        q = self
        r = self if n & 1 else Mod(1, self.n)

        i = 2
        while i <= n:
            q = (q * q)
            if n & i == i:
                r = (q * r)
            else:
                dummy = q * r
            i = i << 1
        return r
