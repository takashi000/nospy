import hashlib
import math
import secrets

ed25519_CURVE:tuple = (
    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed, #p
    0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed, #n
    8, #h
    0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec, #a
    0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3, #d
    0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a, #Gx
    0x6666666666666666666666666666666666666666666666666666666666666658, #Gy
)
P, N, h, _a, _d, Gx, Gy = (
    ed25519_CURVE[0],
    ed25519_CURVE[1],
    ed25519_CURVE[2],
    ed25519_CURVE[3],
    ed25519_CURVE[4],
    ed25519_CURVE[5],
    ed25519_CURVE[6],
)
L, L2 = (32, 64)
G, I = ((Gx, Gy, 1, (Gx * Gy) % P), (0, 1, 1, 0))
B256 = 2 ** 256
RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
W, scalarBits = (8, 256)
pwindows, pwindowSize = (math.ceil(scalarBits / W) + 1, 2 ** (W - 1))

class Ed25519:
    def __init__(self):
        super().__init__()
        self.Gpows:list = None
    
    def base(self) -> tuple[int, int, int, int]:
        return G

    def zero(self) -> tuple[int, int, int, int]:
        return I

    def arange(self, n:int, min:int, max:int) -> int|None:
        if all([isinstance(n, int), min <= n, n < max]): return n
        return None
    
    def M(self, a:int, b:int=P) -> int:
        return a % b
    
    def modN(self, a:int) -> int:
        return a % N
    
    def modL_LE(self, hash:bytes) -> int:
        return self.modN(int.from_bytes(hash, 'little'))
    
    def invert(self, num:int, md:int) -> int|None:
        if num == 0 or md <= 0: return None
        a, b, x, y, u, v = (self.M(num, md), md, 0, 1, 1, 0)
        while a != 0:
            q, r = (b // a, b % a)
            m, n = (x - u * q, y - v * q)
            b, a, x , y, u, v = (a, r, u, v, m, n)

        return self.M(x, md) if b == 1 else None
    
    def curve(self) -> tuple[int, ...]:
        return ed25519_CURVE
    
    def fromAffine(self, ap:tuple[int, int]) -> tuple[int, int, int, int]:
        return [ap[0], ap[1], 1, self.M(ap[0] * ap[1])]
    
    def fromBytes(self, hex:bytes, zip215:bool = False) -> tuple[int, int, int, int]|tuple[None, None, None, None]:
        if not isinstance(hex, bytes) or len(hex) != L: return (None, None, None, None)
        
        d:int = _d
        normed:bytearray = bytearray(hex)
        
        tail_byte:bytes = hex[-1]
        normed[-1] = tail_byte & ~0x80
        max:int = B256 if zip215 else P
        y:int = self.arange(int.from_bytes(normed, byteorder='little'), 0, max)
        if y is None: return (None, None, None, None)
        
        y2:int = self.M(y * y)
        u:int = self.M(y2 - 1)
        v:int = self.M(d * y2 + 1)
        isvalid, x = self.uvRatio(u, v)
        if not isvalid: return (None, None, None, None)

        is_x_odd:bool = (x & 1) == 1
        is_tail_byte_odd:bool = (tail_byte & 0x80) != 0
        if all((not zip215, x == 0, is_tail_byte_odd)): return (None, None, None, None)

        if is_tail_byte_odd != is_x_odd: x = self.M(-x)

        return (x, y, 1, self.M(x * y))

    def fromHex(self, hex:str, zip215:bool=None) ->  tuple[int, int, int, int]|tuple[None, None, None, None]:
        return self.fromBytes(bytes.fromhex(hex), zip215)
    
    def getx(self, point:tuple[int, int, int, int]) -> int:
        return self.toAffine(point)[0]
    
    def gety(self, point:tuple[int, int, int, int]) -> int:
        return self.toAffine(point)[1]
    
    def equals(self, point1:tuple[int, int, int, int], point2:tuple[int, int, int, int]) -> bool:
        x1, y1, z1, _ = point1
        x2, y2, z2, _ = point2
        
        x1z2, x2z1 = (self.M(x1 * z2), self.M(x2 * z1))
        y1z2, y2z1 = (self.M(y1 * z2), self.M(y2 * z1))

        return x1z2 == x2z1 and y1z2 == y2z1
    
    def is0(self, point:tuple[int, int, int, int]) -> bool:
        if None in point: return False

        return self.equals(point, I)
    
    def negate(self, point:tuple[int, int, int, int]) -> tuple[int, int, int, int]:
        return (self.M(-point[0]), point[1], point[2], self.M(-point[3]))
    
    def double(self, point:tuple[int, int, int, int]) -> tuple[int, int, int, int]|tuple[None, None, None, None]:
        if not isinstance(point, tuple): return (None, None, None, None)
        if None in point: return (None, None, None, None)

        x1, y1, z1, _ = point
        a:int = _a
        #https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
        A:int = self.M(x1 * x1)
        B:int = self.M(y1 * y1)
        C:int = self.M(2 * self.M(z1 * z1))
        D:int = self.M(a * A)
        x1y1:int = x1 + y1
        E:int = self.M(self.M(x1y1 * x1y1) - A - B)
        G:int = D + B
        F:int = G - C
        H:int = D - B
        x3:int = self.M(E * F)
        y3:int = self.M(G * H)
        t3:int = self.M(E * H)
        z3:int = self.M(F * G)

        return (x3, y3, z3, t3)

    def add(self, point1:tuple[int, int, int, int], point2:tuple[int, int, int, int]) -> tuple[int, int, int, int]|tuple[None, None, None, None]:
        if not isinstance(point1, tuple) or not isinstance(point2, tuple): return (None, None, None, None)
        if None in point1 or None in point2: return (None, None, None, None)
        
        x1, y1, z1, t1 = point1
        x2, y2, z2, t2 = point2
        a:int = _a
        d:int = _d

        # https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
        A:int = self.M(x1 * x2)
        B:int = self.M(y1 * y2)
        C:int = self.M(t1 * d * t2)
        D:int = self.M(z1 * z2)
        E:int = self.M((x1 + y1) * (x2 + y2) - A - B)
        F:int = self.M(D - C)
        G:int = self.M(D + C)
        H:int = self.M(B - a * A)
        x3:int = self.M(E * F)
        y3:int = self.M(G * H)
        t3:int = self.M(E * H)
        z3:int = self.M(F * G)

        return (x3, y3, z3, t3)
    
    def subtract(self, point1:tuple[int, int, int, int], point2:tuple[int, int, int, int]) -> tuple[int, int, int, int]|tuple[None, None, None, None]:
        return self.add(point1, self.negate(point2))
    
    def multiply(self, point:tuple[int, int, int, int], n:int, safe:bool=True) -> tuple[int, int, int, int]|tuple[None, None, None, None]:
        if not safe and (n == 0 or self.is0(point)): return I
        if self.arange(n, 1, N) is None: return (None, None, None, None)
        if n == 1: return point
        if self.equals(point, G): return self.wNAF(n)[0]
        
        p, f, d = (I, G, point)
        while n > 0:
            if n & 1: p = self.add(p, d) 
            elif safe: f = self.add(f, d)

            d = self.double(d)
            n >>= 1
        
        return p
    
    def multiplyUnsafe(self, point:tuple[int, int, int, int], scalar:int) -> tuple[int, int, int, int]|tuple[None, None, None, None]:
        return self.multiply(point, scalar, False)

    def toAffine(self, point:tuple[int, int, int, int]) -> tuple[int, int]|tuple[None, None]:
        x, y, z, _ = point
        if self.equals(point, I): return (0, 1)
        iz = self.invert(z, P)
        if iz is None: return (None, None)
        if self.M(z * iz) != 1: return (None, None)
        
        return (self.M(x * iz), self.M(y * iz))

    def isValidity(self, point:tuple[int, int, int, int]) -> bool:
        if None in point: return False
        a, d, p = (_a, _d, point)
        if self.is0(p): return False

        x, y, z, t = p
        x2, y2, z2 = (self.M(x * x), self.M(y * y), self.M(z * z))
        
        z4:int = self.M(z2 * z2)
        ax2:int = self.M(x2 * a)
        left:int = self.M(z2 * self.M(ax2 + y2))
        right:int = self.M(z4 + self.M(d * self.M(x2 * y2)))
        if left != right: return False

        xy:int = self.M(x * y)
        zt:int = self.M(z * t)
        if xy != zt: return False

        return True
    
    def toBytes(self, point:tuple[int, int, int, int]) -> bytes|None:
        if not self.isValidity(point): return None
        
        x, y = self.toAffine(point)
        if None in [x, y]: return None

        b:bytearray = bytearray(int.to_bytes(y, 32, 'little'))
        b[31] |= 0x80 if x & 1 else 0

        return bytes(b)

    def toHex(self, point:tuple[int, int, int, int]) -> str|None:
        try:
            return self.toBytes(point).hex()
        except:
            return None

    def clearCofactor(self, point:tuple[int, int, int, int]) -> tuple[int, int, int, int]|tuple[None, None, None, None]:
        return self.multiply(point, h, False)

    def isSmallOrder(self, point:tuple[int, int, int, int]) -> bool:
        return self.is0(self.clearCofactor(point))

    def isTorsionFree(self, point:tuple[int, int, int, int]) -> bool:
        p:tuple[int, int, int, int] = self.double(self.multiply(point, N//2, False))

        if N % 2: p = self.add(point, p)

        return self.is0(p)
    
    def precompute(self) -> list[tuple[int, int, int, int]]:
        points:list = []
        p:tuple[int, int, int, int] = G
        b:tuple[int, int, int, int] = p

        for _ in range(pwindows):
            b = p
            points.append(b)
            for _ in range(1, pwindowSize):
                b = self.add(b, p)
                points.append(b)
            p = self.double(b)
        
        return points

    def ctneg(self, cnd:bool, p:tuple[int, int, int, int]) -> tuple[int, int, int, int]:
        return self.negate(p) if cnd else p

    def wNAF(self, n:int) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]|tuple[None, None]:
        if self.Gpows is None: self.Gpows = self.precompute()
        comp:list = self.Gpows
        p, f = (I, G)
        pow_2_w:int = 2 ** W
        maxNum:int = pow_2_w
        mask:int = pow_2_w - 1
        shiftBy:int = W

        for w in range(pwindows):
            wbits:int = n & mask
            n >>= shiftBy
            if wbits > pwindowSize:
                wbits -= maxNum
                n += 1
            
            off:int = w * pwindowSize
            offF:int = off
            offP:int = off + abs(wbits) - 1
            isEven:bool = w % 2 != 0
            isNeg:bool = wbits < 0
            if wbits == 0:
                f = self.add(f, self.ctneg(isEven, comp[offF]))
            else:
                p = self.add(p, self.ctneg(isNeg, comp[offP]))
        
        return (p, f) if n == 0 else (None, None)
    
    def pow2(self, x:int, power:int) -> int:
        r:int = x
        for _ in range(power):
            r *= r
            r %= P

        return r

    def pow_2_252_3(self, x:int) -> tuple[int, int]:
        x2:int = (x * x) % P
        b2:int = (x2 * x) % P
        b4:int = (self.pow2(b2, 2) * b2) % P
        b5:int = (self.pow2(b4, 1) * x) % P
        b10:int = (self.pow2(b5, 5) * b5) % P
        b20:int = (self.pow2(b10, 10) * b10) % P
        b40:int = (self.pow2(b20, 20) * b20) % P
        b80:int = (self.pow2(b40, 40) * b40) % P
        b160:int = (self.pow2(b80, 80) * b80) % P
        b240:int = (self.pow2(b160, 80) * b80) % P
        b250:int = (self.pow2(b240, 10) * b10) % P
        pow_p_5_8:int = (self.pow2(b250, 2) * x) % P

        return (pow_p_5_8, b2)

    def uvRatio(self, u:int, v:int) -> tuple[bool, int]:
        v3:int = self.M(v * v * v)
        v7:int = self.M(v3 * v3 * v)
        pow:int = self.pow_2_252_3(u * v7)[0]
        x:int = self.M(u * v3 * pow)
        vx2:int = self.M(v * x * x)
        root1:int = x
        root2:int = self.M(x * RM1)
        useroot1:bool = vx2 == u
        useroot2:bool = vx2 == self.M(-u)
        noroot:bool = vx2 == self.M(-u * RM1)
        if useroot1: x = root1
        if useroot2 or noroot: x = root2
        if (self.M(x) & 1) == 1: x = self.M(-x)

        return (useroot1 or useroot2, x)

    # type ExtK = { head: Bytes; prefix: Bytes; scalar: bigint; point: Point; pointBytes: Bytes };
    def hash2extK(self, hashed:bytes) -> tuple[bytes, bytes, int, tuple[int, int, int, int], bytes]:
        head:bytearray = bytearray(hashed[0:L])
        head[0] &= 248
        head[31] &= 127
        head[31] |= 64

        prefix:bytes = hashed[L:L2]
        scalar:int = self.modL_LE(head)
        point:tuple[int, int, int, int] = self.multiply(G, scalar)
        point_bytes:bytes = self.toBytes(point)

        return (bytes(head), prefix, scalar, point, point_bytes)
    
    def getExtendedPublicKey(self, secret_key:bytes) -> tuple[bytes, bytes, int, tuple[int, int, int, int], bytes]|tuple[None, None, None, None, None]:
        if not isinstance(secret_key, bytes) or len(secret_key) != L: return (None, None, None, None, None)
        return self.hash2extK(hashlib.sha512(secret_key).digest())
    
    def getPublicKey(self, priv:bytes) -> bytes:
        return self.getExtendedPublicKey(priv)[4]
    
    def sign(self, message:bytes, secret_key:bytes) -> bytes|None:
        if not isinstance(message, bytes): return None

        m:bytes = message
        e = self.getExtendedPublicKey(secret_key)
        r_bytes:bytes = hashlib.sha512(e[1] + m).digest()

        p, s = (e[4], e[2])
        if p is None: return None

        r:int = self.modL_LE(r_bytes)
        R:bytes = self.toBytes(self.multiply(G, r))
        if R is None: return None

        hashed:bytes = hashlib.sha512(R + p + m).digest()
        S:int = self.modN(r + self.modL_LE(hashed) * s)

        signature:bytes = R + int.to_bytes(S, 32, 'little')
        if len(signature) != L2: return None

        return signature
    
    def verify(self, signature:bytes, message:bytes, pubkey:bytes, zip215:bool=True) -> bool:
        sig, msg, pub = (signature, message, pubkey)
        if not all((
            isinstance(sig, bytes), len(sig) == L2,
            isinstance(msg, bytes),
            isinstance(pub, bytes), len(pub) == L
        )): return False
        
        isverified:bytes = False
        try:
            A:tuple[int, int, int, int] = self.fromBytes(pub, zip215)
            R:tuple[int, int, int, int] = self.fromBytes(sig[0:L], zip215)
            s:int = int.from_bytes(sig[L:L2], 'little')
            SB:tuple[int, int, int, int] = self.multiply(G, s, False)
            hashed:bytes = hashlib.sha512(self.toBytes(R) + self.toBytes(A) + msg).digest()
            
            if None in SB: return False
            if not zip215 and self.isSmallOrder(A): return False

            k:int = self.modL_LE(hashed)
            RkA:tuple[int, int, int, int] = self.add(R, self.multiply(A, k, False))

            isverified = self.is0(self.clearCofactor(self.add(RkA, self.negate(SB))))
        except:
            return False

        return isverified

    def randomSecretKey(self, seed:bytes=None) -> bytes:
        return secrets.token_bytes(L) if not isinstance(seed, bytes) else seed
    
    def keygen(self, seed:bytes=None) -> tuple[bytes, bytes]:
        secret_key:bytes = self.randomSecretKey(seed)
        public_key:bytes = self.getPublicKey(secret_key)

        return (secret_key, public_key)

minScalar:int = 2 ** 254
maxAdded:int = 8 * 2 ** 251 - 1
maxScalar:int = minScalar + maxAdded + 1
class X25519(Ed25519):
    def __init__(self):
        super().__init__()

    def adjustScalarBytes(self, sb:bytes) -> bytes:
        data:bytearray = bytearray(sb)
        data[0] &= 248
        data[31] &= 127
        data[31] |= 64

        return data

    def powPminus2(self, x:int) -> int:
        p58, b2 = self.pow_2_252_3(x)

        return self.M(self.pow2(p58, 3) * b2)

    def encodeU(self, u:int) -> bytes:
        return int.to_bytes(self.M(u), 32, 'little')

    def decodeU(self, u:bytes) -> int:
        data:bytearray = bytearray(u)
        data[31] &= 127

        return self.M(int.from_bytes(data, 'little'))

    def cswap(self, swap:int, x2:int, x3:int) -> tuple[int, int]:
        dummy:int = self.M(swap * (x2 - x3))
        
        return (self.M(x2 - dummy), self.M(x3 + dummy)) 

    def montgomeryLadder(self, u:int, scalar:int) -> int|None:
        if self.arange(u, 0, P) is None: return None
        if self.arange(scalar, minScalar, maxScalar) is None: return None

        k, x1, x2, z2, x3, z3, swap = (scalar, u, 1, 0, u, 1, 0)
        t:int = 254 # 255 - 1
        a24:int = 121665
        while t >= 0:
            kt:int = (k >> t) & 1
            swap ^= kt
            x2, x3 = self.cswap(swap, x2, x3)
            z2, z3 = self.cswap(swap, z2, z3)
            swap = kt

            A:int = x2 + z2
            AA:int = self.M(A * A)
            B:int = x2 - z2
            BB:int = self.M(B * B)
            E:int = AA - BB
            C:int = x3 + z3
            D:int = x3 - z3
            DA:int = self.M(D * A)
            CB:int = self.M(C * B)
            dacb:int = DA + CB
            da_cb:int = DA - CB
            x3:int = self.M(dacb * dacb)
            z3:int = self.M(x1 * self.M(da_cb * da_cb))
            x2:int = self.M(AA * BB)
            z2:int = self.M(E * (AA + self.M(a24 * E)))

            t -= 1
        
        x2, x3 = self.cswap(swap, x2, x3)
        z2, z3 = self.cswap(swap, z2, z3)
        z2 = self.powPminus2(z2)

        return self.M(x2 * z2)

    def decodeScalar(self, scalar:bytes) -> int | None:
        if not isinstance(scalar, bytes) or len(scalar) != 32: return None
        return int.from_bytes(self.adjustScalarBytes(scalar), 'little')

    def scalarMult(self, scalar:bytes, u:bytes) -> bytes|None:
        pu:int = self.montgomeryLadder(self.decodeU(u), self.decodeScalar(scalar))
        if pu == 0: return None

        return self.encodeU(pu)
    
    def scalarMultBase(self, scalar:bytes) -> bytes:
        return self.scalarMult(scalar, self.encodeU(9))

    def getSharedSecret(self, seckeyA:bytes, pubkeyB:bytes) -> bytes:
        return self.scalarMult(seckeyA, pubkeyB)

    def getPublicKey(self, priv:bytes) -> bytes:
        return self.scalarMultBase(priv)

    def keygen(self, seed:bytes=None) -> tuple[bytes, bytes]:
        secret_key:bytes = self.randomSecretKey(seed)
        public_key:bytes = self.getPublicKey(secret_key)

        return (secret_key, public_key)
