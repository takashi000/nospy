import hashlib
import math
import secrets

secp256k1_CURVE:tuple = (
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, #p
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141, #n
    1, #h
    0, #a
    7, #b
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, #Gx
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, #Gy
)
P, N, _b, Gx, Gy = (secp256k1_CURVE[0], secp256k1_CURVE[1], secp256k1_CURVE[4], secp256k1_CURVE[5], secp256k1_CURVE[6])
L, L2 = (32, 64)
lengths = (
    L + 1,  #publicKey
    L2 + 1, #publicKeyUncompressed
    L2,     #signature
    L + L // 2 #seed
)
G, I = ((Gx, Gy, 1), (0, 1, 0))

W, scalarBits = (8, 256)
pwindows, pwindowSize = (math.ceil(scalarBits / W) + 1, 2 ** (W - 1))

class Bip0340:
    def __init__(self):
        super(Bip0340, self).__init__()
        self.Gpows:list = None

    def base(self) -> tuple[int, int, int]:
        return G
    
    def zero(self) -> tuple[int, int, int]:
        return I

    def arange(self, n:int, min:int, max:int) -> int|None:
        if all([isinstance(n, int), min <= n, n < max]): return n
        return None
    
    def invert(self, num:int, md:int) -> int|None:
        if num == 0 or md <= 0: return None
        a, b, x, y, u, v = (self.M(num, md), md, 0, 1, 1, 0)
        while a != 0:
            q, r = (b // a, b % a)
            m, n = (x - u * q, y - v * q)
            b, a, x , y, u, v = (a, r, u, v, m, n)

        return self.M(x, md) if b == 1 else None
    
    def M(self, a:int, b:int=P) -> int:
        return a % b
    
    def modN(self, a:int) -> int:
        return a % N

    def koblitz(self, x:int) -> int|None:
        return self.M(self.M(x * x) * x + _b)
    
    def FpIsValid(self, n:int) -> int|None:
        return self.arange(n, 0, P)
    
    def FpIsValidNot0(self, n:int) -> int|None:
        return self.arange(n, 1, P)
    
    def FnIsValidNot0(self, n:int) -> int|None:
        return self.arange(n, 1, N)
    
    def isEven(self, y:int) -> bool:
        return (y & 1) == 0
    
    def getPrefix(self, y:int) -> bytes:
        return b'\x02' if self.isEven(y) else b'\x03' 

    def lift_x(self, x:int) -> int|None:
        if self.FpIsValidNot0(x) is None: return None
        c = self.koblitz(x)
        if c is None: return None

        r = 1
        (num, e) = (c, (P+1)//4)
        while e > 0:
            if e & 1: r = (r * num) % P
            num = (num * num) % P
            e >>= 1
        
        return r if self.M(r * r) == c else None
    
    def curve(self) -> tuple[int, ...]:
        return secp256k1_CURVE

    def fromAffine(self, ap:tuple[int, int]) -> tuple[int, int, int]:
        x, y = ap
        return  I if x == 0 and y == 0 else (x, y, 1)
    
    def fromBytes(self, data:bytes) -> tuple[int, int, int]|tuple[None, None, None]:
        if not isinstance(data, bytes): return (None, None, None)

        p = None
        comp, uncomp, _, _ = lengths
        length:int = len(data)
        head:bytes = data[0]
        tail:bytes = data[1:]
        x:int = int.from_bytes(tail[0:L])

        if length == comp and (head == 0x02 or head == 0x03):
            y = self.lift_x(x)
            if y is None: return (None, None, None)
            evenY, evenH = (self.isEven(y), self.isEven(head))
            if evenH != evenY: y = self.M(-y)
            p = (x, y, 1)
        
        if length == uncomp and head == 0x04:
            p = (x, int.from_bytes(tail[L:L2]), 1)
        
        return p if p is not None else (None, None, None)
    
    def fromHex(self, hex:str) -> tuple[int, int, int]|tuple[None, None, None]:
        try:
            return self.fromBytes(bytes.fromhex(hex))
        except:
            return (None, None, None)
    
    def getx(self, point:tuple[int, int, int]) -> int:
        return self.toAffine(point)[0]
    
    def gety(self, point:tuple[int, int, int]) -> int:
        return self.toAffine(point)[1]

    def equals(self, point1:tuple[int, int, int], point2:tuple[int, int, int]) -> bool:
        x1, y1, z1 = point1
        x2, y2, z2 = point2
        
        x1z2, x2z1 = (self.M(x1 * z2), self.M(x2 * z1))
        y1z2, y2z1 = (self.M(y1 * z2), self.M(y2 * z1))

        return x1z2 == x2z1 and y1z2 == y2z1
    
    def is0(self, point:tuple[int, int, int]) -> bool:
        return self.equals(point, I)
    
    def negate(self, point:tuple[int, int, int]) -> tuple[int, int, int]:
        return (point[0], self.M(-point[1]), point[2])

    def double(self, point:tuple[int, int, int]) -> tuple[int, int, int]|tuple[None, None, None]:
        return self.add(point, point)

    def add(self, point1:tuple[int, int, int], point2:tuple[int, int, int]) -> tuple[int, int, int]|tuple[None, None, None]:
        if None in point1 or None in point2: return (None, None, None)

        x1, y1, z1 = point1
        x2, y2, z2 = point2
        x3, y3, z3 = (0, 0, 0)
        a = 0
        b = _b
        b3 = self.M(b * 3)

        t0, t1, t2, t3 = (self.M(x1 * x2), self.M(y1 * y2), self.M(z1 * z2), self.M(x1 + y1))
        t4 = self.M(x2 + y2)
        t3, t4 = (self.M(t3 * t4), self.M(t0 + t1))
        t3, t4 = (self.M(t3 - t4), self.M(x1 + z1))
        t5 = self.M(x2 + z2)
        t4, t5 = (self.M(t4 * t5), self.M(t0 + t2))
        t4, t5 = (self.M(t4 - t5), self.M(y1 + z1))
        x3 = self.M(y2 + z2)
        t5, x3 = (self.M(t5 * x3), self.M(t1 + t2))
        t5, z3 = (self.M(t5 - x3), self.M(a * t4))
        x3 = self.M(b3 * t2)
        z3 = self.M(x3 + z3)
        x3 = self.M(t1 - z3)
        z3 = self.M(t1 + z3)
        y3 = self.M(x3 * z3)
        t1 = self.M(t0 + t0)
        t1, t2, t4 = (self.M(t1 + t0), self.M(a * t2), self.M(b3 * t4))
        t1 = self.M(t1 + t2)
        t2 = self.M(t0 - t2)
        t2 = self.M(a * t2)
        t4 = self.M(t4 + t2)
        t0 = self.M(t1 * t4)
        y3 = self.M(y3 + t0)
        t0 = self.M(t5 * t4)
        x3 = self.M(t3 * x3)
        x3 = self.M(x3 - t0)
        t0, z3 = (self.M(t3 * t1), self.M(t5 * z3))
        z3 = self.M(z3 + t0)

        return (x3, y3, z3)
    
    def subtract(self, point1:tuple[int, int, int], point2:tuple[int, int, int]) -> tuple[int, int, int]|tuple[None, None, None]:
        return self.add(point1, self.negate(point2))
    
    def multiply(self, point:tuple[int, int, int], n:int, safe:bool=True) -> tuple[int, int, int]|tuple[None, None, None]:
        if not safe and n == 0: return I
        if self.FnIsValidNot0(n) is None: return (None, None, None)
        if n == 1: return point
        if self.equals(point, G): return self.wNAF(n)[0]
        
        p, f, d = (I, G, point)
        while n > 0:
            if n & 1: p = self.add(p, d) 
            elif safe: f = self.add(f, d)

            d = self.double(d)
            n >>= 1
        
        return p

    def multiplyUnsafe(self, point:tuple[int, int, int], scalar:int) -> tuple[int, int, int]|tuple[None, None, None]:
        return self.multiply(point, scalar, False)

    def toAffine(self, point:tuple[int, int, int]) -> tuple[int, int]|tuple[None, None]:
        x, y, z = point
        if self.equals(point, I): return (0, 0)
        if z == 1: return (x, y)
        iz = self.invert(z, P)
        if iz is None: return (None, None)
        if self.M(z * iz) != 1: return (None, None)
        
        return (self.M(x * iz), self.M(y * iz))

    def isValidity(self, point:tuple[int, int, int]) -> bool:
        x, y = self.toAffine(point)
        if x is None or y is None: return False
        if self.FpIsValidNot0(x) is None or self.FpIsValidNot0(y) is None: return False

        return True if self.M(y * y) == self.koblitz(x) else False
    
    def toBytes(self, point:tuple[int, int, int], isCompressed:bool=True) -> bytes|None:
        if not self.isValidity(point): return None
        
        x, y = self.toAffine(point)
        if x is None or y is None: return None

        x32b, y32b = (int.to_bytes(x, 32), int.to_bytes(y, 32))

        return self.getPrefix(y) + x32b  if isCompressed else b'\x04' + x32b + y32b
    
    def toHex(self, point:tuple[int, int, int], isCompressed:bool=True) -> str|None:
        try:
            return self.toBytes(point, isCompressed).hex()
        except:
            return None

    def precompute(self) -> list[tuple[int, int, int]]:
        points:list = []
        p:tuple[int, int, int] = G
        b:tuple[int, int, int] = p

        for _ in range(pwindows):
            b = p
            points.append(b)
            for _ in range(1, pwindowSize):
                b = self.add(b, p)
                points.append(b)
            p = self.double(b)
        
        return points

    def ctneg(self, cnd:bool, p:tuple[int, int, int]) -> tuple[int, int, int]:
        return self.negate(p) if cnd else p

    def wNAF(self, n:int) -> tuple[tuple[int, int, int], tuple[int, int, int]]|tuple[None, None]:
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
    
    def taggedHash(self, tag: str, messages: list[bytes]) -> bytes:
        tag_hash = hashlib.sha256(('BIP0340/' + tag).encode()).digest()
        return hashlib.sha256(tag_hash + tag_hash + bytes.join(b'', messages)).digest()

    def highS(self, n:int) -> bool:
        return n > N >> 1
    
    def doubleScalarMulUns(self, R:tuple[int, int, int], u1:int, u2:int) -> tuple[int, int, int]|tuple[None, None, None]:
        num = self.add(self.multiply(G, u1, False), self.multiply(R, u2, False))
        return num if self.isValidity(num) else (None, None, None)

    def secretKeyToScalar(self, seckey:bytes) -> int|None:
        if not isinstance(seckey, bytes): return None
        return self.arange(int.from_bytes(seckey), 1, N)
    
    def isValidSecretKey(self, seckey:bytes) -> bool:
        if not isinstance(seckey, bytes) or len(seckey) != L: return False
        if self.arange(int.from_bytes(seckey), 1, N) is None: return False
        
        return True

    def randomSecretKey(self, seed:bytes=secrets.token_bytes(lengths[3])) -> bytes|None:
        if not isinstance(seed, bytes): return None
        if len(seed) < lengths[3] or len(seed) > 1024: return None
        num:int = self.M(int.from_bytes(seed), N - 1)
        
        return  int.to_bytes(num, 32)

    def getPublicKey(self, privKey:bytes, isCompressed:bool = True) -> bytes|None:
        return self.toBytes(self.multiply(G, self.secretKeyToScalar(privKey)), isCompressed)
    
    def getSharedSecret(self, seckeyA:bytes, pubkeyB:bytes, isCompressed:bool = True) -> bytes|None:
        return self.toBytes(self.multiply(self.fromBytes(pubkeyB), self.secretKeyToScalar(seckeyA)), isCompressed)
    
    def extpubSchnorr(self, privkey:bytes) -> tuple[int, bytes]|tuple[None, None]:
        d_:int = self.secretKeyToScalar(privkey)
        p:tuple[int, int, int] = self.multiply(G, d_)
        if not self.isValidity(p): return (None, None)
        x, y = self.toAffine(p)
        d = d_ if self.isEven(y) else self.modN(-d_)
        px = int.to_bytes(x, 32)

        return (d, px)

    def prepSigSchnorr(self, message:bytes, seckey:bytes, auxRand:bytes) -> tuple[bytes, bytes, int, bytes]|tuple[None, None, None, None]:
        if not isinstance(message, bytes) or len(auxRand) != L: return (None, None, None, None)
        
        d, px = self.extpubSchnorr(seckey)
        if px is None or d is None: return (None, None, None, None)

        return (message, px, d, auxRand)
    
    def extractK(self, rand:bytes) -> tuple[int, bytes]|tuple[None, None]:
        k_:int = self.modN(int.from_bytes(rand))
        if k_ == 0: return (None, None)
        d, px = self.extpubSchnorr(int.to_bytes(k_, 32))

        return (d, px)
    
    def createSigSchnorr(self, k:int, px:bytes, e:int, d:int) -> bytes:
        return px + int.to_bytes(self.M(k + e * d, N), 32)

    def challenge(self, messages:list[bytes]) -> int:
        return self.modN(int.from_bytes(self.taggedHash('challenge', messages)))

    def verifySchnorr(self, message:bytes, pubkey:bytes, signature:bytes) -> bool:
        if not all([isinstance(message, bytes), isinstance(pubkey, bytes), isinstance(signature, bytes)]): return False
        
        msg:bytes = message
        pub:bytes = pubkey if len(pubkey) == L else None
        sig:bytes = signature if len(signature) == L2 else None
        if pub is None or sig is None: return False

        x:int = int.from_bytes(pub)
        y:int = self.lift_x(x)
        y_:int = y if self.isEven(y) else self.M(-y)

        P_:tuple[int, int, int] = (x, y_, 1)
        if not self.isValidity(P_): return False
        px:bytes = int.to_bytes(self.toAffine(P_)[0], 32)
        r:int = int.from_bytes(sig[0:L])
        if self.arange(r, 1, P) is None: return False
        s:int = int.from_bytes(sig[L:L2])
        if self.arange(s, 1, N) is None: return False
        i:bytes = int.to_bytes(r, 32) + px + msg

        e:int = self.challenge([i])
        r_x, r_y = self.toAffine(self.doubleScalarMulUns(P_, s, self.modN(-e)))
        if not self.isEven(r_y) or r_x != r: return False

        return True

    def signSchnorr(self, message:bytes, seckey:bytes, auxRand:bytes=secrets.token_bytes(L)) -> bytes|None:
        m, px, d, a = self.prepSigSchnorr(message, seckey, auxRand)
        if a is None: return None
        aux:bytes = self.taggedHash('aux', [a])
        t:bytes = int.to_bytes(d ^ int.from_bytes(aux), 32)
        rand:bytes = self.taggedHash('nonce', [t, px, m])
        k, rx = self.extractK(rand)
        if rx is None or k is None: return None
        e = self.challenge([rx, px, m])
        sig = self.createSigSchnorr(k, rx, e, d)

        if not self.verifySchnorr(m, px, sig): return None

        return sig

