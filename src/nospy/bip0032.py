from __future__ import annotations

import hashlib
import hmac
import re

from .base58 import b58encode_check, b58decode_check
from .bip0340 import Bip0340

bitcoin_versions:dict={"private":b'\x04\x88\xAD\xE4', "public":b'\x04\x88\xB2\x1E'}
hardened_offset:int = 0x80000000

class Bip0032(Bip0340):
    def __init__(
            self,
            versions:dict=bitcoin_versions,
            depth:int=0,
            index:int=0,
            privkey:bytes=None,
            pubkey:bytes=None,
            fingerprint:bytes=bytes(4),
            chaincode:bytes=None,
        ):
        super(Bip0032, self).__init__()
        
        self._privkey = None
        self._pubkey = None
        
        if depth == 0:
            if fingerprint != bytes(4) or index != 0:
                raise ValueError("zero depth with non-zero index/parent fingerprint")
        if depth > 255:
            raise ValueError("depth exceeds the serializable value 255")
        if privkey and pubkey:
            raise ValueError("publicKey and privateKey at same time.")
        if privkey and pubkey is None:
            if not self.isValidSecretKey(privkey): ValueError("Invalid private key")
            self._pubkey = self.getPublicKey(privkey)
            self._privkey = privkey
        elif privkey is None and pubkey:
            self._pubkey = self.toBytes(self.fromBytes(pubkey), True)
            self._privkey = None
        else:
            #raise ValueError("no public or private key provided")
            pass

        self.versions:dict = versions
        self.depth:int = depth
        self.index:int = index
        self.privkey:bytes = privkey
        self.pubkey:bytes = pubkey
        self.fingerprint:bytes = fingerprint
        self.chaincode:bytes = chaincode
        self.pubhash:bytes = hashlib.new('ripemd160', hashlib.sha256(self._pubkey).digest()).digest() if self._pubkey is not None else None

        self.headpath_match = re.compile(r"^[mM]'?")
        self.endpath_match = re.compile(r"^[mM]'?$")
        self.path_sub = re.compile(r"^[mM]'?/")
        self.midpath_match = re.compile(r"^(\d+)('?)$")

    def getfingerprint(self) -> int|None:
        return int.from_bytes(self.pubhash) if self.pubhash is not None else None
    
    def getidentifier(self) -> bytes|None:
        return self.pubhash
    
    def getpubKeyHash(self) -> bytes|None:
        return self.pubhash
    
    def getprivateKey(self) -> bytes|None:
        return self._privkey
    
    def getpublicKey(self) -> bytes|None:
        return self._pubkey
    
    def getprivateExtendedKey(self) -> str|None:
        return b58encode_check(self.serialize(self.versions["private"], bytes(1) + self._privkey)).hex() if self._privkey is not None else None

    def getpublicExtendedKey(self) -> str|None:
        return b58encode_check(self.serialize(self.versions["public"], self._pubkey)).hex() if self._pubkey is not None else None

    def fromMasterseed(self, seed:bytes, versions:dict=bitcoin_versions) -> Bip0032|None:
        if 8 * len(seed) < 128 or 8 * len(seed) > 512: return None

        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        privkey = I[:32]
        chaincode = I[32:]
        
        return Bip0032(
            versions=versions,
            privkey=privkey,
            chaincode=chaincode,
        )
    
    def fromExtendedKey(self, base58_key:str, versions:dict=bitcoin_versions) -> Bip0032|None:
        key_buffer:bytes = b58decode_check(base58_key)
        version:bytes = key_buffer[:4]
        depth:int = key_buffer[4]
        fingerprint:bytes = key_buffer[5:9]
        index:int = int.from_bytes(key_buffer[9:13])
        chaincode:bytes = key_buffer[13:45]
        key_data:bytes = key_buffer[45:]
        is_private = True if key_data[0] == 0x00 else False
        
        version_bytes = versions["private"] if is_private else versions["public"]
        if version != version_bytes: return None
        
        return Bip0032(
            versions=versions, 
            depth=depth,
            index=index,
            privkey=key_data[1:] if is_private else None,
            pubkey=key_data if not is_private else None,
            fingerprint=fingerprint,
            chaincode=chaincode,
        )
    
    def derive(self, path:str) -> Bip0032|None:
        if not self.headpath_match.match(path):
            return None
        
        if self.endpath_match.match(path):
            return self
        
        parts = self.path_sub.sub('', path).split('/')
        child = self
        
        for c in parts:
            m = self.midpath_match.match(c)
            m1 = m.group(1) if m is not None else None
            if any([m is None, len(m.groups()) != 2, not isinstance(m1, str)]):
                return None
            idx = int(m1)
            if not isinstance(idx, int) or idx >= hardened_offset:
                return None
            if m.group(2) == "'":
                idx += hardened_offset
            child = child.deriveChild(idx)
        
        return child
    
    def deriveChild(self, index:int) -> Bip0032|None:
        if self._pubkey is None or self.chaincode is None: return None
        
        data = int.to_bytes(index, 4)
        if index >= hardened_offset:
            priv = self._privkey
            if priv is None: return None
            data = bytes(1) + priv + data
        else:
            data = self._pubkey + data
        
        I = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        childTweak = I[0:32]
        chaincode = I[32:]

        versions = self.versions
        depth = self.depth + 1
        fingerprint = self.fingerprint
        
        privkey = None
        pubkey = None
        ctweak = int.from_bytes(childTweak)
        if self.FnIsValidNot0(ctweak) is None: return None

        try:
            if self._privkey:
                added = self.modN(int.from_bytes(self._privkey) + ctweak)
                if self.FnIsValidNot0(added) is None: raise ValueError("The tweak was out of range or the resulted private key is invalid")
                privkey = int.to_bytes(added, 32)
            else:
                added = self.add(self.fromBytes(self._pubkey), self.multiply(self.base(), ctweak))
                if self.equals(added, self.zero()): raise ValueError("The tweak was equal to negative P, which made the result key invalid")
                pubkey = self.toBytes(added)
            
            return Bip0032(
                versions=versions,
                depth=depth,
                index=index,
                privkey=privkey,
                pubkey=pubkey,
                fingerprint=fingerprint,
                chaincode=chaincode
            )
        except Exception as e:
            print(e)
            return self.deriveChild(index + 1)
    
    def wipePrivateData(self) -> Bip0032|None:
        if self._privkey is not None:
            self._privkey = bytes.zfill(len(self._privkey))
            self._privkey = None
        
        return self
    
    def toJSON(self) -> dict:
        return {
            "xpriv": self.getprivateExtendedKey(),
            "xpub": self.getpublicKey()
        }
    
    def serialize(self, version:bytes, key:bytes) -> bytes|None:
        if self.chaincode is None: return None
        if not isinstance(key, bytes) or len(key) != 33: return None

        return \
            version + \
            int.to_bytes(self.depth, 1) + \
            self.fingerprint + \
            int.to_bytes(self.index, 4) + \
            self.chaincode + \
            key
    