from aiohttp import ClientSession
from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from math import floor, log2
import bech32
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
import unicodedata

from .bip0032 import Bip0032
from .bip0039 import Bip0039
from .bip0340 import Bip0340

class Nip04(Bip0340):
    def __init__(self):
        super(Nip04, self).__init__()

    def aes_encrypt(self, seckey:bytes, pubkey:str, text:str) -> str:
        privkey = seckey
        key = self.getSharedSecret(privkey, bytes.fromhex('02' + pubkey))
        normkey = self.getNormalizedX(key)

        iv = secrets.token_bytes(16)
        plaintext = text.encode('utf-8')

        ciphertext = AES.new(normkey, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))

        ctb64 = b64encode(ciphertext).decode()
        ivb64 = b64encode(iv).decode()

        return str(f"{ctb64}?iv={ivb64}")

    def aes_decrypt(self, seckey:bytes, pubkey:str, data:str) -> str:
        privkey = seckey
        (ctb64, ivb64) = data.split('?iv=')
        key = self.getSharedSecret(privkey, bytes.fromhex('02' + pubkey))
        normkey = self.getNormalizedX(key)

        iv = b64decode(ivb64)
        ciphertext = b64decode(ctb64)

        plaintext = unpad(AES.new(normkey, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)

        return plaintext.decode('utf-8')

    def getNormalizedX(self, key:bytes) -> bytes:
        return key[1:33]

class Nip05:
    def __init__(self):
        super(Nip05, self).__init__()
        # ルートパスを含める
        self.nip05_match = re.compile(r"^(?:([\w.+-]+)@)?([\w_-]+(\.[\w_-]+)+)(/.*)?$")
    
    async def searchDomain(self, domain:str, query:str="") -> dict|None:
        url = f"https://{domain}/.well-known/nostr.json?name={query}"
        async with ClientSession() as session:
            async with session.get(url, allow_redirects=False) as respose:
                    try:
                        json_response = await respose.json()
                        return json_response["names"]
                    except:
                        return None
        
    async def queryProfile(self, event:dict) -> dict|None:
        nip05:tuple = self.parseNip05(event)
        if any((nip05[0] is None, nip05[1] is None, nip05[2] is None)): return None

        route = nip05[2] if nip05[3] is None else nip05[2] + nip05[3]
        query = nip05[1]
        url = f"https://{route}/.well-known/nostr.json?name={query}"

        async with ClientSession() as session:
            async with session.get(url, allow_redirects=False) as respose:
                    try:
                        json_response = await respose.json()
                        pubkey:str = json_response["names"].get(query)
                        relays:dict = json_response.get("relays")
                        relay_list:list = relays.get(pubkey,[]) if relays is not None else []
                        return {pubkey: relay_list} if pubkey else None
                    except:
                        return None

    def parseNip05(self, event:dict) -> tuple[str, str, str, str]|tuple[None, None, None, None]:
        if not isinstance(event, dict): return (None, None, None, None)

        kind, pubkey, content  = (event.get("kind", -1), event.get("pubkey"), event.get("content"))
        if kind != 0: return (None, None, None, None)
        try:
            content:dict = json.loads(content)
            nip05:str = content.get("nip05")
            if pubkey is None or nip05 is None: return (None, None, None, None)
            match_value = self.nip05_match.match(nip05)
            name, domain, _, routepath = match_value.groups() if match_value is not None else (None, None, None, None)
        except:
            return (None, None, None, None)

        return (pubkey, name, domain, routepath)

class Nip06(Bip0032, Bip0039):
    def __init__(self):
        super(Nip06, self).__init__()
        self.derivation_path = "m/44'/1237'"

    def privateKeyFromSeedWords(self, mnemonic:str, passphrase:str="", accountIndex:int = 0, lang:str="english") -> bytes|None:
        root = self.fromMasterseed(self.mnemonicToSeed(mnemonic, passphrase, lang))
        if root is None: return None
        
        privateKey = root.derive(f"{self.derivation_path}/{accountIndex}'/0/0").getprivateKey()
        if privateKey is None: return None

        return privateKey

    def accountFromSeedWords(self, mnemonic:str, passphrase:str="", accountIndex:int = 0, lang:str="english") -> tuple[bytes, str]|tuple[None, None]:
        root = self.fromMasterseed(self.mnemonicToSeed(mnemonic, passphrase, lang))
        if root is None: return (None, None)
        
        seed = root.derive(f"{self.derivation_path}/{accountIndex}'/0/0")
        if seed is None: return (None, None)

        try:
            publicKey = seed.getpublicKey()[1:].hex()
        except:
            return (None, None)
        privateKey = seed.getprivateKey()
        if privateKey is None or publicKey is None: return (None, None)

        return (privateKey, publicKey)

    def extendedKeysFromSeedWords(self, mnemonic:str, passphrase:str="", accountIndex:int = 0, lang:str="english") -> tuple[str, str]|tuple[None, None]:
        root = self.fromMasterseed(self.mnemonicToSeed(mnemonic, passphrase, lang))
        if root is None: return None

        seed = root.derive(f"{self.derivation_path}/{accountIndex}'")
        if seed is None: return None

        privateExtendedKey = seed.getprivateExtendedKey()
        publicExtendedKey = seed.getpublicExtendedKey()

        return (privateExtendedKey, publicExtendedKey)

    def accountFromExtendedKey(self, base58Key:str, accountIndex = 0, lang:str="english") -> tuple[bytes, str]|tuple[None, None]:
        extendedKey = self.fromExtendedKey(base58Key)
        if extendedKey is None: return (None, None)

        version = base58Key[0:4]
        
        child = extendedKey.deriveChild(0).deriveChild(accountIndex)
        if child is None: return (None, None)

        try:
            publicKey = child.getpublicKey()[1:].hex()
        except:
            publicKey = None
        privateKey = child.getprivateKey() if version == 'xprv' else None

        return (privateKey, publicKey)

    def generateSeedWords(self, lang:str="english"):
        return self.generateMnemonic(lang)

    def validateWords(self, words:str, lang:str="english"):
        return self.validateMnemonic(words, lang)

class Nip13:
    def __init__(self):
        super(Nip13, self).__init__()
    
    def getPow(self, hex:str) -> int|None:
        try:
            id:bytes = bytes.fromhex(hex)
        except:
            return None

        return tuple((byte >> (7 - i)) & 1 for byte in id for i in range(8)).index(1, 0)
    
    def minePow(self, event:dict, difficulty:int) -> dict|None:
        count = 0
        tag = ['nonce', f'{count}', f'{difficulty}']
        keys = ['pubkey', 'created_at', 'kind', 'tags', 'content']

        if not all([True if key in event.keys() else False for key in keys]): return None
        if not isinstance(event['tags'], list): return None
        unsignedevent:dict = {key: value for key, value in event.items() if key in keys}

        unsignedevent['tags'].append(tag)
        
        while True:
            now = int(time.time())
            if now != unsignedevent['created_at']:
                count = 0
                unsignedevent['created_at'] = now
            
            count += 1
            
            unsignedevent['tags'][-1][1] = f"{count}"
            unsignedevent['id'] = self.fastEventHash(unsignedevent)

            try:
                if self.getPow(unsignedevent['id']) >= difficulty: break
            except:
                return None
        
        return unsignedevent

    def fastEventHash(self, event:dict) -> str:
        try:
            return hashlib.sha256(
                json.dumps(
                    [0, 
                    event['pubkey'], 
                    event['created_at'], 
                    event['kind'], 
                    event['tags'], 
                    event['content']
                    ],
                    ensure_ascii=False,
                    separators=(',', ':')
                ).encode('utf-8')
            ).hexdigest()
        except:
            return ""

class Nip19:
    def __init__(self):
        super(Nip19, self).__init__()

    def bech32_encode(self, entity:bytes|str|dict=None, prefix:str="") -> str:
        result:str = ""
        def encode_tlv(data:dict, prefix:str):
            tlv_bytes:bytes = None
            tlv_list:list[tuple] = []
            tlv_tuple:tuple = None
            (t, l, v) = (int(0), int(0), bytes(0))

            # dictからTLVに変換
            match(prefix):
                case 'nprofile':
                    for key, value in data.items():
                        match(key):
                            case 'pubkey':
                                t = 0
                                v = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
                                l = len(v)
                                tlv_tuple = (t, l, v)
                                tlv_list.append(tlv_tuple)
                            case 'relays':
                                if not isinstance(value, list): continue
                                for relay in value:
                                    t = 1
                                    v = str(relay).encode('utf-8') if isinstance(relay, str) else bytes(relay)
                                    l = len(v)
                                    tlv_tuple = (t, l, v)
                                    tlv_list.append(tlv_tuple)
                            case '':
                                pass
                case 'nevent':
                    for key, value in data.items():
                        match(key):
                            case 'id':
                                t = 0
                                v = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
                                l = len(v)
                                tlv_tuple = (t, l, v)
                                tlv_list.append(tlv_tuple)
                            case 'relays':
                                if not isinstance(value, list): continue
                                for relay in value:
                                    t = 1
                                    v = str(relay).encode('utf-8') if isinstance(relay, str) else bytes(relay)
                                    l = len(v)
                                    tlv_tuple = (t, l, v)
                                    tlv_list.append(tlv_tuple)
                            case 'author':
                                t = 2
                                v = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
                                l = len(v)
                                tlv_tuple = (t, l, v)
                                tlv_list.append(tlv_tuple)
                            case 'kind':
                                t = 3
                                v = struct.pack('B', value)
                                l = len(v)
                                tlv_tuple = (t, l, v)
                                tlv_list.append(tlv_tuple)
                            case _:
                                pass
                case 'naddr':
                    for key, value in data.items():
                        match(key):
                            case 'identifier':
                                t = 0
                                v = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
                                l = len(v)
                                tlv_tuple = (t, l, v)
                                tlv_list.append(tlv_tuple)
                            case 'relays':
                                if not isinstance(value, list): continue
                                for relay in value:
                                    t = 1
                                    v = str(relay).encode('utf-8') if isinstance(relay, str) else bytes(relay)
                                    l = len(v)
                                    tlv_tuple = (t, l, v)
                                    tlv_list.append(tlv_tuple)
                            case 'pubkey':
                                t = 2
                                v = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
                                l = len(v)
                                tlv_tuple = (t, l, v)
                                tlv_list.append(tlv_tuple)
                            case 'kind':
                                t = 3
                                v = struct.pack('B', value)
                                l = len(v)
                                tlv_tuple = (t, l, v)
                                tlv_list.append(tlv_tuple)
                            case _:
                                pass
                case _:
                    pass
            
            # TLVをbytesに変換
            for tlv in tlv_list:
                tag_bytes = struct.pack('B', tlv[0])
                length_bytes = struct.pack('B', tlv[1])
                value_bytes = tlv[2]
                if tlv_bytes:
                    tlv_bytes += tag_bytes + length_bytes + value_bytes
                else:
                    tlv_bytes = tag_bytes + length_bytes + value_bytes
            
            return tlv_bytes
        
        match(prefix):
            case 'nsec'|'npub'|'note'|'nostr:':
                data = None
                if isinstance(entity, bytes):
                    data = entity
                elif isinstance(entity, str):
                    try:
                        data = bytes.fromhex(entity)
                    except:
                        pass
                else:
                    pass
                if data:
                    result = bech32.bech32_encode(prefix, bech32.convertbits(list(data), 8, 5, True))
                pass
            case 'nprofile'|'nevent'|'naddr':
                data = None
                if isinstance(entity, dict):
                    data = entity
                else:
                    pass
                if data:
                    tlv_bytes = encode_tlv(data, prefix)
                    if tlv_bytes:
                        result = bech32.bech32_encode(prefix, bech32.convertbits(list(tlv_bytes), 8, 5, True))
                    else:
                        pass
            case _:
                pass
        
        return result

    def bech32_decode(self, entity:str="") -> tuple[str,bytes|dict]:
        result:tuple = (None, None)
        # methods
        def parse_tlv(data:bytes) -> list[dict]:
            tlvs:list = []
            datalengh = len(data)
            tlv = (int(0), int(0), bytes(0))
            i = 0
            while i  < datalengh:
                if i + 2 > datalengh or i + 2 + data[i + 1] > datalengh:
                    # 無効なTLVデータ
                    return []
                tlv = (int(data[i]), int(data[i + 1]), bytes(data[i + 2:i + 2 + data[i + 1]]))
                tlvs.append({'type':tlv[0], 'length':tlv[1], 'value':tlv[2]})
                i += 2 + tlv[1]
            
            return tlvs
        
        if isinstance(entity, str):
            (hrp, data) = bech32.bech32_decode(entity)
            data_bytes = bytes(bech32.convertbits(data, 5, 8, False))
            match hrp:
                case 'nsec'|'npub'|'note'|'nostr:':
                    result = (hrp, data_bytes)
                case 'nprofile':
                    tlvs = parse_tlv(data_bytes)
                    profile_data:dict = {
                        'pubkey':"",
                        'relays':[],
                    }
                    for tlv in tlvs:
                        match(tlv['type']):
                            case 0:
                                # special pubkey
                                profile_data['pubkey'] = bytes(tlv['value']).hex()
                            case 1:
                                # relay
                                profile_data['relays'].append(bytes(tlv['value']).decode('ascii'))
                            case _:
                                pass
                    result = (hrp, profile_data)
                case 'nevent':
                    tlvs = parse_tlv(data_bytes)
                    nevent_data:dict = {
                        'id':"",
                        'relays':[],
                        'author':None,
                        'kind':None,
                    }
                    for tlv in tlvs:
                        match(tlv['type']):
                            case 0:
                                # special event id
                                nevent_data['id'] = bytes(tlv['value']).hex()
                            case 1:
                                nevent_data['relays'].append(bytes(tlv['value']).hex())
                            case 2:
                                nevent_data['author'] = bytes(tlv['value']).hex()
                            case 3:
                                nevent_data['kind'] = int.from_bytes(bytes(tlv['value']), 'big')
                            case _:
                                pass
                    result = (hrp, profile_data)
                case 'naddr':
                    tlvs = parse_tlv(data_bytes)
                    naddr_data = {
                        'identifier':"",
                        'pubkey':"",
                        'kind':0,
                        'relays':[]
                    }
                    for tlv in tlvs:
                        match(tlv['type']):
                            case 0:
                                # special identifier
                                naddr_data['identifier'] = bytes(tlv['value']).hex()
                            case 1:
                                naddr_data['relays'].append(bytes(tlv['value']).hex())
                            case 2:
                                naddr_data['pubkey'] = bytes(tlv['value']).hex()
                            case 3:
                                naddr_data['kind'] = int.from_bytes(bytes(tlv['value']), 'big')
                            case _:
                                pass
                    result = (hrp, naddr_data)
                case _:
                    pass
        
        return result
    
class Nip42:
    def __init__(self):
        super(Nip42, self).__init__()
        self.challenge_nip42:str = ""

    def makeAuthEvent(self, relayURL:str="", kind:int=0) -> dict:
        return {
            'kind': kind,
            'created_at': int(time.time()),
            'tags':[
                ['relay', relayURL],
                ['challenge', self.challenge_nip42]
            ],
            'content':"",
        }
    
    def getChallenge(self, event:list=[]) -> str:
        self.challenge_nip42 = event[1]  if event[0] == "AUTH" else ""
        return self.challenge_nip42

class Nip44(Bip0340):
    def __init__(self):
        super(Nip44, self).__init__()
    
    def chacha20_encrypt(self, seckey:bytes, pubkey:str, plaintext:str) -> str|None:
        b64ciphertext:str = None

        nonce = secrets.token_bytes(32)
        conversation_key = self.get_conversation_key(seckey, pubkey)
        (chacha_key, chacha_nonce, hmac_key) = self.get_message_keys(conversation_key, nonce)
        if not all([chacha_key, chacha_nonce, hmac_key]): return None
        
        padded = self.pad(plaintext)
        ciphertext = ChaCha20.new(key=chacha_key, nonce=chacha_nonce).encrypt(padded)
        mac = self.hmac_aad(hmac_key, ciphertext, nonce)
        b64ciphertext = b64encode(self.write_u8(2) + nonce + ciphertext + mac).decode() if mac else None

        return b64ciphertext
    
    def chacha20_decrypt(self, seckey:bytes, pubkey:str, b64ciphertext:str) -> str|None:
        plaintext:str = None
        
        (nonce, ciphertext, mac) = self.decode_payload(b64ciphertext)
        if not all([nonce, ciphertext, mac]): return None
        
        conversation_key = self.get_conversation_key(seckey, pubkey)
        (chacha_key, chacha_nonce, hmac_key) = self.get_message_keys(conversation_key, nonce)
        if not all([chacha_key, chacha_nonce, hmac_key]): return None
        
        calculated_mac = self.hmac_aad(hmac_key, ciphertext, nonce)
        if not self.is_equal_ct(calculated_mac, mac): return None

        plaintext = self.unpad(ChaCha20.new(key=chacha_key, nonce=chacha_nonce).decrypt(ciphertext))

        return plaintext

    def get_message_keys(self, conversation_key:bytes, nonce:bytes) -> tuple[bytes, bytes, bytes]|tuple[None, None, None]:
        if len(conversation_key) != 32: return (None, None, None)
        if len(nonce) != 32: return (None, None, None)

        keys = HKDF(conversation_key, 76, nonce, SHA256, 1)
        chacha_key = keys[0:32]
        chacha_nonce = keys[32:44]
        hmac_key = keys[44:76]

        return (chacha_key, chacha_nonce, hmac_key)

    def get_conversation_key(self, seckey:bytes, pubkey:str) -> bytes:
        shared_x = self.getSharedSecret(seckey,bytes.fromhex('02' + pubkey))

        return HKDF(shared_x, 32, str('nip44-v2').encode('utf-8'), SHA256, 1)

    def hmac_aad(self, key:bytes, ciphertext:bytes, aad:bytes) -> bytes|None:
        if len(aad) != 32: return None
        
        return hmac.new(key, ciphertext + aad, digestmod=hashlib.sha256).digest()

    def decode_payload(self, payload:str) -> tuple[bytes, bytes, bytes]|tuple[None, None, None]:
        plen = len(payload)
        if plen == 0 or payload[0] == '#': return (None, None, None)
        if plen < 132 or plen > 87472: return (None, None, None)
        
        data = b64decode(payload)
        dlen = len(data)
        
        if dlen < 99 or dlen > 65603: return (None, None, None)
        
        vers = data[0]
        if vers != 2: return (None, None, None)
        
        nonce = data[1:33]
        ciphertext = data[33:dlen - 32]
        mac = data[dlen - 32:dlen]

        return (nonce, ciphertext, mac) 

    def pad(self, plaintext:str) -> bytes:
        unpadded:bytes = str(plaintext).encode('utf-8')
        unpadded_len = len(unpadded)        
        
        prefix = self.write_u16_be(unpadded_len)
        suffix = self.zeros(self.calc_padded_len(unpadded_len) - unpadded_len)
        
        return prefix + unpadded + suffix

    def unpad(self, padded:bytes) -> str|None:
        unpadded_len = int.from_bytes(padded[0:2])
        unpadded = bytes(padded[2:2+unpadded_len])

        if any([
            unpadded_len <= 0,
            unpadded_len > 65535,
            len(unpadded) != unpadded_len,
            len(padded) != 2 + self.calc_padded_len(unpadded_len)
        ]): return None
        
        return unpadded.decode('utf-8')

    def calc_padded_len(self, unpadded_len:int) -> int:
        next_power = 1 << (floor(log2(unpadded_len - 1))) + 1 if unpadded_len > 1 else 1
        
        chunk = 32 if next_power <= 256 else next_power // 8

        return chunk * (floor((unpadded_len - 1) // chunk) + 1) if unpadded_len > 32 else 32
    
    def write_u16_be(self, num:int) -> bytes|None:
        if isinstance(num, int) and 0 <= num and num <= 65535:
            return struct.pack('>H', num)
        else:
            return None
    
    def write_u8(self, num:int) -> bytes|None:
        if isinstance(num, int) and 0 <= num and num <= 255:
            return struct.pack('>B', num)
        else:
            return None
        
    def zeros(self, length:int) -> bytes|None:
        if length < 0:
            return None
        else:
            return bytearray(length)
    
    def is_equal_ct(self, a:bytes, b:bytes) -> bool:
        if len(a) != len(b): return False

        diff:int = 0
        for i in range(len(a)):
            diff |= a[i] ^ b[i]
        
        return True if diff == 0 else False 
    
class Nip49:
    def __init__(self):
        super(Nip49, self).__init__()

        self.scrypt_max:int = 340282366920938463463374607431768211456

    def secret_encrypt(self, seckey:bytes, password:str, logn:int=16, ksb:int=0x02) -> str|None:
        if ksb not in(0x00, 0x01, 0x02): return None

        salt:bytes = secrets.token_bytes(16)
        
        n:int = 2 ** logn
        if any([n <=1, n >= self.scrypt_max]): return None

        maxmem:int = ((n * 9 * 128) + 1 * 32)
        try:
            key:bytes = hashlib.scrypt(password=unicodedata.normalize('NFKC', password).encode('utf-8'), salt=salt, n=n, r=8, p=1, maxmem=maxmem, dklen=32)
        except:
            return None
        
        nonce:bytes = secrets.token_bytes(24)
        aad:bytes = bytes([ksb])
        
        xc2p1 = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        xc2p1.update(aad)
        ciphertext = xc2p1.encrypt(seckey)
        
        b = bytes([0x02]) + bytes([logn]) + salt + nonce + aad + ciphertext
        
        return bech32.bech32_encode('ncryptsec', bech32.convertbits(list(b), 8, 5, True))

    def secret_decrypt(self, ncryptsec:str, password:str) -> bytes|None:
        if not isinstance(ncryptsec, str): return None
        prefix, data = bech32.bech32_decode(ncryptsec)
        if prefix != 'ncryptsec': return None
        
        b:bytes = bytes(bech32.convertbits(data, 5, 8, False))

        version:int = b[0]
        if version != 0x02: return None

        logn:int = b[1]
        n:int = 2 ** logn
        if any([n <=1, n >= self.scrypt_max]): return None

        salt:bytes = b[2:18]
        nonce:bytes = b[18:42]
        ksb:int = b[42]
        aad:bytes = bytes([ksb])
        ciphertext:bytes = b[43:75]

        maxmem:int = ((n * 9 * 128) + 1 * 32)
        try:
            key:bytes = hashlib.scrypt(password=unicodedata.normalize('NFKC', password).encode('utf-8'), salt=salt, n=n, r=8, p=1, maxmem=maxmem, dklen=32)
        except:
            return None
        
        xc2p1 = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        xc2p1.update(aad)
        seckey:bytes = xc2p1.decrypt(ciphertext)

        return seckey

class Nip57:
    def __init__(self):
        super(Nip57, self).__init__()
    
    async def getZapEndpoint(self, event:dict) -> tuple[str, int, int, str]|None:
        try:
            lnurl:str = ""
            lud06, lud16 = self.parseNip57(event)
            if lud16:
                name, domain = lud16.split('@')
                lnurl = f"https://{domain}/.well-known/lnurlp/{name}"
            elif lud06:
                hrp, data = bech32.bech32_decode(lud06)
                if hrp.lower() != 'LNURL': return None
                lnurl = bytes(bech32.convertbits(data, 5, 8, False)).decode('utf-8')
            else:
                return None
            
            return await self.requestLNURL(lnurl)
        except:
            return None

    def makeZapRequestEvent(self, params:dict) -> dict|None:
        if not isinstance(params, dict): return None
        
        try:
            zr:dict = {
                "kind": 9734,
                "created_at": int(time.time()),
                "content":  params.get("comment",""),
                "tags":[
                    ["p", params["pubkey"] if "pubkey" in params else params["event"]["pubkey"]],
                    ["amount", str(params["amount"])],
                    ["relays", *[k for k in params["relays"]]],
                ]
            }

            if "event" in params:
                zr["tags"].append(["e", params["event"]["id"]])
                if self.isReplaceableKind(params["event"]["kind"]):
                    zr["tags"].append(["a", f"{params["event"]["kind"]}:{params["evnet"]["pubkey"]}:"])
                elif self.isAddressableKind(params["event"]["kind"]):
                    d:tuple = next(((t, v) for t, v in params["event"]["tags"] if t == "d" and v), None)
                    if d is None: return None
                    zr["tags"].append(["a", f"{params["event"]["kind"]:{params["event"]["pubkey"]:{d[1]}}}"])
                zr["tags"].append(["k", str(params["kind"])])
            
            return zr
        except:
            return None
    
    def validateZapRequestEvent(self, zr:dict) -> bool:
        try:
            p:tuple = next(((t, v) for t, v in zr["tags"] if t == "p" and v), None)
            if p is None: return False
            if re.match(r'^[a-f0-9]{64}$', p[1]) is None: return False

            e:tuple = next(((t,v) for t, v in zr["tags" ] if t == "e" and v), None)
            if e is not None and re.match(r'^[a-f0-9]{64}$', e[1]) is None: return False

            relays:tuple = next(((t, v) for t, v in zr["tags"] if t == "relays" and v), None)
            if relays is None: return False

            return True
        except:
            return False

    def makeZapReceiptEvent(self, zr:dict, bolt11:str, paidat:int, preimage:str=None) -> dict|None:
        try:
            if not all([
                isinstance(zr, dict),
                isinstance(bolt11, str),
                isinstance(paidat, int)
            ]): return None
            
            tags:list[list[str]] = list(filter(lambda x: any((x[0] == "e", x[0] == "p", x[0] == "a")) ,zr["tags"]))
            tags_must:list[list[str]] = [["P", zr["pubkey"]], ["bolt11", bolt11], ["description", json.dumps(zr)]]
            tags_append:list[list[str]] = tags_must.append(["preimage", preimage]) if preimage is not None else tags_must
            tags.append([tags in tags_append])
            
            zap:dict = {
                "kind": 9735,
                "created_at": int(time.time()),
                "content": "",
                "tags": tags
            }

            return zap
        except:
            return None

    def getSatoshisAmount(self, bold11:str) -> int:
        if isinstance(bold11, str) and len(bold11) < 50: return 0
        
        try:
            hrp:str = bold11[0: bold11[0:50].rindex("1")]
            if not hrp.startswith("lnbc"): return 0
            
            amount:str = hrp[len("lnbc")]
            if len(amount) < 1: return 0

            c:str = amount[len(amount) - 1]
            numlastindex:int = len(amount) - 1 if c.isalpha() else len(amount)
            num:int = int(amount[0:numlastindex])

            satoshi_amount:int = 0
            match c:
                case "m":
                    satoshi_amount = num * 100000
                case "u":
                    satoshi_amount = num * 100
                case "n":
                    satoshi_amount = num // 10
                case "p":
                    satoshi_amount = num // 10000
                case _:
                    satoshi_amount = num * 100000000
            
            return satoshi_amount
        except:
            return 0
    
    def paramProfileZap(self, pubkey:str, amount:int, relays:list[str], comment:str=None) -> dict|None:
        try:
            if not all([
                isinstance(pubkey, str),
                isinstance(amount, int),
                isinstance(relays, list),
            ]): return None
            if not all((isinstance(relay, str) for relay in relays)): return None
            params = {
                "pubkey": pubkey,
                "amount": amount,
                "comment": comment if isinstance(comment, str) else "",
                "relays": relays
            }

            return params
        except:
            return None
    
    def paramEventZap(self, event:dict, amount:int, relays:list[str], comment:str=None) -> dict|None:
        try:
            if not all([
                isinstance(event, dict),
                isinstance(amount, int),
                isinstance(relays, list),
            ]): return None
            if not all((isinstance(relay, str) for relay in relays)): return None
            params = {
                "event": event,
                "amount": amount,
                "comment": comment if comment is not None else "",
                "relays": relays
            }

            return params
        except:
            return None

    async def requestLNURL(self, lnurl:str) -> tuple[str, int, int, str]|None:
        async with ClientSession() as session:
            async with session.get(lnurl) as respose:
                    try:
                        json_response = await respose.json()
                        callback, minSendable, maxSendable, allowsNostr, nostrPubkey = (
                            json_response.get("callback"),
                            json_response.get("minSendable"), 
                            json_response.get("maxSendable"),
                            json_response.get("allowsNostr"), 
                            json_response.get("nostrPubkey"),
                        )
                        return (callback, minSendable, maxSendable, nostrPubkey) if allowsNostr else None
                    except:
                        return None         

    def parseNip57(self, event:dict) -> tuple[str, str]|tuple[None, None]:
        if not isinstance(event, dict): return (None, None)

        kind, pubkey, content  = (event.get("kind", -1), event.get("pubkey"), event.get("content"))
        if kind != 0: return (None)
        
        lud06:str = None
        lud16:str = None
        try:
            content:dict = json.loads(content)
            lud06, lud16 = (content.get("lud06"), content.get("lud16"))
            if pubkey is None or (lud06 is None and lud16 is None): return (None, None)
            
            return (lud06, lud16)
        except:
            return (None, None)
    
    def isReplaceableKind(self, kind:int) -> bool:
        # implement on kinds.py
        return True
    
    def isAddressableKind(self, kind:int) -> bool:
        # implement on kinds.py
        return True

class Nips(
    Nip04,
    Nip05,
    Nip06,
    Nip13,
    Nip19,
    Nip42,
    Nip44,
    Nip49,
    Nip57,
):
    def __init__(self):
        super(Nips, self).__init__()