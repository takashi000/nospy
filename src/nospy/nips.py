from ecdsa import ECDH, SECP256k1
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from math import floor, log2
import bech32
import hashlib
import hmac
import secrets
import struct
import time

class Nip04:
    def __init__(self):
        super(Nip04, self).__init__()

    def aes_encrypt(self, seckey:bytes, pubkey:str, text:str) -> str:
        privkey = seckey
        key = self.getSharedSecret(privkey, pubkey)
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
        key = self.getSharedSecret(privkey, pubkey)
        normkey = self.getNormalizedX(key)

        iv = b64decode(ivb64)
        ciphertext = b64decode(ctb64)

        plaintext = unpad(AES.new(normkey, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)

        return plaintext.decode('utf-8')

    def getNormalizedX(self, key:bytes) -> bytes:
        return key[0:33]
    
    def getSharedSecret(self, seckey:bytes, pubkey:str) -> bytes:
        privkey = seckey
        publickey = bytes.fromhex('02' + pubkey)

        ecdh = ECDH(curve=SECP256k1)
        ecdh.load_private_key_bytes(private_key=privkey)
        
        ecdh.load_received_public_key_bytes(public_key_str=publickey)

        shared = ecdh.generate_sharedsecret_bytes()
        
        return shared

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
        self.challenge:str = ""

    def makeAuthEvent(self, relayURL:str="", kind:int=0):
        return {
            'kind': kind,
            'created_at': int(time.time()),
            'tags':[
                ['relay', relayURL],
                ['challenge', self.challenge]
            ],
            'content':"",
        }
    
    def getChallenge(self, event:list=[]):
        if event[0] == "AUTH":
            self.challenge = event[1]

class Nip44:
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
        privkey = seckey
        publickey = bytes.fromhex('02' + pubkey)

        ecdh = ECDH(curve=SECP256k1)
        ecdh.load_private_key_bytes(private_key=privkey)
        ecdh.load_received_public_key_bytes(public_key_str=publickey)

        shared_x = ecdh.generate_sharedsecret_bytes()

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

        return chunk * (floor((len - 1) // chunk) + 1) if unpadded_len > 32 else 32
    
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

class Nips(
    Nip04,
    Nip19,
    Nip42,
    Nip44,
):
    def __init__(self):
        super(Nips, self).__init__()