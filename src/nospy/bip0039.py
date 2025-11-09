import hashlib
import unicodedata
import secrets

from .wordlist import get_wordlist, get_wordlist_index_table

class Bip0039:
    def __init__(self):
        super(Bip0039, self).__init__()

    def entropyToMnemonic(self, entropy:bytes, lang:str="english") -> str|None:
        if len(entropy) not in [16, 20, 24, 28, 32]: return None
        
        num_bits_entropy = len(entropy) * 8
        num_bits_checksum = num_bits_entropy // 32
        num_words = (num_bits_entropy + num_bits_checksum) // 11

        checksum = hashlib.sha256(entropy).digest()[0] >> (8 - num_bits_checksum)

        entropy_and_checksum = (
            int.from_bytes(entropy, byteorder="big") << num_bits_checksum
        ) | checksum

        remaining_data = entropy_and_checksum
        wordlist = get_wordlist(lang)
        words:list[str] = []
        for _ in range(num_words):
            index = remaining_data & 0x7FF
            words.append(wordlist[index])
            remaining_data >>= 11
        words.reverse()

        # 日本語の場合は全角スペース、それ以外は半角スペースで連結して返す
        return '\u3000'.join(words) if lang in ["japanese"] else ' '.join(words)

    def mnemonicToEntropy(self, mnemonic:str|list[str], lang:str="english") -> bytes|None:
        if isinstance(mnemonic, str):
            words = mnemonic.split('\u3000') if lang in ["japanese"] else mnemonic.split(' ')
        else:
            words = mnemonic
        
        if len(words) not in [12, 15, 18, 21, 24]: return None
        
        def get_entropy_bits(num_words:int) -> int|None:
            try:
                return {12:128, 15:160, 18:192, 21:224, 24:256}[num_words]
            except KeyError:
                return None

        num_bits_entropy = get_entropy_bits(len(words))
        num_bits_checksum = num_bits_entropy // 32 if num_bits_entropy else None
        if not num_bits_entropy or not num_bits_checksum: return None
        
        index_table = get_wordlist_index_table(lang)

        bits = 0
        for word in words:
            index = index_table.get(unicodedata.normalize('NFKD', word))
            if index is None: return None
            bits = (bits << 11) | index

        checksum = bits & ((1 << num_bits_checksum) - 1)
        entropy_bits = bits >> num_bits_checksum
        entropy = entropy_bits.to_bytes(num_bits_entropy // 8, byteorder="big")

        hash_checksum = hashlib.sha256(entropy).digest()[0] >> (8 - num_bits_checksum)
        if checksum != hash_checksum: return None

        return entropy

    def generateMnemonic(self, lang:str="english", strength:int=128) -> str|None:
        if any([
            not isinstance(strength, int),
            strength % 32 != 0,
            strength > 256
        ]):
            return None

        return self.entropyToMnemonic(secrets.token_bytes(strength // 8), lang)

    def validateMnemonic(self, mnemonic:str|list[str], lang:str="english") -> bool:
        return True if self.mnemonicToEntropy(mnemonic, lang) else False

    def mnemonicToSeed(self, mnemonic:str, passphrase:str="", lang:str="english") -> bytes|None:
        if not self.validateMnemonic(mnemonic, lang): return None

        phrase = unicodedata.normalize('NFKD', mnemonic).encode('utf-8')
        salt = ('mnemonic' + unicodedata.normalize('NFKD', passphrase)).encode('utf-8')

        return hashlib.pbkdf2_hmac("sha512", phrase, salt, 2048)[:64]
