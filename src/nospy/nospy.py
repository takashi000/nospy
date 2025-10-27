import secrets

from .bip0340 import pubkey_gen
from .relay import Relay

class Nostr(Relay):
    def __init__(
            self, 
            skey:bytes|str=None, 
            pkey:bytes|str=None, 
            url:str="", 
            ping:bool=False, 
            reconnect_on:bool=True,
            reconnect_max:int=3,
            timeout:float=1.5
        ):
        super(Nostr, self).__init__(url=url, ping=ping, reconnect_on=reconnect_on, reconnect_max=reconnect_max, timeout=timeout)

        self.skey = self.generateSecretKey(skey)
        self.pubkey = self.getPublicKey(self.skey)
        self.url = url

    def generateSecretKey(self, sk:bytes|str = None) -> bytes:
        if type(sk) is str:
            sk = self.bech32_decode(sk)[1]
            if not sk:
                try:
                    sk = bytes.fromhex(sk)
                except:
                    sk = None
        return secrets.token_bytes(32) if sk is None else sk
    
    def getPublicKey(self, sk:bytes|str = None) -> str:
        if type(sk) is str:
            sk = self.bech32_decode(sk)[1]
            if not sk:
                try:
                    sk = bytes.fromhex(sk)
                except:
                    sk = None
        return pubkey_gen(sk if sk is not None else self.skey).hex()

    async def __aenter__(self):
        await self.connect(url=self.url)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()
        return False