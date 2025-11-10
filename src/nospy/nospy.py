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
            timeout:float=1.5,
            server_on:bool=False,
            server_host:str="0.0.0.0",
            server_port:int=8080,
            server_route:str="/",
            server_ssl_on:bool=False,
            ssl_certfile:str="",
            ssl_keyfile:str="",
            client_ssl_on:bool=True,
        ):
        super(Nostr, self).__init__(
            url=url,
            ping=ping,
            reconnect_on=reconnect_on,
            reconnect_max=reconnect_max,
            timeout=timeout,
            server_host=server_host,
            server_port=server_port,
            server_route=server_route,
            server_ssl_on=server_ssl_on,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            client_ssl_on=client_ssl_on,
        )

        self.skey = self.generateSecretKey(skey)
        self.pubkey = self.generatePublicKey(self.skey)
        self.url = url
        self.server_on = server_on

    def generateSecretKey(self, sk:bytes|str = None) -> bytes:
        if type(sk) is str:
            sk = self.bech32_decode(sk)[1]
            if not sk:
                try:
                    sk = bytes.fromhex(sk)
                except:
                    sk = None
        return self.randomSecretKey() if sk is None else sk
    
    def generatePublicKey(self, sk:bytes|str = None) -> str:
        if type(sk) is str:
            sk = self.bech32_decode(sk)[1]
            if not sk:
                try:
                    sk = bytes.fromhex(sk)
                except:
                    sk = None
        return self.getPublicKey(sk if sk is not None else self.skey)[1:].hex()

    async def __aenter__(self):
        if self.server_on:
            await self.server_start()
        if self.url != "":
            await self.connect(url=self.url)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if self.server_on:
            if self.server_runner is not None:
                await self.server_runner.cleanup()
        if self.connected:
            await self.close()
        return False