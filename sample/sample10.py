import asyncio

from nospy import Nostr

"""
NIP49で秘密キーを復号化/暗号化する例
"""

async def main():
    async with Nostr(
        skey='ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p',
        secret_password='nostr',
    ) as nostr:
        print("decoded secret key:", nostr.skey.hex())
        
        ncryptsec = nostr.secret_encrypt(nostr.skey, "password", 16)
        print("encrypted secret key:", ncryptsec)

        seckey = nostr.secret_decrypt(ncryptsec, "password")
        print("success:", seckey.hex())

        seckey = nostr.secret_decrypt(ncryptsec, "abc")
        print("fault:",seckey.hex())

if __name__ == "__main__":
    asyncio.run(main())