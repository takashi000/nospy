import asyncio

from nospy import Nostr

"""
NIP04でメッセージを暗号化したメッセージを作成する例
<your secret key> := npub or hex
<relay url> := wss://...
"""

async def main():
    async with Nostr(
        skey="<your secret key>",
        url="<relay url>",
    ) as nostr:
        nostr.addFilters(kinds=[1])
        await nostr.subscribe(id="59223")
        for _ in range(5):
            print(">>>", end="")
            content = input("")
            cipher = nostr.aes_encrypt(nostr.skey, nostr.pubkey, content)
            print(cipher)
            plaintext = nostr.aes_decrypt(nostr.skey, nostr.pubkey, cipher)
            print(plaintext)

if __name__ == "__main__":
    asyncio.run(main())