import asyncio

from nospy import Nostr

"""
NIP44でメッセージを暗号化したメッセージを作成する例
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
            cipher = nostr.chacha20_encrypt(nostr.skey, nostr.pubkey, content)
            print(cipher)
            plaintext = nostr.chacha20_decrypt(nostr.skey, nostr.pubkey, cipher)
            print(plaintext)

if __name__ == "__main__":
    asyncio.run(main())