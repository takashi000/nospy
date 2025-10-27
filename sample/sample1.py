import asyncio

from nospy import Nostr

"""
kind1でメッセージを投稿する例
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
            nostr.addEvent(kind=1, content=content)
            await nostr.publish()
            await nostr.receive()
            data = nostr.choice(subscribe_id=["59223"], msg_type="EVENT", num=-1)
            print(data, flush=True)

if __name__ == "__main__":
    asyncio.run(main())