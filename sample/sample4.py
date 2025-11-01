import asyncio

from nospy import Nostr

"""
イベントを購読するときの例
<your secret key> := nsec or hex
<relay url> := wss://...
"""

async def main():
    async with Nostr(
        skey="<your secret key>",
        url="<relay url>",
    ) as nostr:
        nostr.addFilters(kinds=[1])
        nostr.addFilters(kinds=[2])
        nostr.addFilters(kinds=[3])
        await nostr.subscribe(id="59223")
        for _ in range(5):
            await nostr.receive()
            data = nostr.choice(subscribe_id=["59223"], msg_type="EVENT", num=-1)
            print(data, flush=True)

if __name__ == "__main__":
    asyncio.run(main())