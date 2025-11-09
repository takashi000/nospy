import asyncio

from nospy import Nostr

"""
NIP13でマイニングしたテキストを投稿する例
<your secret key> := nsec or hex
<relay url> := wss://...
"""

async def main():
    async with Nostr(
        skey="<your secret key>",
        url="<relay url>",
    ) as nostr:
        event = nostr.addEvent(kind=1, content="おなかすいた", finalize=False)
        print(event)
        event_pow = nostr.minePow(event, 20)
        print(event_pow)
        nostr.addEvent(kind=event_pow['kind'], tags=event_pow['tags'], content=event_pow['content'], created_at=event_pow['created_at'])
        nostr.publish()
    
if __name__ == "__main__":
    asyncio.run(main())