import asyncio
import json

from nospy import Nostr

"""
Nip05使用例
<your secret key> := nsec or hex
<pubkey> := hex
<name> := Nip05仕様のユーザ名
<domain> := Nip05仕様のドメイン名
<relay url> := wss://...
"""

async def main():
    async with Nostr(
        skey="<your secret key>",
        url="<relay url>",
    ) as nostr:
        # イベントから該当するユーザのpubkeyとリレー一覧を取得
        nip05 = await nostr.queryProfile(event={"kind":0, "pubkey":"<pubkey>", "content":json.dumps({"nip05":"<name>@<domain>"})})
        print(nip05)
        # イベントから該当するユーザのnostr.jsonのnamesを取得
        nip05 = await nostr.searchDomain("<domain>", "<name>")
        print(nip05)
        
        # リレーから取得したイベントから該当するユーザのpubkeyとリレー一覧を取得
        nostr.addFilters(kinds=[0, 1])
        await nostr.subscribe(id="59223")
        await nostr.receive()
        data = nostr.choice(
            subscribe_id=["59223"],
            msg_type="EVENT",
            num=-1,
            event={
                "kind": 0,
                "content": "^.*nip05.*$"
            }
        )
        if data:
            for message in data:
                try:
                    nip05 = await nostr.queryProfile(message[2])
                    print(nip05)
                except Exception as e:
                    print(e)
                    pass

if __name__ == "__main__":
    asyncio.run(main())