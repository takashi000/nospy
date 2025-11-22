import asyncio
import json

from nospy import Nostr

"""
取得したメッセージから対象のイベントを検索する例
<your secret key> := nsec or hex
<relay url> := wss://...
"""

async def main():
    async with Nostr(
        skey="<your secret key>",
        url="<relay url>",
    ) as nostr:
        nostr.addFilters(kinds=[1])
        await nostr.subscribe(id="59223")
        await nostr.receive()
        data = nostr.choice(
            subscribe_id=["59223"],
            msg_type="EVENT",
            num=-1,
            # eタグまたはpタグを含む場合
            event={
                "tags":[
                    [r'^e$'],
                    [r'^p$'],
                ]
            },
            event_sort=True, # EVENTのソートを有効化
            event_sort_reverse=True, # 降順ソート
            event_sort_key="created_at" # created_atをキーにしてソート 
        )
        # 結果をファイルに出力
        with open('./data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

if __name__ == "__main__":
    asyncio.run(main())