import asyncio

from nospy import Nostr

"""
サーバー機能を有効にしてメッセージ受信待ちする例
"""

async def server():
    async with Nostr(
        server_on=True,
        server_host="0.0.0.0",
        server_port=443,
        server_ssl_on=True,
        server_route="/",
        ssl_certfile="./cert.pem",  # サーバー証明書ファイルのパス
        ssl_keyfile="./privkey.pem", # サーバー秘密鍵ファイルのパス
    ) as nostr:
        while True:
            print("Waiting for events...", flush=True)
            data = await nostr.server_dequeue() # 受信したメッセージを取得
            # メッセージキューはuuid, ws, messageを含む辞書型で返される
            uuid = data.get("uuid") if data is not None else "" # 接続ごとのユニークなID
            ws = data.get("ws") if data is not None else None   # 接続元のwebsocketオブジェクト
            message = data.get("message") if data is not None else None # 受信したNIP仕様のメッセージ本体
            if data is not None:
                print(f"ID:{uuid}, message:{message}", flush=True)
                await nostr.server_send(ws, message=nostr.noticeMessage("Event received"))
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(server())