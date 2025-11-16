# nospy

Pythonで作ったNostr用ライブラリです。

## アップデート

2025/10/28: 初回リリース(NIP-01, NIP-04, NIP-19, NIP-42, NIP-44対応)\
2025/11/01: 0.0.2リリース(REQ送信時に複数のORフィルターを指定できるように修正)\
2025/11/02: 0.0.3リリース(リレーサーバ機能の追加)\
2025/11/09: 0.0.4リリース(NIP-06対応 中/韓/日/英/伊/仏/チェコ/ポルトガル/スペイン BIP0340の処理を大幅に変更 完全加法公式 https://eprint.iacr.org/2015/1060 に準拠)\
2025/11/09: 0.0.5リリース(NIP-13対応, そのほか、送受信や接続/再接続の処理見直し修正)\
2025/11/17: 0.0.6リリース(NIP-05対応、choiceメソッドにイベント検索機能追加。そのほか再接続の処理見直し修正)

## インストール

```sh
uv venv -p 3.12 .venv
```

```sh
git clone https://github.com/takashi000/nospy.git
```

```sh
uv pip install nospy
```

## 使い方

サンプルコード

```python
import asyncio

from nospy import Nostr

"""
kind1でメッセージを投稿する例
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
```

```python
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
```

## 特徴

コンテキストマネージャを持っているので少しリソース管理が楽になると思います。\
cffiを使用していないため、pkg-configなどのビルドツールが不要でインストールが簡単です。

## 著作権

作成者・著作者: Tanaka Takashi
Copyright(C) 2025 Tanaka Takashi

## 利用規約・免責事項

このソフトウェアは、MITライセンスの条件に従って提供されています。以下の利用規約および免責事項に同意することにより、このソフトウェアを使用することができます。

### 利用規約

#### 再配布および使用

このソフトウェアは、個人使用または商業目的で自由に使用、コピー、変更、統合、サブライセンス、および再配布することができます。

#### 著作権表示

本ソフトウェアを再配布する場合、著作権表示および本ライセンスの全文をすべてのコピーまたは重要な部分に含める必要があります。

### 免責事項

#### 無保証

このソフトウェアは「現状有姿」で提供され、明示的または暗黙的ないかなる保証もありません。これには、商品性、特定目的への適合性、非侵害に関する保証が含まれますが、これに限定されません。

#### 責任の制限

作者または著作権者は、このソフトウェアの使用または使用に関連して生じるいかなる損害（包括的に含まれるがこれに限定されない、データの損失、利益の損失、人身傷害、特別な、偶発的な、または結果的な損害）に対して責任を負いません。
