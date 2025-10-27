# nospy

Pythonで作ったNostr用ライブラリです。

## アップデート

2025/10/28: 初回リリース(NIP-01, NIP-04, NIP-19, NIP-42, NIP-44対応)

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

