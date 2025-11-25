import asyncio
import secrets
from nospy import Nostr

"""
NIP57で受け取り側ウォレットから支払先インボイスを取得する例
<relay url> := wss://...
<their npub>" := npub
<zap receipt relay> := wss://...
"""

async def main():
    async with Nostr(
        url="wss://yabu.me",
    ) as nostr:
        id = secrets.token_hex(16)

        # npubで指定したユーザのkind0をフィルターに指定
        nostr.addFilters(kinds=[0], authors=[nostr.bech32_decode("<their npub>")[1].hex()])
        
        await nostr.subscribe(id=id)
        await nostr.receive()

        data = nostr.choice(subscribe_id=id, msg_type="EVENT")

        if len(data) > 0:
            metadata_kind0 = data[0][2]

            # 成功時の戻り値は(callback url, minSendable, maxSendable, nostrPubkey)
            res = await nostr.getZapEndpoint(metadata_kind0)
            
            param = nostr.paramProfileZap(nostr.pubkey, 1000, ["<zap receipt relay>"], "test")
            zr = nostr.makeZapRequestEvent(param)
            if nostr.validateZapRequestEvent(zr):
                nostr.addEvent(kind=zr["kind"], tags=zr["tags"], content=zr["content"], created_at=zr["created_at"], verify=True, validate=True)

                invoice = await nostr.zap(res[0], 1000)
                print(invoice)

if __name__ == "__main__":
    asyncio.run(main())