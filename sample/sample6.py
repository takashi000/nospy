import asyncio

from nospy import Nostr

"""
NIP06の使用例
<your secret key> := nsec or hex
<relay url> := wss://...
"""

async def main():
    async with Nostr(
        skey="<your secret key>",
        url="<relay url>",
    ) as nostr:
        # ニーモニックシードワードを生成(英語)
        enwords = nostr.generateSeedWords()
        print(enwords)
        if nostr.validateWords(enwords):
            print("OK")
        else:
            print("NG")
        # ニーモニックシードワードを生成(日本語)
        jawords = nostr.generateSeedWords("japanese")
        print(jawords)
        if nostr.validateWords(jawords,"japanese"):
            print("OK")
        else:
            print("NG")

        # ニーモニックシードワードから秘密キーを生成
        seckey = nostr.privateKeyFromSeedWords("leader monkey parrot ring guide accident before fence cannon height naive bean")
        print(seckey.hex())

        seckey = nostr.privateKeyFromSeedWords(mnemonic=jawords, lang="japanese")
        print(seckey.hex())

        # ニーモニックシードワードから秘密キーと公開キーを生成
        seckey, pubkey = nostr.accountFromSeedWords("leader monkey parrot ring guide accident before fence cannon height naive bean")
        print(seckey.hex(), pubkey)

        seckey, pubkey = nostr.accountFromSeedWords(mnemonic=jawords, lang="japanese")
        print(seckey.hex(), pubkey)

        #ニーモニックシードワードから拡張秘密キーと拡張公開キーを生成
        exseckey, expubkey = nostr.extendedKeysFromSeedWords("leader monkey parrot ring guide accident before fence cannon height naive bean")
        print(exseckey, expubkey)

        # 拡張キーから秘密キーと公開キーを生成
        seckey, pubkey = nostr.accountFromExtendedKey("xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G")
        print(seckey.hex(), pubkey)

if __name__ == "__main__":
    asyncio.run(main())