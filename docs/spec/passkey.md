# ZeroPass パスキー仕様（passkey.md）

- 版: 0.1（ドラフト）
- 関連: [ADR-0010](../adr/0010-passkey-engine.md)、[ADR-0007](../adr/0007-domain-processes-and-key-agent.md)、[脅威モデル](../threat-model.md) §5.4（G7・G8）、[`crypto.md`](crypto.md) §6（鍵階層）
- 実装: `crates/zp-passkey`
- タスク: P5-02（本書の §1〜§3）

ZeroPass は、ブラウザ拡張を通じて、Web サイト（Relying Party、RP）にパスキー（WebAuthn の発見可能なクレデンシャル）を作り、それで署名する。パスキーは金庫のパスキーのドメインのアイテムで、ペアリングした端末の間で同期される。

## 1. 原則

1. **秘密鍵はパスキーワーカーの外に出ない。** 秘密鍵は VK-K で暗号化したアイテムの中にだけ保存し、復号と署名はパスキーのドメインを持つプロセス（金庫デーモンのパスキーワーカー、ADR-0007）だけが行う（G7）。IPC の応答にも、拡張にも、秘密鍵は含めない。
2. **メモリの秘密は消去する。** 秘密鍵は、消去される型（`zp_passkey::CredentialKey`、PKCS #8 の `Zeroizing`）でだけ持つ。
3. **利用者が毎回確かめる。** 作成と署名のたびに Windows Hello で利用者を確かめる（ADR-0010）。
4. **RP ID はページのオリジンで決まる。** 他のサイトの RP ID のパスキーで署名しない（G8）。

## 2. アルゴリズムと鍵

| アルゴリズム | COSE | 鍵 | 署名の形 |
|---|---|---|---|
| ES256 | `-7` | P-256 | ASN.1 DER の `Ecdsa-Sig-Value`。SHA-256、ノンスは RFC 6979 の決定的なもの、`s` の正規化はしない |
| EdDSA | `-8` | Ed25519 | 64 バイト（RFC 8032） |

- 作成するときは、RP の `pubKeyCredParams` を先頭から見て、最初に上の表にあるものを使う。`pubKeyCredParams` が空なら ES256（WebAuthn の既定の一覧は ES256 と RS256）。どれもなければ作らない（`NotSupportedError` に当たる）。
- 秘密鍵は OS の乱数（`getrandom`）から作る。P-256 のスカラーが範囲外（0、または位数以上）なら引き直す。
- **保存の形**: PKCS #8 DER（RFC 5958。P-256 は RFC 5915 の `ECPrivateKey`、Ed25519 は RFC 8410）。アルゴリズムは `cose_algorithm` に別に持ち、読むときは、その形の鍵であることを確かめる。
- **公開鍵の形**:
  - 認証器データの中は COSE_Key（RFC 9052 §7）。パラメータは CTAP2 の正準順（エンコードしたキーの短い順、同じ長さならバイト順）に並べる。
    - ES256: `{1: 2 (EC2), 3: -7, -1: 1 (P-256), -2: x (32 バイト), -3: y (32 バイト)}`
    - EdDSA: `{1: 1 (OKP), 3: -8, -1: 6 (Ed25519), -2: x (32 バイト)}`
  - ブラウザの `getPublicKey()` が返す形は DER の SubjectPublicKeyInfo（P-256 は RFC 5480 の非圧縮の点、Ed25519 は RFC 8410）。

## 3. 保管

パスキーは金庫のアイテム `PasskeyCredential`（`zp_vault::model`、パスキーのドメイン）である。平文で保存されるのは、ほかのアイテムと同じく `item_id`・ドメイン・時刻印などだけで、RP ID も含めてすべて暗号文の中にある（`crypto.md` §9）。

| フィールド | 内容 |
|---|---|
| `rp_id` | RP ID（§8 で検証したもの） |
| `rp_name` | RP の表示名（`rp.name`） |
| `user_handle` | ユーザーハンドル（`user.id`、1〜64 バイト） |
| `user_name` | アカウント名（`user.name`） |
| `user_display_name` | 表示名（`user.displayName`） |
| `credential_id` | クレデンシャル ID。ZeroPass が作るものは乱数 16 バイト |
| `private_key` | 秘密鍵（§2 の PKCS #8 DER） |
| `cose_algorithm` | §2 の COSE の識別子 |

- **発見可能**: すべてのクレデンシャルは発見可能（discoverable）で、RP ID だけで探せる。RP が `allowCredentials` を渡したときは、その ID のものに絞る。どちらの場合も、別の RP ID のクレデンシャルは、ID が一致しても使わない。
- **置き換え**: 同じ RP ID と同じユーザーハンドルのクレデンシャルを作ると、同じアイテムを新しいクレデンシャルで更新する（WebAuthn §6.3.2 の認証器の動作）。古い版はアイテムの履歴に暗号文のまま残る（`crypto.md` §9）が、探す対象にはならない。
- **並び**: 候補はアカウント名の順（大文字と小文字を区別しない）、同じなら `item_id` の順。
- **同期**: ほかのアイテムと同じく、暗号文の op として同期される（`sync.md`）。開けるのは、ペアリングで VK-K を受け取った端末だけである（`pairing.md`）。
- **削除**: ほかのアイテムと同じ（`DeleteItem`、tombstone）。RP には知らせない（WebAuthn の Signal API は扱わない）。
