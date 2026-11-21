# ADR-0010: パスキーエンジンは自作し、1Password の `passkey` クレート群は採用しない

- 状態: 採用
- 日付: 2026-11-22
- 関連: [ADR-0001](0001-technology-stack.md)、[ADR-0007](0007-domain-processes-and-key-agent.md)、脅威モデル §5.4（G7・G8）、タスク P5-01〜P5-05、`docs/spec/passkey.md`

## 背景

ADR-0001 は、パスキーに P-256 ECDSA（ES256）を必須とし EdDSA にも対応すること、1Password 製の `passkey` クレート群（passkey-rs）を採用するかを P5-01 で決めることを定めた。パスキーエンジンに求められることは次のとおりである。

- 秘密鍵は金庫の外に平文で出ず、署名は金庫デーモンのパスキーワーカーの中で行う（G7、ADR-0007）。秘密は使い終えたら消去する（ADR-0001 の `zeroize`）。
- RP ID を金庫デーモンの側でも検証し、他のサイト向けのパスキーで署名しない（G8）。照合に使うオリジンは、ページではなくブラウザが決める（`extension.md` §1）。
- 署名カウンタの扱いを ADR で明記する（脅威モデル §5.4）。
- パスキーは金庫のアイテムとして端末の間で同期される（ペアリングで配った VK-K で開く）。
- 金庫デーモンの依存ツリーにネットワーク系クレートを入れない（ADR-0004、`scripts/check-offline-deps.sh`）。

### 評価（2026-11-22、passkey-authenticator / passkey-types / passkey-client 0.6.0、passkey-crypto 0.1.1）

クレートの中身（crates.io から取得したソース）と依存ツリー（`cargo tree`）を調べた。

| 観点 | 結果 |
|---|---|
| ライセンス | MIT OR Apache-2.0。GPL-3.0 と両立し、`deny.toml` の許可リストに入っている |
| 保守 | 1Password のリポジトリ（`1Password/passkey-rs`）で保守されている。0.6.0 の最低 Rust は 1.87 |
| 保管先の差し替え | できる。`passkey_authenticator::CredentialStore`（`find_credentials`・`save_credential`・`update_credential`・`get_info`）を実装すればよい。ただし非同期（`async-trait`）で、認証器の `make_credential`・`get_assertion` も非同期である。金庫デーモンのワーカーは同期のスレッドで動くので、実行器が要る |
| 秘密鍵の扱い | `passkey_types::Passkey` の秘密鍵は `coset::CoseKey`（COSE 形式）で持ち、**消去されない**（ソースに "TODO: Implement Zeroize on this if/when rolling our own CoseKey type"）。保管先との受け渡しは秘密鍵を含む `Passkey` の値で行うので、ワーカーのメモリに消去されない複製が残る |
| 依存 | `passkey-authenticator` だけで 110 個。うち 57 個は今の `zp-vaultd` の依存ツリー（131 個）にない（`ciborium`・`coset`・`serde_json`・`strum`・`ml-dsa`・`half`・`indexmap` ほか）。`passkey-client` はさらに、独自の公開サフィックスリスト（`public-suffix` 0.1.3。`zp-origin` の `psl` と二重になる）、`url`・`idna`、Windows の WebAuthn API への FFI（`unsafe`）を持つ |
| 範囲 | CTAP2 のコマンド体系、PIN/UV の認証プロトコル、拡張（hmac-secret・PRF・largeBlob）、ML-DSA まで含む。ZeroPass に要るのは、ES256・EdDSA、attestation `none`、発見可能なクレデンシャルの作成と署名だけである |

## 決定

### 1. 自作する

`crates/zp-passkey` に、WebAuthn の認証器（クレデンシャルの作成と署名）と、クライアントの役割のうち ZeroPass が担う部分（`clientDataJSON` の生成と RP ID の検証）を実装する。passkey-rs は採用しない。

- プリミティブは、すでに使っている系統の監査済みの実装に限る: `p256`（ECDSA。ノンスは RFC 6979 の決定的なもの）、`ed25519-dalek`、`sha2`、`getrandom`、`zeroize`。秘密鍵は PKCS #8 DER で金庫のアイテム（`PasskeyCredential.private_key`）に保存し、メモリでは消去される型でだけ持つ。
- CBOR は、書く形が決まっている（COSE_Key と attestationObject）ので、小さな書き手を自作する。読む必要はない（RP の検証は行わない）ので、`ciborium` などは入れない。
- 同期のスレッドでそのまま呼べる API にする（非同期にしない）。

### 2. 範囲と方針

仕様の詳細は `docs/spec/passkey.md`。

- **アルゴリズム**: ES256（COSE `-7`）と EdDSA（`-8`、Ed25519）。RP が `pubKeyCredParams` に並べた順に見て、最初に対応するものを使う。RS256 は ADR-0001 どおり範囲外。
- **attestation**: 常に `none`（RP が `direct` などを求めても）。AAGUID は ZeroPass 固定の値。
- **発見可能**: すべてのクレデンシャルを発見可能なもの（discoverable credential）として金庫に保存する。同じ RP ID と同じユーザーハンドルのクレデンシャルを作ると、前のものを置き換える。
- **利用者の確認**: 作成と認証のたびに、パスキーのドメインを施錠してから鍵エージェントで解錠し直す（Windows Hello。拡張の TOTP と同じ。`extension.md` §9）。認証器データのフラグ UP と UV を立てる。
- **署名カウンタ**: 常に 0。同期されるパスキーは複数の端末に同じ秘密鍵があり、端末の間で増え方をそろえられない。0 は「カウンタを使わない」ことを RP に伝える値で、RP は複製の検知をカウンタに頼らない（同期型パスキーの慣行。脅威モデル §5.4）。
- **バックアップのフラグ**: BE（バックアップできる）は常に 1。BS（バックアップされている）は、金庫に失効していない別の端末があるときだけ 1。端末が 1 台だけなら、その端末を失えばパスキーも失われる（復旧キットは金庫ファイルの写しではない）ので、RP がバックアップを勧められるように 0 にする。
- **clientDataJSON**: パスキーワーカーが、拡張がブラウザから得たオリジン（`sender`）から作る。ページが渡す値は `challenge` だけ使う。
- **RP ID**: ページのホストそのもの、または公開サフィックス（私的な部分を含む）でない親ドメインに限る。`https` のページだけ（試験のため `http://localhost` は許す）。IP アドレスは扱わない。関連オリジン（`/.well-known/webauthn`）は使わない（金庫デーモンはネットワークを持たない）。
- **フレーム**: 最上位のフレームと同じサイトのフレームだけ（ログインの入力と同じ。`extension.md` §7）。
- **拡張**: `credProps` だけ（`rk: true` を返す）。ほかは無視する。

### 3. 確かめ方

- W3C Web Authentication Level 3 §16 のテストベクタ（ES256 の `none`、`crossOrigin`、`topOrigin`、長いクレデンシャル ID、Ed25519）と、認証器データ・attestationObject・署名・clientDataJSON がバイト単位で一致すること（P5-03）。
- 独立した RP の実装（`@simplewebauthn/server`）が、拡張を通じて作った登録と認証を検証できること（P5-04）。
- webauthn.io で登録と認証ができること（P5-04）。

## 検討した代替案

| 案 | 却下理由 |
|---|---|
| passkey-rs を採用する | 秘密鍵が消去されない型で受け渡される。非同期の API。金庫デーモンに 57 個の新しい依存（公開サフィックスリストの二重化と、使わない CTAP2・ML-DSA を含む）が入る |
| passkey-types だけを型と CBOR のために使う | `coset`・`ciborium`・`serde` 一式が入る一方、自分で書く部分（鍵の扱い、認証器のロジック、RP ID の検証）は減らない。秘密鍵の型の問題も残る |
| OS のパスキー（Windows の WebAuthn API、プラットフォーム認証器）に任せる | 端末に縛られ、同期できない。原則④（OS 非依存のパスキー）に反する |

## 結果

- 認証器・CBOR の書き手・RP ID の検証を自前で持つ。正しさは上のテストベクタと独立した RP の実装で確かめ、外部監査（P8-02）の対象に含める。
- 金庫デーモンに加わる依存は、`p256` とその下の RustCrypto のクレート（ECDSA・楕円曲線・PKCS #8 など）に限られる。
- 範囲外: RS256、attestation（`none` 以外）、CTAP2（USB・NFC・BLE の認証器としてふるまうこと）、PRF（hmac-secret）・largeBlob などの拡張、関連オリジン、条件付きの仲介（パスキーの自動入力の候補。P5-04 ではブラウザに任せる）。必要になったときに、この ADR を見直す。
- passkey-rs が秘密鍵を消去される型で扱うようになれば、再評価の余地がある。
