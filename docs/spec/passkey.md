# ZeroPass パスキー仕様（passkey.md）

- 版: 0.1（ドラフト）
- 関連: [ADR-0002](../adr/0002-key-hierarchy.md)、[ADR-0007](../adr/0007-domain-processes-and-key-agent.md)、[ADR-0010](../adr/0010-passkey-engine.md)、[脅威モデル](../threat-model.md) §5.4（G7・G8）、[`ipc.md`](ipc.md) §4.3・§6・§13、[`extension.md`](extension.md)
- 実装: `crates/zp-passkey`、`crates/zp-origin`、`crates/zp-ipc`、`bins/zp-vaultd`、`bins/zp-nmh`、`apps/extension`
- タスク: P5-01（本書初版）、P5-02（生成・保管・ワーカー分離）、P5-03（`makeCredential` / `getAssertion`）、P5-04（ブラウザ拡張）、P5-05（端末間同期検証）

ZeroPass の OS 非依存・同期可能パスキー（WebAuthn Level 2/3）の仕様を定める。

## 1. 原則

1. **秘密鍵はパスキーワーカーの外に出さない（G7）。** クレデンシャルの生成・保管・署名はすべて `zp-vaultd` のパスキーワーカープロセス（`VK-K` ドメイン）の中で行う。フロント・UI・拡張・ブラウザに渡すのは公開鍵・クレデンシャル ID・署名・認証器データ等の公開情報だけである。
2. **RP ID は金庫デーモンが検証する（G8）。** ブラウザ拡張が `sender` から得たページのオリジン（と最上位フレームのオリジン）を金庫デーモンへ渡し、デーモンが `zp-origin` を用いて `rpId` の正当性を確認する。ページや content script が主張するオリジンは信頼しない。
3. **登録と認証のたびに生体認証を求める（UV=1）。** パスキー登録（`PasskeyCreate`）と認証（`PasskeyGetAssertion`）では、呼び出し元の役割によらず Passkey ドメインがすでに解錠されていても一度施錠し、鍵エージェント（Windows Hello 等）で解錠し直してから鍵生成・署名を行う（`BridgeTotp` と同じ原則）。
4. **同期可能パスキーとして振る舞う。** `BE=1`（Backup Eligible）・`BS=1`（Backup State）・`signCount = 0` 固定とする（ADR-0010）。

## 2. クレデンシャル形式と保管

金庫内の保存形式は `zp_vault::model::PasskeyCredential`（Domain = `Passkey`、VK-K でラップされたアイテム DEK で暗号化）をそのまま使う。

| フィールド | 型 | 内容 |
|---|---|---|
| `rp_id` | `String` | Relying Party ID（ASCII 小文字、末尾ドットなし。例: `webauthn.io`） |
| `rp_name` | `String` | Relying Party の表示名 |
| `user_handle` | `Vec<u8>` | RP が指定する `user.id`（1〜64 バイト） |
| `user_name` | `String` | アカウント名（例: `alice@example.com`） |
| `user_display_name` | `String` | 表示名（例: `Alice`） |
| `credential_id` | `Vec<u8>` | 32 バイトの OS CSPRNG 乱数（不透明・一意） |
| `private_key` | `Vec<u8>` | PKCS #8 DER 形式の秘密鍵（`ZeroizeOnDrop`） |
| `cose_algorithm` | `i32` | COSE アルゴリズム番号（`-7` = ES256、`-8` = EdDSA） |

### 2.1 対応アルゴリズム

| COSE alg | 名称 | 曲線 / プリミティブ | 署名形式 | COSE 公開鍵 |
|---|---|---|---|---|
| `-7` | ES256 | NIST P-256（`p256`）+ SHA-256 | ASN.1 DER（`SEQUENCE { INTEGER r, INTEGER s }`、low-S 正規化） | `{ 1: 2 (EC2), 3: -7, -1: 1 (P-256), -2: x(32B), -3: y(32B) }` |
| `-8` | EdDSA | Ed25519（`ed25519-dalek`） | 生 64 バイト | `{ 1: 1 (OKP), 3: -8, -1: 6 (Ed25519), -2: pub(32B) }` |

- `pubKeyCredParams` の配列を先頭から走査し、最初に一致した対応アルゴリズム（`-7` または `-8`）を選ぶ。いずれもなければ拒否する（`NotSupportedError` 相当）。
- 同一 `(rp_id, user_handle)` のクレデンシャルがすでに金庫に存在する場合、WebAuthn の discoverable credential の規定に従い、新しいクレデンシャルで既存アイテムを置き換える（`update_item`）。これにより同期後も同一アカウントの古いパスキーが重複残留しない。

## 3. RP ID とオリジンの検証

WebAuthn Level 2/3 §5.4.1 / HTML `effective domain` に従い、ページのオリジン `origin` と要求された `rp_id` を検証する。

1. `origin` は `zp-origin::Origin::parse` で解釈し、さらに `top_origin` が与えられている場合は `origin.same_site(&top_origin)`（クロスオリジン iframe 拒否）を確認する。
2. スキーム制約:
   - `https://` は許可。
   - `http://` は開発・ローカルテスト用のループバック（ホストが `localhost`、`127.0.0.1`、`[::1]`）のみ許可。それ以外の `http://` は拒否する。
3. `rp_id` の正規化と既定値:
   - 省略または空のときは `origin.host()` を用いる。
   - 指定されたときは ASCII 小文字、末尾ドットなし、空でない有効なホスト名（ポートやスキームやパスを含まない）であること。
4. 有効ドメイン一致:
   - `rp_id == origin.host()` なら許可（IP アドレスや `localhost` を含む）。
   - それ以外のドメイン名については、以下のすべてを満たすときのみ許可:
     - `origin.host()` が `.{rp_id}` で終わる（`rp_id` が親ドメイン）。
     - `rp_id` が登録可能ドメインまたはそのサブドメインである（`psl::domain_str(rp_id)` が `Some`、すなわち `com`・`co.uk`・`github.io` 等の公開サフィックス自身ではない）。
   - `origin.host()` が IP アドレスまたは単一ラベル（`localhost` 等）の場合は完全一致のみ。

## 4. `authenticatorData` と WebAuthn 出力

### 4.1 `authenticatorData` の構造

```text
authData = rpIdHash (32 B: SHA-256(UTF-8(rp_id)))
         ‖ flags (1 B)
         ‖ signCount (4 B: big-endian 0x00000000)
         ‖ [attestedCredentialData]    // makeCredential のみ
```

フラグ（1 バイト）:
- bit 0 (`0x01`): `UP`（User Present）= 1
- bit 2 (`0x04`): `UV`（User Verified）= 1
- bit 3 (`0x08`): `BE`（Backup Eligible）= 1
- bit 4 (`0x10`): `BS`（Backup State）= 1
- bit 6 (`0x40`): `AT`（Attested Credential Data included）= `makeCredential` は 1、`getAssertion` は 0
- bit 7 (`0x80`): `ED`（Extension Data included）= 0

したがって:
- `makeCredential` の `flags` = `0x01 | 0x04 | 0x08 | 0x10 | 0x40` = **`0x5D`**
- `getAssertion` の `flags` = `0x01 | 0x04 | 0x08 | 0x10` = **`0x1D`**

### 4.2 `attestedCredentialData`（`makeCredential` のみ）

```text
attestedCredentialData = aaguid (16 B)
                       ‖ credentialIdLength (2 B, big-endian)
                       ‖ credentialId (32 B)
                       ‖ credentialPublicKey (CBOR-encoded COSE Key)
```

- ZeroPass の AAGUID は仕様で固定した 16 バイト値（UUID v5 / 固定識別子: `5a506173-7300-4000-8000-000000000001`、バイト列 `[0x5a, 0x50, 0x61, 0x73, 0x73, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]`）。
- COSE Key のマップは CTAP2 正準 CBOR 順（RFC 8949 §4.2 / CTAP2 §6: キーのバイト列長が短い順、同じ長さなら辞書順。すなわち `1`, `3`, `-1`, `-2`, (`-3`) の順）でエンコードする。

### 4.3 `attestationObject`（`makeCredential` のみ）

CTAP2 正準 CBOR マップ（キーを長さ順・辞書順: `"fmt"`, `"attStmt"`, `"authData"`）:

```cbor
{
  "fmt": "none",
  "attStmt": {},
  "authData": h'...'
}
```

### 4.4 `clientDataJSON` と署名

ブラウザ拡張（および WebAuthn クライアント）では、次の JSON を UTF-8 で生成し、その SHA-256 を `clientDataHash` とする:

```json
{"type":"webauthn.create","challenge":"<base64url-no-pad>","origin":"<origin>","crossOrigin":false}
```
（認証時は `"type":"webauthn.get"`）

- `getAssertion` の署名対象は `authData ‖ clientDataHash`（37 + 32 = 69 バイト）。
  - ES256: `SHA-256(authData ‖ clientDataHash)` に P-256 ECDSA 署名し、ASN.1 DER で返す。
  - EdDSA: `authData ‖ clientDataHash` に Ed25519 署名し、生 64 バイトで返す。
- `makeCredential` は以下も返す（WebAuthn Level 3 の `AuthenticatorAttestationResponse` ヘルパー用）:
  - `authenticatorData`（生バイト）
  - `publicKey`（SubjectPublicKeyInfo DER）
  - `publicKeyAlgorithm`（COSE alg: `-7` または `-8`）

### 4.5 `excludeCredentials` と `allowCredentials`

- `makeCredential`: `excludeCredentials` に指定された `credential_id` のいずれかが、対象 `rp_id` の金庫内パスキーと一致すれば登録を拒否する（`ALREADY_EXISTS` / ブラウザ側 `InvalidStateError`）。
- `getAssertion`:
  - `allowCredentials` が空でないときは、`rp_id` と `credential_id` の両方に一致するクレデンシャルのみを候補とする。
  - `allowCredentials` が空のときは、`rp_id` に一致するすべてのクレデンシャルを候補とする（discoverable credential）。
  - 候補が複数あるときは、クライアント（拡張または UI）に一覧（`credential_id`・`user_name`・`user_display_name`・`rp_id`・`rp_name` のみ、秘密鍵なし）を返し、利用者が選んだ `credential_id` を指定して署名を要求する。

## 5. ローカル IPC（予約番号 64〜79）

`ipc.md` §4.3 で予約した要求番号 64〜79（および対応する応答）を P5-02 / P5-03 で定義する。すべてフロントがパスキーワーカー（`Scope::Domain(DomainId::Passkey)`）へ転送する。

| 番号 | 要求 | 応答 | 呼べる役割 | 内容 |
|---|---|---|---|---|
| 64 | `PasskeyMakeCredential` | `PasskeyCreated` | UI、拡張ブリッジ | オリジン検証 + 生体認証（ブリッジ時は毎回再解錠）+ 鍵生成 + 保管 + `attestationObject` 等を返す |
| 65 | `PasskeyList` | `PasskeyCandidates` | UI、拡張ブリッジ | `origin` / `rp_id` / `allow_credential_ids` に一致する候補の概要（秘密鍵なし）を返す。Passkey ドメインが解錠中なら候補一覧、施錠中なら `LOCKED` |
| 66 | `PasskeyGetAssertion` | `PasskeyAssertion` | UI、拡張ブリッジ | オリジン検証 + 生体認証（ブリッジ時は毎回再解錠）+ 署名して `authenticatorData`・`signature`・`user_handle`・`credential_id` を返す |

※ 既存の `ListItems(Passkey)` / `GetItem` / `DeleteItem` も引き続きパスキーワーカーが処理し、秘密鍵・クレデンシャル ID・ユーザーハンドルは `GetItem` の応答に含めない（`ipc.md` §6）。

## 6. ブラウザ拡張の仲介（P5-04）

- 拡張はページの `MAIN` world に小さな仲介スクリプトを注入し、`navigator.credentials.create` と `navigator.credentials.get` のうち `options.publicKey` を持つ呼び出しを横取りする。`publicKey` 以外の認証情報（PasswordCredential 等）は元の実装へそのまま通す。
- ページ（`MAIN` world）と content script（`ISOLATED` world）の間は、読み込みごとに生成するランダムなチャネル ID を付けた `CustomEvent` / `MessageChannel` で通信する。
- 利用者への確認 UI（登録の確認、認証時のアカウント選択、および「OS / セキュリティキーを使う」フォールバック選択）は閉じた Shadow DOM に表示し、`isTrusted` の操作だけを受け付ける。
- 利用者が ZeroPass を使わず OS の認証器（Windows Hello / セキュリティキー）を選んだ場合、または ZeroPass に該当パスキーがなくフォールバックを選んだ場合は、元の `navigator.credentials.create/get` にそのまま委譲する。
- background は `sender` のフレーム URL と最上位フレーム URL から `origin` と `top` を取り、`zp-nmh` 経由で `zp-vaultd` に渡す。

## 7. 限界

- **`signCount = 0` 固定**: 秘密鍵が流出して他所で複製使用されても RP のカウンタでは検知できない（ADR-0010）。
- **ブラウザ API フックの限界**: `navigator.credentials` の書き換えはページ側のスクリプトと同一 JS 環境で行われるため、ページ側が拡張の実行前に参照を退避する、あるいは拡張を検出する挙動は完全に防げない（拡張の実行タイミングを `document_start` にすることで実用上カバーする）。OS ネイティブの Credential Provider API による完全統合は Phase 6（Android / iOS）および将来の OS 対応で行う。
- **未対応の WebAuthn 拡張**: `prf`、`largeBlob`、`hmac-secret`、`relatedOrigins`（ROR）は初期スコープ外。
