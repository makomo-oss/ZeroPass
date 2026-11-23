# ZeroPass パスキー仕様（passkey.md）

- 版: 0.1（ドラフト）
- 関連: [ADR-0010](../adr/0010-passkey-engine.md)、[ADR-0007](../adr/0007-domain-processes-and-key-agent.md)、[脅威モデル](../threat-model.md) §5.4（G7・G8）、[`crypto.md`](crypto.md) §6（鍵階層）
- 実装: `crates/zp-passkey`（認証器・クライアントの一部）、`crates/zp-origin`（RP ID の検証）、`bins/zp-vaultd`（§9）
- タスク: P5-02（本書の §1〜§3）、P5-03（§4〜§10）

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

## 4. 認証器データ

WebAuthn §6.1 の形。

```text
authenticatorData = rpIdHash(32) ‖ flags(1) ‖ signCount(4, ビッグエンディアン)
                    ‖ [ attestedCredentialData ]          -- 作成のときだけ（AT）
attestedCredentialData = aaguid(16) ‖ credentialIdLength(2, ビッグエンディアン)
                         ‖ credentialId ‖ credentialPublicKey（§2 の COSE_Key）
```

- `rpIdHash` は RP ID（§8）の SHA-256。
- **フラグ**: UP（0x01）と UV（0x04）は常に立てる（毎回 Windows Hello で確かめるため。ADR-0010）。BE（0x08）は常に立てる。BS（0x10）は、金庫に失効していない別の端末があるときだけ立てる。AT（0x40）は作成のときだけ。ED（0x80）は立てない（認証器の拡張を返さない）。
- **署名カウンタ**: 常に 0（ADR-0010）。
- **AAGUID**: `4826244e-9eab-4432-8ad5-d2f3693fb8c5`（ZeroPass の固定値）。

## 5. 作成（makeCredential）

`navigator.credentials.create` の `publicKey` に当たるものを受け取る（§9 の `PasskeyCreate`）。

1. 要求元のフレームのオリジンと RP ID を確かめる（§8）。アルゴリズムを選ぶ（§2）。ユーザーハンドルが 1〜64 バイト、チャレンジが 1〜1024 バイト、`excludeCredentials` が 64 件以下（ID は 1〜1023 バイト）であることを確かめる。ここまでは利用者に尋ねる前に行う。
2. 利用者を確かめる（Windows Hello。§9）。
3. `excludeCredentials` のどれかが、その RP ID のクレデンシャルとして金庫にあれば、作らずに `CREDENTIAL_EXCLUDED`（ブラウザの `InvalidStateError`）。利用者を確かめた後に調べるので、確かめずに ID の有無を探ることはできない。
4. 鍵の組とクレデンシャル ID を作り、金庫に保存する（§3。同じユーザーハンドルのものは置き換える）。
5. 認証器データ（AT 付き）、clientDataJSON（§7、`webauthn.create`）、attestation object を返す。
   - attestation object は "none" だけ: `{"fmt": "none", "attStmt": {}, "authData": 認証器データ}`（キーは正準順）。RP が `attestation` に何を求めても同じ。
   - 公開鍵（SubjectPublicKeyInfo）とアルゴリズムも返す（ブラウザの `getPublicKey()`・`getPublicKeyAlgorithm()` に当たる）。
- `authenticatorSelection`（`residentKey`・`userVerification` など）は、どの値でも上のとおりに作る（常に発見可能、常に UV）。

## 6. 署名（getAssertion）

`navigator.credentials.get` の `publicKey` に当たるものを受け取る（§9 の `PasskeyGet`）。

1. 要求元と RP ID を確かめる（§8）。チャレンジ、`allowCredentials`（64 件以下）の大きさを確かめる。ここまでは利用者に尋ねる前に行う。
2. 利用者を確かめる（Windows Hello。§9）。
3. 候補を探す（§3）。なければ `ITEM_NOT_FOUND`。
4. 候補が 2 件以上で、利用者が選んでいなければ、候補の一覧（クレデンシャル ID、アカウント名、表示名）を返す。利用者が選んだら、同じ要求に選んだ ID を添えてもう一度送る（§9.2）。
5. 認証器データ（AT なし）と clientDataJSON（§7、`webauthn.get`）を作り、`認証器データ ‖ SHA-256(clientDataJSON)` に署名する（§2）。クレデンシャル ID、ユーザーハンドル、署名を返す。

## 7. clientDataJSON

WebAuthn §5.8.1.1 の直列化。

```json
{"type":"webauthn.get","challenge":"<base64url>","origin":"https://login.example.com","crossOrigin":false}
{"type":"webauthn.create","challenge":"<base64url>","origin":"https://login.example.com","crossOrigin":true,"topOrigin":"https://www.example.com"}
```

- `challenge` は RP のチャレンジの base64url（パディングなし）。
- `origin` は、拡張がブラウザから得た、要求したフレームのオリジン（`extension.md` §1）。ページが渡す値ではない。
- フレームのオリジンが最上位のフレームと違えば（同じサイトに限る。§8）、`crossOrigin` を `true` にして `topOrigin` を加える。
- 文字列は `CCDToString`（`"` と `\` をエスケープし、制御文字は `\uXXXX`）。
- clientDataJSON は、署名を行うパスキーワーカーが作る。署名は、そのワーカーが作った clientDataJSON の上にだけ行う。

## 8. 要求元と RP ID

- **要求元**: フレームのオリジンは `scheme://host[:port]`（`extension.md` §5.1）。最上位のフレームのオリジンが渡され、別のサイト（登録可能ドメインが違う）なら、作成も署名もしない（`DENIED`。ログインの入力と同じ。`extension.md` §7）。
- **RP ID**: 要求の `rp.id`（作成）・`rpId`（署名）。空ならページのホスト。次のすべてを満たすものだけを使う（実装は `zp_origin::Origin::relying_party_id`）。
  1. ページが `https`（または `http://localhost`。そのときの RP ID は `localhost` だけ）。
  2. ページのホストがドメイン名（IP アドレス、ドットのない名前でない）。
  3. RP ID は、ホストそのもの、またはラベルの区切りで終わるホストの親ドメイン。
  4. RP ID は公開サフィックス（私的な部分を含む。`github.io` など）でなく、ホストの登録可能ドメイン以下である。
  - RP ID は小文字の ASCII（国際化ドメイン名は Punycode）で比べる。ポート、パス、利用者情報、末尾のドットを含むものは使わない。
  - 満たさなければ `DENIED`（ブラウザの `SecurityError`）。
- 関連オリジン（`/.well-known/webauthn`）による例外は扱わない（金庫デーモンはネットワークを持たない。ADR-0010）。
- **これで防ぐもの**: フィッシングのページ（`example.com.evil.net` など）は、自分の RP ID のクレデンシャルしか見つけられず、本物の RP ID を名乗れない。共有ホスティングの別の利用者は、互いの RP ID を使えない。

## 9. 金庫デーモンでの流れ

要求は IPC の `PasskeyCreate`（要求 64）と `PasskeyGet`（65）。応答は `PasskeyCreated`（29）、`PasskeyAssertion`（30）、`PasskeyChoices`（31）。呼べるのは UI と拡張ブリッジの役割（`ipc.md` §5）。

### 9.1 手順

1. **フロント**が要求を確かめる（§5 の 1、§6 の 1）。確かめられないものは、利用者に尋ねずに断る。
2. フロントは、パスキーのドメインを**施錠してから鍵エージェントで解錠し直す**（Windows Hello。ドメインが開いていても毎回。TOTP のブリッジと同じ。`extension.md` §9）。利用者が断れば `USER_CANCELLED`。
3. フロントは要求を**パスキーワーカー**に渡す。ワーカーは同じ検査をもう一度行い（署名するのはワーカーなので）、作成または署名を行う。秘密鍵が復号されるのはワーカーの中だけで、フロントは秘密鍵を持つことがない（フロントのプロセスは、パスキーの要求を自分では処理できない）。
4. 応答はフロントを通ってクライアントに返る。応答に秘密鍵は含まれない。

### 9.2 候補から選ぶ

- `PasskeyGet` が `PasskeyChoices` を返したとき、フロントはその要求（オリジン、最上位のオリジン、RP ID、チャレンジ、`allowCredentials`）と候補の ID を 120 秒覚える。
- 同じ要求に、候補の 1 つを `chosen` に入れて送り直したものは、利用者に**もう一度尋ねずに**署名する（選ぶ直前に確かめたため）。覚えた要求は 1 回使えば消える。ほかの要求、別のチャレンジ、施錠、期限切れでも消える。
- 選ぶ間にパスキーのドメインが自動施錠されていれば、もう一度尋ねる。
- `chosen` があっても覚えた要求に当たらなければ、利用者を確かめてから、その ID で署名する（候補にあれば）。

### 9.3 エラー

| コード | 意味 | ブラウザの例外（`extension.md` §11） |
|---|---|---|
| `DENIED` | 別のサイトのフレーム、使えない RP ID | `SecurityError` |
| `UNSUPPORTED_ALGORITHM` | RP のアルゴリズムに ES256・EdDSA がない | `NotSupportedError` |
| `CREDENTIAL_EXCLUDED` | `excludeCredentials` のクレデンシャルが金庫にある | `InvalidStateError` |
| `ITEM_NOT_FOUND` | その RP のパスキーがない（`allowCredentials` に当たらない） | `NotAllowedError` |
| `USER_CANCELLED` | Windows Hello で断られた | `NotAllowedError` |
| `BAD_REQUEST` | 形の誤り、大きすぎる値 | `TypeError` 相当 |
| `DOMAIN_UNAVAILABLE` | パスキーのドメインがない金庫（ハードウェア鍵ストアなしで作った） | — |

## 10. 限界

- **乗っ取られたフロントや拡張ブリッジ**: フロントは、利用者を確かめずに、開いているパスキーのドメインで署名させることができる（ADR-0007 の限界と同じ）。拡張とブリッジは、オリジンを偽って、別のサイトの RP ID のパスキーで署名させることができる（`extension.md` §10 と同じ）。どちらも、署名のたびに Windows Hello が利用者を確かめることは変わらない（乗っ取ったフロントを除く）。
- **選択の 120 秒**: 選ぶ間に、同じ要求に別の候補を入れて送り直せば、尋ねずに署名する。尋ねたときに利用者が承認したのは、その RP の、その要求への署名である。
- **署名カウンタ 0**: RP は、カウンタでクレデンシャルの複製を見つけられない（同期型パスキーの性質。ADR-0010）。
- **範囲外**: RS256 などほかのアルゴリズム、attestation（"none" 以外）、拡張（`credProps` 以外。`extension.md` §11）、関連オリジン、ブラウザの Signal API による RP からの通知、パスキーの自動入力（条件付きの仲介）。

## 11. ブラウザが clientDataJSON を作る場合（Android）

Android の Credential Manager では、特権ブラウザ（Chrome など。`android.md` §6）が clientDataJSON を自分で作り、プロバイダにはその SHA-256（`clientDataHash`）だけを渡す。ブラウザは応答の clientDataJSON を自分のもので置き換える。

- `PasskeyCreate`・`PasskeyGet` の `client_data_hash`（32 バイト）があれば、ZeroPass は clientDataJSON を作らず（応答の `client_data_json` は空）、署名は `authenticatorData ‖ client_data_hash` に対して行う。32 バイトでなければ断る。
- オリジンと RP ID の検査（§8）は変わらない。オリジンは、ブラウザが Credential Manager に示し、OS が特権ブラウザの許可リストで確かめたもの（`CallingAppInfo.getOrigin`）である。ハッシュの中身（チャレンジとオリジン）を ZeroPass は確かめられないので、その正しさは許可リストのブラウザに任せる。
- **一覧だけ**（`PasskeyGet` の `list_only`）: 候補が 1 件でも署名せず `PasskeyChoices` を返す。利用者の確認は署名と同じく求め、選んだ候補の送り直しは §9.2 と同じく 120 秒間尋ねない。Credential Manager の選択画面に、アカウントを並べるため。
- 選択の照合（§9.2）は `client_data_hash` も比べる。
