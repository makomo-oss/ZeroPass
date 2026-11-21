# ZeroPass ブラウザ拡張と拡張ブリッジ仕様（extension.md）

- 版: 0.1（ドラフト）
- 関連: [ADR-0004](../adr/0004-process-architecture.md)、[脅威モデル](../threat-model.md) §4（境界 B2・B3）、T6、`docs/spec/ipc.md` §5
- 実装: `apps/extension`（拡張）、`bins/zp-nmh`（拡張ブリッジ）、`crates/zp-origin`（オリジンの照合）、`bins/zp-vaultd`（拡張ブリッジの要求）
- タスク: P4-04（本書の §1〜§5）、P4-05（§6・§7）、P4-06（§8・§9）、P5-04（§11）

ブラウザ拡張は、ページのログインフォームに金庫のログインを入力し、ページのためにパスキーを作って使う（§11）。拡張は秘密を持たず、入力の瞬間にだけ、拡張ブリッジ `zp-nmh` を通じて金庫デーモンに 1 件ずつ尋ねる。

```
Web ページ ⇄ content script ⇄ 拡張の background ⇄（Native Messaging, stdio）⇄ zp-nmh ⇄（IPC, 拡張ブリッジの役割）⇄ zp-vaultd
```

## 1. 原則

1. **拡張は秘密を保持しない。** パスワードは入力のために 1 件ずつ受け取り、フォームに入れたら捨てる。保存しない（`storage` に書かない）。
2. **オリジンはブラウザが決める。** 照合に使うオリジンは、background が `runtime.onMessage` の `sender`（送り手のフレームの URL）から得る。content script やページが名乗るオリジンは使わない。
3. **照合は金庫デーモンが行う。** 拡張とブリッジはオリジンを渡すだけで、どのログインがそのオリジンのものかは金庫デーモンが決める（§5）。パスワードは、そのオリジンに一致したログインについてだけ返す。
4. **拡張ブリッジができることは狭い。** 一覧（`ListItems`）・項目の取得（`GetItem`）・解錠（パスワードのドメイン）はできない。施錠されていれば、利用者をデスクトップアプリへ案内する。
5. **入力は利用者の操作から。** ページを読み込んだだけで入力しない。利用者が候補を選んだとき（ブラウザが `isTrusted` と認めた操作）だけ入力する（§7）。

## 2. 拡張の識別

| ブラウザ | 拡張 ID | 決め方 |
|---|---|---|
| Chrome / Edge（展開した開発版） | `gehobienihkbhglhnibeobdkgeinamdn` | 拡張の `manifest.json` の `key`（公開鍵）から導かれる |
| Firefox | `zeropass@makomo-oss.github.io` | `browser_specific_settings.gecko.id` |

- ストアで配布するときの ID（Chrome Web Store、Edge アドオン）は、配布方式とともに P8-03 で加える。
- `key` は公開鍵なので秘密ではない。秘密鍵はリポジトリに置かない（展開した拡張には要らない）。

## 3. Native Messaging ホスト

### 3.1 登録

ホスト名は `io.github.makomo_oss.zeropass`。インストーラ（`packaging/windows/install.ps1`）が、インストール先にマニフェストを 2 つ置き、マシン全体のレジストリに登録する。マニフェストもインストール先（管理者しか書き換えられない）に置く。

| ブラウザ | レジストリのキー（既定値 = マニフェストのパス） | マニフェスト | 許可する拡張 |
|---|---|---|---|
| Chrome | `HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\io.github.makomo_oss.zeropass` | `zp-nmh-chrome.json` | `allowed_origins`: `chrome-extension://<ID>/` |
| Edge | `HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\…` | 同上 | 同上 |
| Chromium | `HKLM\SOFTWARE\Chromium\NativeMessagingHosts\…` | 同上 | 同上 |
| Firefox | `HKLM\SOFTWARE\Mozilla\NativeMessagingHosts\…` | `zp-nmh-firefox.json` | `allowed_extensions`: Firefox の ID |

アンインストーラは、これらのキーのうち、インストール先のマニフェストを指すものを消す。

### 3.2 接続元の検査

- ブラウザは、マニフェストが許す拡張にだけホストへの接続を許す。これが主な検査である。
- `zp-nmh` も起動時の引数を確かめる。Chrome 系は最初の引数に `chrome-extension://<ID>/` を、Firefox は 2 番目の引数に拡張 ID を渡す。§2 の ID でなければ、何も読まずに終わる。
- **限界**: 引数は起動した者が自由に決められる。同じ利用者のプログラムが `zp-nmh` を直接起動し、正しい ID を名乗ることはできる。その場合でも、できるのは §4 の範囲（オリジンに一致したログインを 1 件ずつ）で、照合のためのオリジンも名乗れてしまう。同じ利用者のマルウェアは防御範囲外（脅威モデル §6）であり、IPC のパスの照合（`ipc.md` §3.3）と同じ限界である。

### 3.3 通信

Native Messaging の形式（4 バイトのネイティブエンディアンの長さ ‖ UTF-8 の JSON）。拡張からの 1 つの要求に、ブリッジは 1 つの応答を返す。

```json
→ { "id": 7, "type": "find", "origin": "https://accounts.example.com" }
← { "id": 7, "ok": true, "logins": [ { "id": "…32 桁…", "title": "Example", "username": "alice", "match": "exact" } ] }
← { "id": 7, "ok": false, "error": { "code": "Locked", "message": "…" } }
```

| `type` | 引数 | 応答 | 金庫デーモンへの要求 |
|---|---|---|---|
| `status` | — | `vault`（金庫があるか）、`running`（デーモンが動いているか）、`unlocked`（パスワードのドメイン）、`totp`（TOTP のドメインがあるか）、`passkeys`（パスキーのドメインがあるか） | `Status` |
| `find` | `origin`、`top`（タブの最上位のフレームのオリジン） | `logins`: `id`、`title`、`username`、`match`（`exact` / `site`）。**パスワードは含まない** | `BridgeFind` |
| `fill` | `origin`、`top`、`item`（ログインの ID） | `username`、`password` | `BridgeFill` |
| `totp` | `origin`、`top`、`item`（ログインの ID） | `code`（Windows Hello が尋ねる） | `BridgeTotp` |
| `compare` | `origin`、`top`、`username`、`password` | `item`（そのページの、その利用者名のログイン。なければ空）、`same`（パスワードも同じか） | `BridgeCompare` |
| `save` | `origin`、`top`、`title`、`username`、`password` | `item`（新しいログインの ID） | `BridgeSave` |
| `update` | `origin`、`top`、`item`、`password` | — | `BridgeUpdate` |
| `passkey_create` | `origin`、`top`、`rp_id`、`rp_name`、`user_id`、`user_name`、`user_display_name`、`challenge`、`algorithms`（COSE の番号、好みの順）、`exclude`（ID の一覧） | `credential_id`、`client_data_json`、`attestation_object`、`authenticator_data`、`public_key`、`algorithm`（Windows Hello が尋ねる） | `PasskeyCreate`（`passkey.md` §9） |
| `passkey_get` | `origin`、`top`、`rp_id`、`challenge`、`allow`（ID の一覧）、`chosen`（選んだ候補の ID。なければ空） | `credential_id`、`client_data_json`、`authenticator_data`、`signature`、`user_handle`、または `choices`（`credential_id`、`user_name`、`display_name`）（Windows Hello が尋ねる。選んだ候補の送り直しを除く） | `PasskeyGet` |
| `open_app` | — | — | （なし。デスクトップアプリを起動する） |

- エラーの `code` は IPC のエラーコード（`ipc.md` §4.2。`Locked`、`NoVault` など）か、ブリッジのもの（`NotRunning`: 金庫デーモンが動いていない、`BadRequest`）。
- パスキーの要求のバイト列（チャレンジ、ユーザーハンドル、クレデンシャル ID、署名など）は base64url（パディングなし）で書く。ブラウザの `PublicKeyCredential.toJSON()` と同じ。
- ブリッジは金庫デーモンを起動しない（ブラウザが Native Messaging のホストをジョブに入れ、ホストの終了とともに子プロセスを終わらせることがあるため）。動いていなければ `NotRunning` を返し、拡張は利用者に ZeroPass を開くよう案内する（`open_app`）。
- 1 つのメッセージの上限は、ブラウザへは 1 MiB（Chrome の上限）、ブリッジへは 64 KiB とする（超えたら終了する）。

## 4. 金庫デーモンの要求（拡張ブリッジの役割）

番号 100〜111 を使う（`ipc.md` §4.3）。

| 番号 | 要求 | 応答 | 内容 |
|---|---|---|---|
| 100 | `BridgeFind { origin, top_origin }` | `BridgeLogins`（応答 24） | `origin` に一致するログイン（§5）。ID、題名、利用者名、一致の度合い。パスワードの要らない場面でも、**秘密は含まない** |
| 101 | `BridgeFill { origin, item_id, top_origin }` | `BridgeCredential`（応答 25） | ログイン 1 件の利用者名とパスワード。そのログインが `origin` に一致しなければ `DENIED` |
| 102 | `BridgeTotp { origin, top_origin, item_id }` | `TotpCodeReply` | ログインがページに一致すれば、TOTP のドメインを**施錠してから鍵エージェントで解錠し直し**（毎回 Windows Hello）、そのログインに結び付いた TOTP のコードを返す。結び付いたものがなければ `ITEM_NOT_FOUND` |
| 103 | `BridgeSave { origin, top_origin, title, username, password }` | `ItemAdded` | ページのオリジンを URL とするログインを加える |
| 104 | `BridgeUpdate { origin, top_origin, item_id, password }` | `Done` | ページに一致するログインのパスワードを置き換える |
| 105 | `BridgeCompare { origin, top_origin, username, password }` | `BridgeComparison`（応答 26） | ページに一致し、利用者名が同じログインと、そのパスワードが同じか |

拡張ブリッジの役割が呼べるのは、`Hello`、`Status`、この表の要求だけである。パスワードのドメインが施錠されていれば `LOCKED`。

## 5. オリジンの照合

実装は `crates/zp-origin`。

### 5.1 ページのオリジン

- `scheme://host[:port]` の形。scheme は `https` か `http`。host は ASCII（国際化ドメイン名は Punycode。ブラウザの `URL.origin` の形）を小文字で。それ以外の形は `BAD_REQUEST`。

### 5.2 保存された URL

- ログインの URL を、scheme がなければ `https://` を補って WHATWG URL として読む。国際化ドメイン名は Punycode に、ホストは小文字にする。読めない URL は照合しない。

### 5.3 一致

ページのオリジン `P` とログインの URL `L` について:

| 度合い | 条件 |
|---|---|
| `exact` | scheme、ホスト、ポート（既定のポートを補う）がすべて等しい。ただし `L` が `http` で `P` が `https` のとき（同じホスト・既定のポート）も含める（https への格上げ） |
| `site` | どちらのホストもドメイン名で、**登録可能ドメイン**（公開サフィックスリストの私的な部分を含めた eTLD+1）が等しく、空でない。scheme は `exact` と同じ規則（`L` が `https` で `P` が `http` なら一致しない）。ポートは等しい |

- IP アドレス、`localhost`、ドットのないホストは `exact` だけで照合する。
- ホストそのものが公開サフィックス（`github.io` など）なら、`site` で照合しない。私的な公開サフィックス（`*.github.io`、`*.blogspot.com` など）の下の別の利用者のサイトは、別のサイトである。
- ログインに URL が複数あれば、最も強い度合いを採る。結果は `exact` を先に、次に題名の順に並べる。

### 5.4 これで防ぐもの

- 似た文字のドメイン（ホモグラフ）: Punycode どうしで比べるので、見た目が同じでも別のドメインには一致しない。
- `http` への格下げ: `https` で保存したログインは、`http` のページに入力しない。
- 共有ホスティングの別の利用者: 私的な公開サフィックスで区切る。
- 似た名前の別ドメイン（`example.com.evil.net`、`examp1e.com`）: 登録可能ドメインが違えば一致しない。

## 6. 拡張（P4-05）

- WXT + TypeScript、Manifest V3。Chrome・Edge・Firefox。
- 権限: `nativeMessaging` だけ。`storage`・`tabs`・`activeTab`・`scripting` は使わない。ツールバーのポップアップは、今のタブの最上位のフレームの content script に、ログインを探させて（`find_now`）入力させる（`fill_now`）。タブのアドレスを読む権限は要らず、オリジンは常にブラウザの `sender` から得る。content script はすべてのサイトの全フレームに入る（`<all_urls>`、`all_frames`）。Chrome・Edge は Manifest V3、Firefox は Manifest V2（WXT の既定。Firefox の V3 ではサイトへの権限が利用者の許可制になるため）。
- background（service worker）がブリッジとの接続を持ち、content script の要求に、`sender` から得たオリジンを付けて中継する。

## 7. フォームの検出と入力（P4-05）

- パスワード欄（`input[type=password]`）と、その前にある利用者名の欄（`type` が `email`・`text`・`tel`、または `autocomplete` が `username`・`email`）を探す。利用者名だけの段階（2 段階のログイン）も扱う。DOM の変化を見て、後から現れたフォームにも対応する。
- 候補の表示: 欄にフォーカスすると、ページから切り離した表示（閉じた Shadow DOM）に、一致したログインの題名と利用者名を出す。パスワードは出さない。
- **入力の条件**（すべて満たすときだけ）:
  1. 利用者が候補を選んだ（`isTrusted` のクリックまたはキー操作）。
  2. 入力するフレームのオリジンが、タブの最上位のフレームと同じサイト（登録可能ドメイン）である。別のサイトの `iframe` の中には入力しない（クリックジャッキングの対策）。background は両方のオリジンをブラウザから得てブリッジに渡し（`find`・`fill` の `top`）、金庫デーモンが確かめる（`BridgeFind`・`BridgeFill` の `top_origin`。違えば候補なし・`DENIED`）。
  3. 欄が見えている（表示され、大きさがあり、透明でない、画面の外でない）、有効で、読み取り専用でない。
  4. パスワードは `type=password` の欄にだけ入れる。
- 入力は、ページの枠組み（React など）が気付くように、値の設定と `input`・`change` イベントで行う。フォームは送信しない。

## 8. 保存・更新の提案（P4-06）

- 利用者がフォームを送信したとき、入力されたパスワードが金庫のものと違えば（または一致するログインがなければ）、保存か更新を提案する。提案は、利用者が「保存」を選んだときだけブリッジに送る。
- 送信を検出する（`submit`、送信のボタンのクリック、パスワード欄での Enter。いずれも `isTrusted`）と、content script は入力された利用者名とパスワードを background に渡し、background がブリッジで金庫と比べる（`compare`）。同じなら何もしない。利用者名が同じで違うパスワードなら更新、なければ保存を提案する。利用者名は大文字・小文字を区別せずに比べる。2 段階のログインでは、前の画面で入力された利用者名を background がそのタブについて 5 分覚えておく（秘密ではない）。
- 利用者を覚えているサイトは、パスワードの欄だけを出すことが多い。利用者名を入力する欄がないときは、フォームの中の隠れた欄・読み取り専用の欄にある利用者名（`autocomplete="username"` など）を使う。それもなければ利用者名なしで比べる。この場合、そのページのログインに同じパスワードがあれば何もしない。ないときは、どのログインのことか分からないので提案しない（違うログインを書き換えないため）。ログインが 1 件もないページでだけ、保存を提案する。利用者名なしで保存したログインは、後で利用者名付きで同じパスワードを入力したとき、同じログインとみなす。
- 提案のために覚えておく値（パスワードを含む）は、**background のメモリにだけ**、そのタブについて、利用者が答えるか、2 分たつか、タブを閉じるまで置く。拡張の `storage` には書かない。送信の後にページが移っても、移った先の最上位のフレームが提案を受け取って表示する。MV3 の service worker が止まれば、提案は失われる。
- 保存するログインの URL は入力したページのオリジン、題名はそのホスト。更新はパスワードだけを置き換える。どちらもページに一致するログイン・同じサイトのフレームに限る（金庫デーモンが確かめる）。

## 9. TOTP の入力（P4-06）

- ワンタイムコードの欄（`autocomplete="one-time-code"`、名前や ID に otp・2fa・verification code などを含む短い欄）にフォーカスすると、そのページのログインを示し、利用者が選んだログインに結び付いた TOTP のコードを入力する。1 文字ずつの欄に分かれた入力は、まだ扱わない。
- ブリッジは、`totp` のたびに鍵エージェントを起動する（`ipc.md` §13.2）。
- **金庫デーモンは、`BridgeTotp` のたびに Windows Hello で利用者を確かめる**（TOTP のドメインがすでに解錠されていても）。拡張やブリッジが乗っ取られても、利用者の操作なしにコードを取り出せないようにするためである。

## 10. 限界

- 拡張とブリッジが乗っ取られれば、オリジンを偽って、施錠されていないパスワードのドメインのログインを 1 件ずつ取り出せる。照合はデーモンが行うが、オリジンは拡張が名乗るので、乗っ取られた拡張には効かない。防げるのは、ページ（B3）からの攻撃と、拡張の不具合による誤入力である。
- 開発版の拡張 ID は公開鍵から導かれるので、同じ公開鍵を持つ展開した拡張は同じ ID になる。ストアの ID（P8-03）では、ストアが ID を管理する。
- 乗っ取られたブリッジは、`BridgeTotp` で TOTP のドメインを何度でも施錠させ、Windows Hello の確認画面を出させることができる。コードを得るには利用者の承認が要るが、承認を繰り返し求められる（利用者が慣れて承認してしまう）おそれはある。
- 送信の検出は推測である。パスワードの欄に値があるときに押されたボタンを送信とみなす（表示の切り替えらしいボタンは除く）ので、送信の前に提案が出たり、送信を見逃したりすることがある。提案は利用者が選んだときだけ保存・更新する。
- パスキーについては §11.5。

## 11. パスキー（P5-04）

ページが `navigator.credentials.create` / `.get` でパスキーを求めたとき、利用者が選べば ZeroPass が答える。選ばなければ、ブラウザ自身の WebAuthn（ほかのパスキーのプロバイダ、セキュリティキー、スマートフォン）が答える。認証器の仕様は `passkey.md`。

### 11.1 仕組み

```
ページ ─ navigator.credentials ─▶ ページの世界のスクリプト（webauthn.content.ts）
        ─ window.postMessage ─▶ content script（passkeys.content.ts。ダイアログ）
        ─ runtime.sendMessage ─▶ background（オリジンは sender から）─▶ zp-nmh ─▶ zp-vaultd
```

- **ページの世界のスクリプト**: すべてのフレームで、ページのスクリプトより前に（`document_start`、`world: "MAIN"`）`CredentialsContainer.prototype` の `create` と `get` を置き換える。`publicKey` のない要求、条件付きの仲介（`mediation: "conditional"`、パスキーの自動入力）と `silent` は、元の関数に渡す。それ以外は、要求を JSON（バイト列は base64url）にして、同じフレームの content script に `window.postMessage` で渡す。content script が 2 秒以内に受け取らなければ、ブラウザに任せる。
- **content script**: 同じウィンドウ（`event.source === window`）からのメッセージだけを受け取る。別のフレームや別のウィンドウからの要求は無視する。1 フレームに 1 つずつ扱い、扱っている間の次の要求には `NotAllowedError` を返す。
- **background**: 要求のオリジンを `sender` から得て（§1）、ブリッジの `passkey_create` / `passkey_get` を呼ぶ。ページや content script が名乗るオリジンは使わない。
- 結果は、ページの世界のスクリプトが `PublicKeyCredential` の形のオブジェクト（`PublicKeyCredential.prototype` を継ぐ。`rawId`、`response`（`AuthenticatorAttestationResponse` / `AuthenticatorAssertionResponse` を継ぐ）、`getClientExtensionResults()`、`toJSON()`、`authenticatorAttachment: "platform"`、`getTransports()` は `["internal"]`）にしてページに返す。

### 11.2 ブラウザに任せるもの

ZeroPass は何も表示せず、元の関数がそのまま答える。

- ZeroPass が動いていない、金庫がない、パスキーのドメインがない（`status` の `passkeys`）。
- 作成で、`authenticatorAttachment` が `cross-platform`、または `pubKeyCredParams` に ES256・EdDSA がない（空なら ES256 で作る）。
- 最上位のフレームとオリジンが違うフレーム（同じサイトでも。ログインの入力より狭い）。
- 条件付きの仲介と `silent`。

### 11.3 ダイアログ

ページの右上に、閉じた Shadow DOM のダイアログを出す。ボタンは `isTrusted` のクリックだけを受け付ける（ページはダイアログの中を読めず、押せない）。

1. **提案**: 作成なら「Save a passkey for <RP>?」（アカウント名つき）、署名なら「Sign in to <RP> with a passkey?」。「Save in ZeroPass」/「Use ZeroPass」、「Use another device or key」（ブラウザに任せる）、「Cancel」（`NotAllowedError`）。
2. **Windows Hello の待ち**: ZeroPass を選ぶと、ブリッジが鍵エージェントを起動し（`ipc.md` §13.2）、金庫デーモンが Windows Hello で利用者を確かめる。この間、ダイアログに取り消しのボタンは置かない（Hello で承認したものは、必ずページに届ける）。
3. **選択**: 候補が複数なら、アカウント名と表示名の一覧を出す。選んだものは、同じ要求に `chosen` を添えて送り直す（もう一度は尋ねない。`passkey.md` §9.2）。
4. **結果**: 作成・署名できればダイアログを閉じてページに返す。できなければ、次のとおり。

| ブリッジのエラー | ページへ |
|---|---|
| `UserCancelled` | すぐに `NotAllowedError` |
| `Denied` | すぐに `SecurityError` |
| `CredentialExcluded` | 「ZeroPass already keeps a passkey of this account」と示し、閉じたら `InvalidStateError` |
| `ItemNotFound` | 「ZeroPass has no passkey for <RP>」と示し、ブラウザに任せるか `NotAllowedError` |
| そのほか | 理由を示し、ブラウザに任せるか `NotAllowedError` |

- ページが `AbortSignal` で取り消せば、ページの世界のスクリプトはすぐに `AbortError`（`signal.reason`）で終え、ダイアログを閉じる。Windows Hello の後に届いた結果は捨てる。

### 11.4 拡張（WebAuthn extensions）

- `credProps` を求められれば `{ rk: true }` を返す（すべて発見可能なクレデンシャル）。ほかの拡張は無視し、結果に含めない。

### 11.5 限界

- **Firefox**: ページの世界のスクリプトには、`content_scripts` の `world: "MAIN"` に対応した Firefox が要る。対応していない版では置き換えが効かず、ブラウザ自身の WebAuthn が答える（害はない）。Firefox では確かめていない。
- **パスキーの自動入力**（条件付きの仲介）には加わらない。ZeroPass のパスキーは、ページの「パスキーでサインイン」などのボタン（モーダルの要求）から使う。
- **ページの世界**: 置き換えたスクリプトはページと同じ世界で動くので、ページのスクリプトはそれを見たり、さらに置き換えたりできる。できるのは、そのページ自身の要求（そのページの RP のパスキー）に関わることだけで、ほかのサイトのパスキーには触れられない（オリジンはブラウザが決め、照合は金庫デーモンが行う）。
- 乗っ取られた拡張とブリッジの限界は §10 と同じ（オリジンを偽れば、別のサイトのパスキーで署名させられる。署名のたびに Windows Hello が利用者を確かめることは変わらない）。
