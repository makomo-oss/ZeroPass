# ZeroPass ブラウザ拡張と拡張ブリッジ仕様（extension.md）

- 版: 0.1（ドラフト）
- 関連: [ADR-0004](../adr/0004-process-architecture.md)、[脅威モデル](../threat-model.md) §4（境界 B2・B3）、T6、`docs/spec/ipc.md` §5
- 実装: `apps/extension`（拡張）、`bins/zp-nmh`（拡張ブリッジ）、`crates/zp-origin`（オリジンの照合）、`bins/zp-vaultd`（拡張ブリッジの要求）
- タスク: P4-04（本書の §1〜§5）、P4-05（§6・§7）、P4-06（§8・§9）

ブラウザ拡張は、ページのログインフォームに金庫のログインを入力する。拡張は秘密を持たず、入力の瞬間にだけ、拡張ブリッジ `zp-nmh` を通じて金庫デーモンに 1 件ずつ尋ねる。

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
| `status` | — | `vault`（金庫があるか）、`running`（デーモンが動いているか）、`unlocked`（パスワードのドメイン）、`totp`（TOTP のドメインがあるか） | `Status` |
| `find` | `origin` | `logins`: `id`、`title`、`username`、`match`（`exact` / `site`）。**パスワードは含まない** | `BridgeFind` |
| `fill` | `origin`、`item`（ログインの ID） | `username`、`password` | `BridgeFill` |
| `totp` | `origin`、`item`（ログインの ID） | `code` | `BridgeTotp`（P4-06） |
| `save` | `origin`、`title`、`username`、`password` | `id` | `BridgeSave`（P4-06） |
| `update` | `origin`、`item`、`username`、`password` | — | `BridgeUpdate`（P4-06） |
| `open_app` | — | — | （なし。デスクトップアプリを起動する） |

- エラーの `code` は IPC のエラーコード（`ipc.md` §4.2。`Locked`、`NoVault` など）か、ブリッジのもの（`NotRunning`: 金庫デーモンが動いていない、`BadRequest`）。
- ブリッジは金庫デーモンを起動しない（ブラウザが Native Messaging のホストをジョブに入れ、ホストの終了とともに子プロセスを終わらせることがあるため）。動いていなければ `NotRunning` を返し、拡張は利用者に ZeroPass を開くよう案内する（`open_app`）。
- 1 つのメッセージの上限は、ブラウザへは 1 MiB（Chrome の上限）、ブリッジへは 64 KiB とする（超えたら終了する）。

## 4. 金庫デーモンの要求（拡張ブリッジの役割）

番号 100〜111 を使う（`ipc.md` §4.3）。

| 番号 | 要求 | 応答 | 内容 |
|---|---|---|---|
| 100 | `BridgeFind { origin }` | `BridgeLogins`（応答 24） | `origin` に一致するログイン（§5）。ID、題名、利用者名、一致の度合い。パスワードの要らない場面でも、**秘密は含まない** |
| 101 | `BridgeFill { origin, item_id }` | `BridgeCredential`（応答 25） | ログイン 1 件の利用者名とパスワード。そのログインが `origin` に一致しなければ `DENIED` |
| 102 | `BridgeTotp { origin, item_id }` | `TotpCodeReply` | P4-06 |
| 103 | `BridgeSave { origin, title, username, password }` | `ItemAdded` | P4-06 |
| 104 | `BridgeUpdate { origin, item_id, username, password }` | `Done` | P4-06 |

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
- 権限: `nativeMessaging`、`storage` は使わない、`activeTab`・`scripting` は使わない。content script はすべてのサイトの全フレームに入る（`<all_urls>`、`all_frames`）。
- background（service worker）がブリッジとの接続を持ち、content script の要求に、`sender` から得たオリジンを付けて中継する。

## 7. フォームの検出と入力（P4-05）

- パスワード欄（`input[type=password]`）と、その前にある利用者名の欄（`type` が `email`・`text`・`tel`、または `autocomplete` が `username`・`email`）を探す。利用者名だけの段階（2 段階のログイン）も扱う。DOM の変化を見て、後から現れたフォームにも対応する。
- 候補の表示: 欄にフォーカスすると、ページから切り離した表示（閉じた Shadow DOM）に、一致したログインの題名と利用者名を出す。パスワードは出さない。
- **入力の条件**（すべて満たすときだけ）:
  1. 利用者が候補を選んだ（`isTrusted` のクリックまたはキー操作）。
  2. 入力するフレームのオリジンが、タブの最上位のフレームと同じサイト（登録可能ドメイン）である。別のサイトの `iframe` の中には入力しない（クリックジャッキングの対策）。
  3. 欄が見えている（表示され、大きさがあり、透明でない、画面の外でない）、有効で、読み取り専用でない。
  4. パスワードは `type=password` の欄にだけ入れる。
- 入力は、ページの枠組み（React など）が気付くように、値の設定と `input`・`change` イベントで行う。フォームは送信しない。

## 8. 保存・更新の提案（P4-06）

- 利用者がフォームを送信したとき、入力されたパスワードが金庫のものと違えば（または一致するログインがなければ）、保存か更新を提案する。提案は、利用者が「保存」を選んだときだけブリッジに送る。
- 提案のために覚えておく値は、そのタブの content script のメモリにだけ置き、提案を閉じるか、ページを離れたら捨てる。拡張の `storage` には書かない。

## 9. TOTP の入力（P4-06）

- ワンタイムコードの欄（`autocomplete="one-time-code"` など）に、ログインに結び付いた TOTP のコードを入力する。
- **金庫デーモンは、`BridgeTotp` のたびに Windows Hello で利用者を確かめる**（TOTP のドメインがすでに解錠されていても）。拡張やブリッジが乗っ取られても、利用者の操作なしにコードを取り出せないようにするためである。

## 10. 限界

- 拡張とブリッジが乗っ取られれば、オリジンを偽って、施錠されていないパスワードのドメインのログインを 1 件ずつ取り出せる。照合はデーモンが行うが、オリジンは拡張が名乗るので、乗っ取られた拡張には効かない。防げるのは、ページ（B3）からの攻撃と、拡張の不具合による誤入力である。
- 開発版の拡張 ID は公開鍵から導かれるので、同じ公開鍵を持つ展開した拡張は同じ ID になる。ストアの ID（P8-03）では、ストアが ID を管理する。
