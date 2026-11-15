# ZeroPass 暗号化エクスポートとインポート仕様（export.md）

- 版: 0.1（ドラフト）
- 関連: [`crypto.md`](crypto.md) §4（エンベロープ）・§5（鍵導出）、[`ipc.md`](ipc.md) §4.2・§13.1、[ADR-0007](../adr/0007-domain-processes-and-key-agent.md)
- 実装: `crates/zp-crypto`（`ExportKey`）、`crates/zp-vault`（`export`）、`crates/zp-import`、`bins/zp-vaultd`、`bins/zp-cli`（`export` / `import`）、`apps/desktop`（設定の「Import」「Encrypted export」）
- タスク: P4-07

## 1. 目的

- **暗号化エクスポート**: 金庫のすべてのアイテム（TOTP のシード、パスキーの秘密鍵を含む）を、利用者がその場で決めるパスフレーズで保護した 1 つのファイルにする。別の金庫に取り込める。端末を持たない予備の写しや、ZeroPass の別のインストールへの移行に使う。
- **インポート**: ほかのパスワードマネージャーが書き出したファイル（平文）から、ログイン・セキュアノート・TOTP を取り込む。

復旧キット（`crypto.md` §8）は金庫ファイルとともに使う復旧の手段で、エクスポートはそれとは別の、金庫ファイルなしで読める写しである。

## 2. ファイル形式（バージョン 1）

```
file     = header ‖ envelope
header   = "ZPEXPORT"（8 バイト）‖ version（1 バイト、= 0x01）
           ‖ m（u32）‖ t（u32）‖ p（u32）‖ salt（16 バイト）       -- 整数はビッグエンディアン
key      = HKDF-SHA256(salt = salt,
                       ikm = Argon2id(UTF-8(NFKC(passphrase)), salt, m, t, p, 32 バイト),
                       info = "zeropass/v1/export")
envelope = crypto.md §4 のエンベロープ（version 1、XChaCha20-Poly1305）、関連データ = header
平文     = ExportArchive（Protocol Buffers）
```

- `info` が `KEK-P`（`"zeropass/v1/kek/password"`）と違うので、同じ文字列をマスターパスワードとパスフレーズに使っても、同じ鍵にはならない。
- `m`・`t`・`p` は作成時に較正する（`crypto.md` §5 と同じく約 500 ms）。読むときは `crypto.md` §5 の上限を超えるパラメータを拒む（偽のファイルで資源を使い果たさせない）。
- パスフレーズは 12 文字以上（マスターパスワードと同じ）。
- 誤ったパスフレーズ、別のヘッダ、書き換えられたファイルは、どれも同じ失敗（`WRONG_PASSWORD`）になる。

```protobuf
message ExportArchive {
  bytes  vault_id   = 1;   // 書き出した金庫
  uint64 created_ms = 2;   // 作成時刻（UNIX ミリ秒）
  repeated ExportedItem items = 3;
}
message ExportedItem {
  bytes item_id = 1;                 // 元の金庫での ID（TOTP とログインの結び付きのため）
  Login             login   = 2;     // 以下のどれか 1 つ（zp-vault の model）
  SecureNote        note    = 3;
  TotpEntry         totp    = 4;     // シードを含む
  PasskeyCredential passkey = 5;     // 秘密鍵を含む
}
```

## 3. 作成と取り込みはデーモンの中で

- **作成**（`ExportVault { passphrase }` → `Exported { data, counts }`、要求 18・応答 27）と**取り込み**（`ImportExport { data, passphrase }` → `ImportedItems { counts }`、要求 19・応答 28）は、金庫デーモンの**全体プロセス**（`ipc.md` §13.1）が行う。すべての金庫鍵を持つのはこのプロセスだけである。UI の役割だけが出せる。
- 金庫のすべてのドメインが解錠されていなければ `LOCKED`（クライアントは解錠してやり直す。TOTP・パスキーは Windows Hello）。
- **平文のアイテムは、金庫デーモンの外に出ない。** UI はパスフレーズを渡し、封をしたファイルを受け取って書き込む（デーモンはサンドボックスの中で、利用者の選んだ場所に書けない）。取り込みでは、ファイルを読んでデーモンに渡す。TOTP のシードを返す要求はない（`ipc.md` §6）ことが、ここでも保たれる。
- 取り込んだアイテムは新しいアイテムになる（新しい ID）。TOTP の結び付きは、元の ID から新しいログインの ID に付け替える。同じファイルを 2 度取り込めば、2 組になる。
- 取り込みは、ファイルを開けて、必要なドメインがすべて解錠されていることを確かめてから書き始める。

## 4. ほかのパスワードマネージャーからのインポート

| 出元 | ファイル | 見分け方 |
|---|---|---|
| Chrome・Edge（ほかの Chromium 系） | CSV `name,url,username,password[,note]` | `name`・`url`・`password` の列 |
| Firefox | CSV `url,username,password,httpRealm,formActionOrigin,…` | `httpRealm` か `formActionOrigin` の列 |
| Bitwarden | 暗号化しない JSON（`{"encrypted": false, "items": [...]}`） | `{` で始まる |
| Bitwarden | CSV `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp` | `type` と `login_password` の列 |
| 1Password | CSV（`Title,Url,Username,Password,OTPAuth,…,Notes` など。列名で読む） | `title` と `password` の列 |

- 取り込むもの: ログイン（題名、利用者名、パスワード、URL、メモ）、セキュアノート、TOTP（`otpauth://` のアドレス、または Base32 の秘密鍵。後者はアドレスに直す）。取り込まないもの: カード、個人情報、カスタムフィールド、添付ファイル、フォルダ（件数だけ示す）。Bitwarden の暗号化したエクスポートは読まない（暗号化しないで書き出し直すよう案内する）。1Password の 1PUX 形式は読まない（CSV で書き出す）。
- **ファイルは UI のプロセスで読む**（`crates/zp-import`）。平文のファイルを読めるのは、もともと利用者とその UI である。読んだ内容はページ（デスクトップアプリのウェブビュー）に渡さず、件数だけを示す。アイテムは 1 件ずつ `AddItem` で金庫デーモンに加える（TOTP は、加えたログインの ID に結び付けて）。1 件の失敗（不正な `otpauth://` など）でほかを止めない。
- 取り込んだ後、元のファイルを消すよう利用者に案内する（平文のパスワードが残るため）。

## 5. 限界

- エクスポートのファイルとパスフレーズの両方を得た者は、すべてを読める。パスフレーズの強さは利用者に依存する（長さだけを求める）。Argon2id のコストで総当たりを遅らせる。
- エクスポートには失効の考え方がない。一度書き出したファイルは、パスフレーズとともに、書き出した時点の内容を明かし続ける。
