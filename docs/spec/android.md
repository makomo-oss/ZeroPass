# ZeroPass Android アプリ仕様（android.md）

- 版: 0.1（ドラフト）
- 関連: [ADR-0004](../adr/0004-process-architecture.md)、[ADR-0012](../adr/0012-android-vault-process.md)、`ipc.md` §14、`ble.md`、`lan.md`、`crypto.md` §7
- 実装: `apps/android`、`crates/zp-ffi`（UniFFI）、`bins/zp-vaultd`（金庫の処理）

Android アプリの構成（プロセス、金庫の保存、鍵ストア、同期、自動入力とパスキー）を定める。金庫・同期・ペアリング・パスキーの中身はデスクトップと同じ Rust のコードで、Kotlin は Android の API（画面、Binder、Keystore、Bluetooth、自動入力、Credential Manager）だけを受け持つ。

## 1. プロセス

| プロセス | 中身 | 権限 |
|---|---|---|
| アプリ（`io.github.makomooss.zeropass`） | 画面（Jetpack Compose）、鍵エージェント（Keystore、§3）、金庫ファイルの保管、同期とペアリングのネットワーク（LAN は Rust、BLE は Kotlin）、自動入力のサービス、Credential Manager のプロバイダ | `INTERNET`（LAN 同期）、Bluetooth、カメラ（QR）、通知 |
| 金庫（`:vault`、`isolatedProcess`） | 金庫デーモンの処理（`zp-vaultd` の `Service`、すべてのドメイン） | なし |

- 金庫のプロセスは、`VaultService`（`exported="false"`、`isolatedProcess="true"`）として、アプリのプロセスが `bindService` している間だけ動く。アプリが離れると OS が終わらせ、鍵はメモリから消える。
- アプリのプロセスには金庫鍵がない（ADR-0012 §6）。金庫のプロセスはネットワークもファイルも Keystore も使えない。
- 両方のプロセスが同じ Rust のライブラリ（`libzp_ffi.so`）を読み込む。金庫のプロセスで使うのは金庫の処理だけ、アプリのプロセスで使うのはクライアントとネットワークだけである。

## 2. 金庫のプロセスへの接続

1. アプリのプロセスは `VaultService` に `bindService` する。サービスは Binder のインターフェース `IVaultService` を返す。
2. 接続を 1 本開くたびに、アプリのプロセスは `ParcelFileDescriptor.createSocketPair()` でソケットの組を作り、一方を `IVaultService.connect(ParcelFileDescriptor)` で渡す。金庫のプロセスは、受け取ったソケットで `ipc.md` の会話を新しいスレッドで始める。もう一方はアプリのプロセスの Rust が `Client` として使う。
3. アプリのプロセスは、最初に次の 2 つの中継を開いたままにする。
   - **イメージの保管役**（`ImageHostAttach`、`ipc.md` §14.2、§2.1）
   - **鍵エージェント**（`KeyAgentAttach`、`ipc.md` §13.2、§3）
4. その後の要求（解錠、一覧、同期の要求、ペアリングの中継など）は、デスクトップの UI・同期デーモンと同じものを、必要なだけ接続を開いて送る。

### 2.1 金庫ファイル

- 場所はアプリのデータディレクトリの `files/vault.zpvault`。バックアップの対象にしない（`allowBackup="false"`）。
- 保存は、同じディレクトリの一時ファイル `vault.zpvault.tmp` に書き、`fsync` し、`rename` で置き換え、ディレクトリを `fsync` する。置き換えの途中で止まっても、前の版か新しい版のどちらかが残る。
- 金庫のプロセスは、要求で金庫が変わったら答える前に保存させる（`ipc.md` §14.2）。答えを受け取った変更は失われない。
- PoC（P2-16）の金庫ファイル（`files/vault.zpvault`）は形式が同じなので、そのまま開ける。

## 3. 鍵エージェント（Android Keystore）

TOTP とパスキーのドメインの鍵（VK-T・VK-K）は、Android Keystore の HMAC の鍵でラップする（`crypto.md` §7.2、実装 ID `0x04`）。Keystore を使えるのはアプリのプロセスだけなので、アプリのプロセスが鍵エージェント（`ipc.md` §13.2）になる。

- アプリのプロセスは、金庫のプロセスに接続するときに鍵エージェントの中継（`KeyAgentAttach`）を開き、問いに答える（`zp-ffi` の `PlatformKeyStore`、Kotlin の `KeystoreKeyStore`）。
  - `Probe`: 画面ロックがなければ「使えない」。鍵があれば `0x04`。なければ、`create` なら作り、そうでなければ「使えない」。
  - `Sign`: 32 バイトのチャレンジだけを受け、`BiometricPrompt` で利用者を確かめてから HMAC を計算する。結果は Rust の側で、金庫のプロセスの鍵に封をして返す（`ipc.md` §13.3）。
- `BiometricPrompt` は前面にある画面（`FragmentActivity`）から出す。アプリの画面が前面になければ「失敗」と答える（自動入力・パスキーの要求は、OS が出させるアプリの画面の中で行う。§6）。
- 確認の画面の文言は「ZeroPass の金庫を開く」（題）と、何のためか（「ワンタイムコード」「パスキー」など、金庫のプロセスは理由を伝えないので、アプリの操作から決める）。
- 認証を取り消した・失敗したら `Cancelled`（金庫のプロセスは `USER_CANCELLED`）。180 秒で答えがなければ同じ。
- 鍵がどこにあるか（StrongBox、TEE、ソフトウェア）は、鍵を作ったときに記録に残す（`Log`）。ソフトウェアの Keystore しかない端末でも使うが、保護は OS のプロセス分離だけになる。

### 3.1 鍵が使えなくなったとき

- 画面ロックを外すと、Android が鍵を消す。その端末のハードウェアスロットは開けなくなり、`Unlock` は失敗する。鍵の受け取り（ADR-0011）は、ドメインを持っている端末のスロットを作り直さないので使えない。ほかの端末が鍵を持っていれば、この端末の金庫を消して参加し直すと戻る。
- アプリのデータを消す・アンインストールすると、鍵も消える（金庫ファイルも消える）。

## 4. 画面

Jetpack Compose の 1 つの画面（`MainActivity`）で、金庫の状態に応じて切り替える。金庫の操作はすべて `VaultClient`（金庫のプロセスへの要求）で、UI のスレッドの外で行う。

| 状態 | 画面 |
|---|---|
| 金庫がない | 「金庫を作る」（マスターパスワード 2 回、この端末の名前）、「ほかの端末の金庫に参加する」（QR コードを読み、端末名とこの端末のマスターパスワードを決め、BLE で参加。§5） |
| 施錠中 | マスターパスワードで解錠 |
| 解錠中 | 下のタブ: 「Vault」（ログインとノート）、「Codes」（ワンタイムコード）、「Passkeys」、「Devices」、「Settings」 |

- **Vault**: 検索（題名・利用者名・URL）、一覧、詳細（利用者名・パスワード・URL・メモ。パスワードは「Show」で 30 秒だけ表示）、追加・編集（パスワード生成器つき）・削除（確かめてから）。この端末の鍵で開けないものの件数を示す（ADR-0011）。
- **Codes**: 「Show one-time codes」で Keystore の確認（§3）のあとにコードと残り秒数を出し、操作がなければ 60 秒で隠して TOTP のドメインを施錠する。追加は `otpauth://` の QR コードを読むか、Base32 の秘密鍵を入れる（シードは入れるだけで表示しない）。ドメインがなければ理由と「この端末で作る」または「ほかの端末から受け取る」（ADR-0011）。
- **Passkeys**: 確認のあとに RP とアカウント名の一覧と削除（秘密鍵・クレデンシャル ID は出さない）。
- **Devices**: 端末の一覧（この端末・有効・失効、保持している変更の数）、「Sync now」（§5）、失効（確かめてから。全ドメインの解錠が要るので確認が出る）。
- **Settings**: 復旧キットの作成（復旧鍵を 1 回だけ表示）、マスターパスワードの変更、「Lock now」、この端末の金庫の削除（確かめてから。ほかの端末の金庫は変わらない）。
- **コピー**: クリップボードに入れるときに機密の印（`ClipDescription.EXTRA_IS_SENSITIVE`。Android 13 以上で、キーボードの候補や通知に出さない）を付け、30 秒後にまだ同じものなら消す。
- **画面の保護**: リリースビルドは `FLAG_SECURE`（スクリーンショット・最近使ったアプリのサムネイルに出さない）。デバッグビルドは自動テストのため付けない。
- **自動施錠**: 金庫のプロセスの自動施錠（パスワード 5 分、TOTP・パスキー 1 分）に従い、画面は 5 秒ごとの状態の問い合わせ（鍵を使わない）で施錠を映す。アプリが裏に回ったら、10 秒後に TOTP・パスキーのドメインを施錠する（Keystore の確認画面がアプリを覆っている間は除く）。
- **デバッグビルドの操作**: `adb shell am start -n <パッケージ>/.MainActivity -e do <操作> …`（`create`・`unlock`・`add`・`join`・`sync`・`codes`。`apps/android/README.md`）。リリースビルドでは無視する。

## 5. 同期

P6-04 で定める。

## 6. 自動入力とパスキー

P6-05 で定める。
