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

P6-02 で定める。

## 4. 画面

P6-03 で定める。

## 5. 同期

P6-04 で定める。

## 6. 自動入力とパスキー

P6-05 で定める。
