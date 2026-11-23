# ZeroPass Android アプリ

近接同期 PoC（P2-16）の検証アプリを、Phase 6 で製品のアプリにしていく途中のもの。画面は Jetpack Compose（`ui/`、`docs/spec/android.md` §4）: 金庫の作成、QR コードによる参加（BLE）、解錠、ログインとノートの一覧・検索・詳細・編集・パスワード生成器、ワンタイムコード、パスキー、端末と同期、復旧キット・マスターパスワードの変更。構成は `docs/spec/android.md`。

- **金庫は分離プロセス**（`VaultService`、`isolatedProcess`、プロセス名 `:vault`）で動く（ADR-0012）。権限・ファイル・ネットワークがなく、デスクトップの金庫デーモンと同じ Rust の処理が金庫をメモリ上に持つ。アプリのプロセスは `IVaultService.connect` でソケットの組を渡して要求を送り、金庫ファイル（`files/vault.zpvault`）を保管役として書く（`Vault.kt`、`VaultBinding.kt`）。ペアリングと同期のネットワークはアプリのプロセスで動く
- 無線（スキャン、接続、バイト列の受け渡し）は Kotlin が受け持つ: `Ble.kt`（`docs/spec/ble.md` のセントラル側）
- ペアリング、Noise チャネル、同期、金庫は PC と同じ Rust コアが受け持つ: `crates/zp-ffi`（UniFFI）
- QR の読み取りは CameraX と ZXing で端末内で行う
- 同期は、同じ Wi-Fi に相手がいれば LAN（mDNS + TCP、`docs/spec/lan.md`）で行い、届かなかった相手とだけ BLE で行う。同じ相手と両方で同期することはない
- LAN での同期のために `INTERNET` 権限を持つ（Android には「ローカルネットワークだけ」の権限がなく、ソケットを開くだけで必要になる）。通信先をプライベート／リンクローカルアドレスに限り、ホップ数を 1 にする制限は Rust コア側で守る
- 制限（P6-02 まで）: ハードウェア鍵ストアに未対応のため、スマートフォン側で開けるのはパスワードのドメインだけ（TOTP とパスキーは暗号文のまま同期される）

## 必要なもの

- Android Studio（同梱の JDK を使う）、Android SDK（platform 37.2。Compose のライブラリが求める。対象は 36 のまま。build-tools）、NDK
- `rustup target add aarch64-linux-android x86_64-linux-android` と `cargo install cargo-ndk`
- 環境変数 `ANDROID_HOME`、`ANDROID_NDK_HOME`、`JAVA_HOME`（Android Studio の `jbr` フォルダ）
- Android 8.0 以上の arm64 の実機。エミュレータ（x86_64）でも動くが BLE は使えない（金庫の作成・解錠・一覧は試せる）
- Android 11 以前の実機では、端末の「位置情報」をオンにしておく（オフだと OS が BLE のスキャン結果を返さない。アプリは位置を読まない）

## ビルド

```sh
# 1. Rust コアを Android 向けにビルドし、Kotlin バインディングを生成する（Git Bash）
bash apps/android/build-core.sh

# 2. APK を作る
cd apps/android
./gradlew assembleDebug        # app/build/outputs/apk/debug/app-debug.apk

# 3. USB デバッグを有効にした実機へ入れる
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

手順 1 の生成物（`app/src/main/jniLibs/`、`app/src/main/java/uniffi/`）はコミットしない。`crates/` 以下を変更したら手順 1 からやり直す。

## 確認手順（Wi-Fi を切った状態で）

1. PC とスマートフォンの Bluetooth をオンにし、スマートフォンの Wi-Fi をオフにする
2. PC: `zp-cli --vault a.zpvault init`（未作成の場合）→ ログインを 1 件追加 → `zp-cli --vault a.zpvault pair`（QR コードが表示される。60 秒有効）
3. スマートフォン: アプリを開き、権限を許可し、名前とこの端末用のマスターパスワード（12 文字以上）を入れて「Scan a pairing code and join」→ QR を写す
4. PC: 表示された端末名を確かめて `y` → スマートフォンのログに `joined vault …` と `first sync: … received 1` が出る
5. スマートフォン: 「Unlock and list logins」で PC のログインが見えること
6. スマートフォン: ログインを 1 件追加する
7. PC: `zp-syncd --vault a.zpvault` を起動したままにする
8. スマートフォン: 「Sync」→ `Bluetooth: synced with "…": sent 1, received 0`（Wi-Fi をオンにして同じネットワークにいれば `Wi-Fi: synced with …` になる）
9. PC: `zp-cli --vault a.zpvault list` にスマートフォンで追加したログインが出ること。逆方向（PC で追加 → スマートフォンで Sync → 一覧）も確認する

## adb からの操作（デバッグビルドのみ）

手を使わずに無線の経路を試すため、デバッグビルドは起動時の引数で操作できる。リリースビルドでは無視される。

```sh
adb shell am start -n io.github.makomooss.zeropass/.MainActivity \
    -e do join -e code "ZP1:…" -e password "<この端末のマスターパスワード>" -e name "<端末名>"
adb shell am start -n io.github.makomooss.zeropass/.MainActivity -e do sync
adb shell am start -n io.github.makomooss.zeropass/.MainActivity -e do unlock -e password "…"
adb logcat -s ZeroPass:I      # アプリのログ
```

`do` には `create`（この端末で金庫を作る。`password`、`name`）、`join`、`unlock`、`lock`、`sync`、`codes`（ワンタイムコードを表示。確認画面が出る）、`add-code`（`uri` に `otpauth://`）、`tab`（`vault`・`codes`・`passkeys`・`devices`・`settings`）を指定できる。デバッグビルドでは、画面の部品のテストタグがリソース ID になる（`uiautomator dump` で探してタップできる）。`adb shell` は引数を空白で分けるので、パスワードに空白を入れない。

背面の同期（WorkManager の仕事、`docs/spec/android.md` §5）は、デバッグビルドなら `adb shell am broadcast -n io.github.makomooss.zeropass/.DebugSyncReceiver` で 1 回起こせる（電池の計測に使う）。

金庫のプロセスが分離されていることは、次で確かめられる（`u0_i` で始まる利用者で動き、ネットワークの権限のグループ 3003 を持たない）。

```sh
adb shell ps -A -o USER,PID,NAME | grep zeropass
adb shell cat /proc/<金庫のプロセスの PID>/status | grep Groups
```
