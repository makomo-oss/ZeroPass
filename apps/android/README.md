# ZeroPass Android 検証アプリ（P2-16）

近接同期 PoC の検証用アプリ。PC が表示したペアリングコード（QR）を読み取って金庫に参加し、Bluetooth LE だけで同期する。製品の UI ではなく、1 画面の最小構成である。

- 無線（スキャン、接続、バイト列の受け渡し）は Kotlin が受け持つ: `Ble.kt`（`docs/spec/ble.md` のセントラル側）
- ペアリング、Noise チャネル、同期、金庫は PC と同じ Rust コアが受け持つ: `crates/zp-ffi`（UniFFI）
- QR の読み取りは CameraX と ZXing で端末内で行う
- 同期は、同じ Wi-Fi に相手がいれば LAN（mDNS + TCP、`docs/spec/lan.md`）で行い、届かなかった相手とだけ BLE で行う。同じ相手と両方で同期することはない
- LAN での同期のために `INTERNET` 権限を持つ（Android には「ローカルネットワークだけ」の権限がなく、ソケットを開くだけで必要になる）。通信先をプライベート／リンクローカルアドレスに限り、ホップ数を 1 にする制限は Rust コア側で守る
- PoC の制限: ハードウェア鍵ストアに未対応のため、スマートフォン側で開けるのはパスワードのドメインだけ（TOTP とパスキーは暗号文のまま同期される）

## 必要なもの

- Android Studio（同梱の JDK を使う）、Android SDK（platform 36、build-tools）、NDK
- `rustup target add aarch64-linux-android` と `cargo install cargo-ndk`
- 環境変数 `ANDROID_HOME`、`ANDROID_NDK_HOME`、`JAVA_HOME`（Android Studio の `jbr` フォルダ）
- Android 8.0 以上の arm64 の実機（エミュレータは BLE を使えない）
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
adb shell am start -n io.github.makomooss.zeropass/.MainActivity -e do list -e password "…"
adb logcat -s ZeroPass:I      # アプリのログ
```

`do` には `join`、`sync`、`list`、`add`、`delete` を指定できる。
