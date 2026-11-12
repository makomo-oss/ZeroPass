# ZeroPass 開発計画（PLAN.md）

> 本ファイルが進捗の正本。§4 のチェックリストを 1 タスクずつ、§7 の運用ルールに従って消化する。

## 0. Context（背景と狙い）

- インプット: `zeropass-architecture-overview.md`（設計思想 4 原則 + 4 層分離モデル）。
- リポジトリ現状: `README.md` のみのグリーンフィールド（コード・ビルド設定なし）。
- 目的: 「運営サーバーゼロ／ネット非経由の近接同期／パスワードと TOTP の鍵分離／OS 非依存パスキー」を満たすパスワードマネージャーを、**最難関（暗号コアと近接同期）から先に PoC で潰す**順序で実装する。
- 本計画の前提（変更したい場合は着手前に指示）:
  - **対応順は Windows → Android → macOS / iOS → Linux**（開発機が Windows のため。iOS/macOS ビルドには Mac が必要）。
  - 個人〜少人数開発を想定し、1 タスク = 半日〜2 日程度の粒度に分解。
  - クレートのバージョンは着手時点の最新安定版を採用し `Cargo.lock` で固定する（本計画ではバージョンを決め打ちしない）。

## 1. 技術スタックと選定理由

| 領域 | 採用 | 理由 |
|---|---|---|
| コア言語 | **Rust**（stable, edition 2024） | メモリ安全・GC なし（秘密がヒープに残留しない）・`zeroize` による確実な消去。Win/macOS/Linux/Android/iOS すべてに同一コアを出せる |
| AEAD | **XChaCha20-Poly1305**（`chacha20poly1305`） | 192bit ノンスでランダムノンスが安全、AES-NI のない端末でも定数時間。RustCrypto 実装は第三者監査済み |
| パスワード KDF | **Argon2id**（`argon2`） | メモリハードで GPU/ASIC 耐性。OWASP 推奨 |
| 鍵導出 / MAC | **HKDF-SHA256**（`hkdf`）, `hmac`, `sha2`, `sha1`（TOTP 互換用のみ） | 鍵ドメイン分離のための標準構成 |
| 鍵交換 / 署名 | **X25519**（`x25519-dalek`）, **Ed25519**（`ed25519-dalek`） | 端末 ID 鍵・ペアリング用 |
| セキュアチャネル | **Noise Protocol**（`snow`）: ペアリング `XXpsk3` / 通常同期 `KK` | TLS と違い CA 不要＝サーバーレスに適合。QR の使い捨て秘密を PSK に混ぜ MITM を排除、ペア済み端末は静的鍵ピン留め |
| パスキー | **P-256 ECDSA (ES256)** 必須（`p256`）, EdDSA 対応, CBOR は `ciborium`。1Password 製 `passkey` クレート群の採用を P5-01 で評価 | WebAuthn の事実上必須アルゴリズム。RS256 は `rsa` クレートのタイミング脆弱性（Marvin）を踏まえ初期スコープ外 |
| 秘密のメモリ管理 | `zeroize`, `secrecy`, ページロック（`VirtualLock`/`mlock`） | スワップ・コアダンプへの漏出防止 |
| 乱数 | `getrandom`（OS CSPRNG のみ） | 独自 RNG を持たない |
| ストレージ | **SQLite**（`rusqlite`, bundled）+ **アイテム単位のエンベロープ暗号** | 同期層が暗号文のまま扱える（TOTP を解錠せず同期可能）。SQLCipher 依存を避け全 OS でビルドを単純化 |
| 同期モデル | **自前 oplog + バージョンベクタ + HLC による item 単位 LWW**（敗者バージョンは履歴保持） | Automerge 等の汎用 CRDT は平文マージ前提で過剰。小さく監査可能な実装を優先 |
| 直列化 | **Protocol Buffers**（`prost`）: IPC・同期ワイヤ共通 | スキーマ進化（フィールド追加）に強い |
| LAN 探索 / 通信 | **mDNS/DNS-SD**（`mdns-sd`）+ TCP + Noise、非同期は `tokio` | ルーター設定不要。TTL=1 / プライベート・リンクローカル宛限定でインターネット流出を構造的に遮断 |
| BLE | GATT（分割転送）。デスクトップ=ペリフェラル: Windows は WinRT `GattServiceProvider`（`windows` クレート）、Linux は `bluer`、macOS は CoreBluetooth（`objc2`）。モバイル=セントラル: Kotlin / Swift ネイティブ API | `btleplug` はセントラル専用のため不採用。iOS のバックグラウンド制約上「モバイルがセントラル」が最も安定 |
| FFI | **UniFFI** | Rust コアから Kotlin / Swift バインディングを自動生成 |
| デスクトップ UI | **Tauri 2 + Svelte + TypeScript** | Electron 比で起動が速く軽量、バックエンドが Rust でコアと同一言語 |
| モバイル UI | **Kotlin + Jetpack Compose** / **Swift + SwiftUI**（ネイティブシェル） | Autofill Service・Credential Manager（Android 14+）・ASCredentialProviderExtension（iOS 17+）・生体認証付きキーストアはネイティブ実装が必須 |
| ブラウザ拡張 | **WXT + TypeScript（MV3）** + Native Messaging ホスト（Rust） | Chrome/Edge/Firefox を単一コードで対応。拡張は秘密を保持せずデーモンに都度問い合わせ |
| AI 連携 | **MCP サーバー**（公式 Rust SDK `rmcp`, stdio） | エージェント連携の標準。ツール戻り値に秘密を含めない設計にしやすい |
| 生体認証 / HW 鍵 | Windows Hello + TPM（`windows`）、Secure Enclave + LocalAuthentication、Android Keystore(StrongBox) + BiometricPrompt | TOTP 鍵を「生体認証必須の HW 鍵」でのみラップするため |
| 品質 | `cargo-deny`, `cargo-audit`, `cargo-fuzz`, `proptest`, `criterion`, GitHub Actions | サプライチェーン検査とパーサのファジング |

## 2. 中核設計（PoC で検証する決定事項）

### 2.1 鍵階層（原則③ 要素分離）
```
マスターパスワード ─Argon2id→ KEK-P ─unwrap→ VK-P（パスワード金庫鍵）
HW鍵(生体認証必須) ──────────unwrap→ VK-T（TOTP 金庫鍵）※マスターパスワードからは導出不能
HW鍵(生体認証必須) ──────────unwrap→ VK-K（パスキー金庫鍵）
端末ごと: Ed25519 端末ID鍵 / X25519 Noise 静的鍵
アイテム: ランダム DEK を VK-* でラップ、AAD = item_id ‖ domain ‖ version
```
- VK-T / VK-K の他端末への配布は**ペアリング時のみ**、既存端末で生体認証 → Noise チャネル経由 → 受信側が自端末 HW 鍵で再ラップ。
- メモリ分離: PoC は別アリーナ（ページロック）、Phase 3 でドメインごとの**別プロセス**に昇格。

### 2.2 プロセス構成（4 層モデル）
| バイナリ | 層 | ネットワーク権限 |
|---|---|---|
| `zp-vaultd` | L1 金庫 | **なし**（OS サンドボックスで剥奪 + 依存ツリーにソケット系クレート禁止を CI で検査） |
| `zp-syncd` | L4 近接通信 | LAN/BLE のみ。扱うのは暗号文 op と Noise セッションのみ、金庫鍵は持たない |
| `zp-broker` | L3 Agent Broker | なし（stdio MCP + ローカル IPC） |
| `zp-nmh` | L2 拡張ブリッジ | なし（stdio ⇔ IPC） |
| デスクトップ / モバイル / 拡張 | L2 UI | なし |

IPC は Windows 名前付きパイプ / Unix ドメインソケット + 接続元プロセス検証。

### 2.3 同期プロトコル
- 各端末が `(device_id, seq)` で単調増加する暗号文 op を追記。接続時にバージョンベクタを交換し差分のみ送信。
- 競合は HLC による item 単位 LWW、負けた版は履歴として保持。削除は tombstone。
- 端末失効時は VK-* をローテーションし残存端末へ再配布。

### 2.4 リポジトリ構成
```
crates/  zp-crypto  zp-vault  zp-hwkey  zp-sync  zp-pairing  zp-transport  zp-passkey  zp-ipc  zp-ffi
bins/    zp-vaultd  zp-syncd  zp-broker  zp-nmh  zp-cli
apps/    desktop(Tauri)  extension(WXT)  android  ios
docs/    threat-model.md  adr/  spec/
```

## 3. フェーズ概要

| Phase | 内容 | 完了条件（Exit Criteria） |
|---|---|---|
| 0 | 基盤整備 | CI が緑、脅威モデル初版 |
| **1** | **暗号コア PoC** | CLI で金庫の作成・解錠・CRUD・TOTP 生成ができ、鍵分離テストとファジングが通る |
| **2** | **近接同期 PoC** | 2 端末が QR ペアリング → LAN と BLE の両方で差分同期し収束する |
| G | Go/No-Go ゲート | PoC 結果レビュー、仕様凍結 |
| 3 | Vault Core Daemon | サンドボックス下でネット不能を実証、生体認証結合 |
| 4 | デスクトップ UI + 拡張 | 実サイトで自動入力 |
| 5 | パスキーエンジン | webauthn.io で登録・認証、端末間同期 |
| 6 | モバイル | Android / iOS で自動入力・パスキー・同期 |
| 7 | Agent Broker | AI に秘密を渡さずログイン代行 |
| 8 | 堅牢化・リリース | 外部監査、署名付き配布 |

## 4. タスクチェックリスト

記法: `- [ ] ID 内容 — 完了条件（依存: ID）`。依存がすべて `[x]` のタスクから着手する。

### Phase 0: 基盤整備
- [x] **P0-00** `.gitignore`（§7.2 の内容）と `.gitattributes`（改行コード正規化 `* text=auto eol=lf`）を追加し、`.claude/PLAN.md` と合わせて最初の PR として push・マージ — `git status` がクリーン、GitHub の `main` に反映（依存: なし）
- [x] **P0-01** Cargo ワークスペースと §2.4 のディレクトリ骨格を作成、`rust-toolchain.toml`・`rustfmt`・`clippy`（`unsafe_code = forbid` を既定、例外クレートのみ明示許可）を設定 — `cargo build` / `cargo test` が通る（依存: P0-00）
- [x] **P0-02** GitHub Actions（Windows/Linux/macOS）で fmt・clippy・test・`cargo-deny`・`cargo-audit` を実行 — PR で自動実行され緑（依存: P0-01）
- [x] **P0-03** `docs/threat-model.md` 初版（資産・攻撃者・信頼境界・スコープ外。例: 解錠中の端末を完全掌握したマルウェアは防御範囲外、を明記） — レビュー可能な文書がある（依存: なし）
- [x] **P0-04** `docs/adr/` に §1・§2 の決定を ADR として記録（スタック、鍵階層、同期モデル、プロセス構成） — ADR 4 本（依存: P0-03）
- [x] **P0-05** `scripts/check-offline-deps.sh`（`cargo tree` ベース。cargo-deny の禁止リストはワークスペース全体に効き `zp-syncd` まで縛るため不採用）で `zp-crypto` / `zp-vault` / `zp-vaultd` の依存ツリーにネットワーク系クレート（`tokio` の net、`socket2`、`mio`、`reqwest` 等）が入ったら失敗する検査を追加 — 故意に依存を足すと CI が赤になる（依存: P0-02）

### Phase 1: 暗号コア PoC（最難関①）
- [x] **P1-01** `docs/spec/crypto.md`: 鍵階層、エンベロープ形式（バージョンバイト・ノンス・AAD）、Argon2id パラメータ方針、ドメイン分離ラベルを仕様化 — 仕様書（依存: P0-04）
- [x] **P1-02** `zp-crypto`: 秘密型（`SecretKey<Domain>` 型でドメインを型レベル区別、`Zeroize`/`ZeroizeOnDrop`、`Debug` 非表示、ページロック） — P/T/K の鍵を取り違えるコードがコンパイルエラーになる（依存: P0-01）
- [x] **P1-03** `zp-crypto`: XChaCha20-Poly1305 エンベロープ seal/open（AAD 束縛、形式バージョン付き） — 公式テストベクタ + 改ざん・AAD 不一致で失敗するテスト（依存: P1-01, P1-02）
- [x] **P1-04** `zp-crypto`: Argon2id による KEK-P 導出とパラメータ自動較正（目標 ~500ms、下限あり）、パラメータを金庫ヘッダに保存 — RFC 9106 ベクタ一致（依存: P1-02）
- [x] **P1-05** `zp-crypto`: 鍵ラップ／アンラップと HKDF ドメイン分離、VK-P/VK-T/VK-K 生成 — VK-P から VK-T を導出・復号できないことを示すテスト（依存: P1-03, P1-04）
- [x] **P1-06** `zp-crypto`: `HardwareKeyStore` トレイト（生体認証必須のラップ鍵の抽象）とテスト用ソフトウェア実装 — トレイト経由で VK-T をラップ／アンラップ（依存: P1-05）
- [x] **P1-07** `zp-vault`: データモデル（Login / TOTP / Passkey / Note、protobuf 定義）と SQLite スキーマ（平文は item_id・domain・HLC・バージョンのみ） — マイグレーション付きで DB 作成（依存: P1-01）
- [x] **P1-08** `zp-vault`: アイテム CRUD（DEK 生成 → VK ラップ → 保存、tombstone 削除、履歴保持） — DB ファイルを `strings` 相当で走査しても平文が出ないテスト（依存: P1-05, P1-07）
- [x] **P1-09** `zp-vault`: 金庫ライフサイクル（作成・解錠・施錠・マスターパスワード変更・自動ロック）。ドメイン別に独立した解錠状態 — P を解錠しても T/K がロックのままである統合テスト（依存: P1-06, P1-08）
- [x] **P1-10** `zp-vault`: TOTP エンジン（RFC 6238、SHA1/256/512、`otpauth://` URI パース） — RFC 6238 付録 B ベクタ一致（依存: P1-09）
- [x] **P1-11** `zp-cli`: `init / unlock / add / get / list / totp / lock` — 手動 E2E デモが通る（依存: P1-09, P1-10）
- [x] **P1-12** ファジング（エンベロープ open、protobuf デコード、otpauth パース）と proptest（seal→open 往復） — 各ターゲット 10 分以上クラッシュなし（依存: P1-08, P1-10）
- [x] **P1-13** Windows 実装: `HardwareKeyStore` を Windows Hello（`KeyCredentialManager`）+ TPM で実装 — 実機で指紋／顔／PIN 承認なしに VK-T が開かない（依存: P1-06）
- [x] **P1-14** リカバリーキット: 紙出力用の復旧鍵（VK-* を復旧鍵でラップした暗号化エクスポート）と復元 — 新規環境で復元できる（依存: P1-09）
- [x] **P1-15** `criterion` ベンチ（解錠時間、1 万件の一覧・検索） — 解錠 <1s、一覧 <100ms を計測記録（依存: P1-11）

### Phase 2: 近接同期 PoC（最難関②）
- [x] **P2-01** `docs/spec/sync.md`: op 形式、バージョンベクタ交換、HLC、競合解決、tombstone GC、端末失効を仕様化 — 仕様書（依存: P1-01）
- [x] **P2-02** `docs/spec/pairing.md`: QR ペイロード（静的公開鍵指紋 + 32byte 使い捨て秘密 + 接続ヒント、有効期限 60s）、Noise `XXpsk3`、VK 配布手順を仕様化 — 仕様書（依存: P1-01）
- [x] **P2-03** `zp-sync`: HLC とバージョンベクタ — proptest で単調性・比較則を検証（依存: P0-01）
- [x] **P2-04** `zp-sync`: 暗号文 oplog（追記、`(device_id, seq)` 索引、差分抽出）を `zp-vault` に統合 — CRUD が op を生成する（依存: P1-08, P2-01, P2-03）
- [x] **P2-05** `zp-sync`: マージ（item 単位 LWW、敗者版の履歴化、tombstone）。**トランスポート非依存の純粋ロジック** — proptest: 任意順序・重複配送でも N 端末が同一状態に収束（依存: P2-04）
- [x] **P2-06** `zp-sync`: 同期セッション状態機械（ベクタ交換 → 差分送受 → 完了通知、中断再開、フレーム上限）を入出力なしの状態機械として実装（ADR-0005） — インメモリパイプで 2 金庫が収束（依存: P2-05）
- [x] **P2-07** `zp-pairing`: 端末 ID 鍵・Noise 静的鍵の生成と保管、ペア済み端末レジストリ — 再起動後も保持（依存: P1-05）
- [x] **P2-08** `zp-pairing`: Noise チャネル（`snow`）— ペアリング `XXpsk3`、通常同期 `IK`（ADR-0005）、再鍵、フレーミング — 誤 PSK・未知の静的鍵で握手失敗するテスト（依存: P2-02, P2-07）
- [x] **P2-09** `zp-pairing`: QR 生成／パースと、ペアリング完了時の VK-P/VK-T/VK-K 配布（送信側は生体認証必須、受信側は HW 鍵で再ラップ） — インメモリで新端末が全ドメインを解錠可能に（依存: P1-06, P2-08）
- [x] **P2-10** `zp-transport`: `Transport` トレイト（探索 + バイトストリーム）とループバック実装 — P2-06 がトレイト越しに動く（依存: P2-06）
- [x] **P2-11** LAN トランスポート: mDNS 広告／探索（ペア鍵から導出する回転式匿名 ID で端末特定を防止）+ TCP + Noise — 同一 Wi-Fi の PC 2 台が自動発見（依存: P2-08, P2-10）
  - 2026-11-13 確認: 同じ Wi-Fi 上の Windows PC（`zp-syncd`）と Android タブレット（検証アプリ）が mDNS で互いを見つけて同期した。2 台目は PC ではなくタブレットである。同じ PC 上の 2 インスタンスでの確認は `cargo test -p zp-transport -- --ignored`。
- [ ] **P2-12** LAN のインターネット遮断: プライベート／リンクローカル IF のみに bind、TTL/Hop Limit=1、非ローカル宛先を拒否 — パケットキャプチャで LAN 外宛が 0 件（依存: P2-11）
  - 実装済み（ローカルアドレスへのみ bind・接続・受け入れ、全ソケットで TTL=1。仕様は `docs/spec/lan.md`）。ソケット単位の検査は自動テストで確認済み。**完了条件のパケットキャプチャによる確認だけが未了**: 採取には管理者権限が必要。管理者の PowerShell で `scripts/check-lan-capture.ps1` を実行し、採取中に別の端末から同期する（手順は `docs/spec/lan.md` §6）。確認できたらこの行を削除して `[x]` にする。
- [x] **P2-13** `zp-syncd` 最小版 + `zp-cli pair / sync`: PC 2 台で QR 文字列ペアリング → LAN 自動同期 — 片方の変更が数秒で他方に反映（依存: P2-09, P2-11）
  - 2026-11-13 確認: PC で追加したログインが、同じ Wi-Fi 上のタブレットの同期操作 1 回（約 3 秒）で届き、逆方向も届いた（PC 側は `zp-syncd`）。**2 台の間での LAN 経由のペアリングは未確認**（タブレットのペアリングは BLE で行った。LAN 経由のペアリングは同じ PC 上の 2 つの金庫ファイルで確認済み: `cargo test -p zp-cli --test e2e -- --ignored`）。PC 2 台で試す場合の手順:
    1. 両方の PC でビルドする: `cargo build --release -p zp-cli -p zp-syncd`
    2. PC-A: `zp-cli --vault a.zpvault init` → `zp-cli --vault a.zpvault pair`（表示されたコードを控える。60 秒有効）
    3. PC-B: `zp-cli --vault b.zpvault join`（新しいマスターパスワードを決め、コードを入力）→ PC-A で端末名を確認して `y`
    4. 両方で `zp-syncd --vault <ファイル>` を起動したままにする
    5. PC-A で `zp-cli --vault a.zpvault add login --title test` → 数秒後に PC-B の `zp-cli --vault b.zpvault list` に出ること、逆方向も同様であることを確認する
    6. Windows ファイアウォールの確認が出たら「プライベート ネットワーク」のみ許可する
- [x] **P2-14** BLE 仕様: GATT サービス／キャラクタリスティック、MTU 交渉、分割・再構成、フロー制御、回転式広告 ID — `docs/spec/ble.md`（依存: P2-10）
- [x] **P2-15** BLE ペリフェラル（Windows, WinRT `GattServiceProvider`）を `Transport` 実装 — 汎用 BLE スキャナアプリから接続・読み書きできる（依存: P2-14）
  - 2026-11-13 確認: スマートフォンの BLE スキャナアプリから接続し、Tx の購読でリンクが開き、Rx に書いた 4 バイトが PC 側に届いた（`cargo run -p zp-transport --example ble_echo`）。
- [x] **P2-16** Android 検証アプリ（最小 Kotlin + UniFFI で `zp-sync`/`zp-pairing` を呼ぶ、BLE セントラル、CameraX で QR 読取） — Android ⇔ Windows が BLE だけで同期（Wi-Fi オフ）（依存: P2-13, P2-15）
  - 2026-11-13 確認（Fire HD 10、Fire OS 7 = Android 9、Wi-Fi オフ）: BLE だけでペアリング（スキャン 4 秒を含め約 8.5 秒、MTU 517）と双方向の同期（1 回約 6.4 秒）が完了した。コードは adb 経由でアプリに渡して確認した。**カメラでの QR 読み取りは実機で未確認**（手順は `apps/android/README.md`）。
  - 実装: デスクトップ側（`zp-cli pair` / `sync` と `zp-syncd` が LAN と BLE の両方で待ち受け、`pair` は QR コードを表示）、`crates/zp-ffi`（UniFFI）、`apps/android`（Kotlin の BLE セントラル、CameraX + ZXing）。
  - PoC の制限: スマートフォン側はハードウェア鍵ストア未対応（P6-02）のため、開けるのはパスワードのドメインだけ。
- [x] **P2-17** トランスポート選択と切替（LAN 優先、BLE フォールバック、同時接続の重複排除） — Wi-Fi の入切で同期が継続（依存: P2-16）
  - 2026-11-13 確認（Windows PC の `zp-syncd` と Android 9 タブレット）: タブレットの Wi-Fi をオン → オフ → オンと切り替えながら同期を 3 回行い、LAN（約 3 秒）→ BLE（約 6.7 秒）→ LAN の順に経路が切り替わって、毎回変更が届いた。`zp-syncd` は動かしたまま。
  - 実装: デスクトップは LAN と BLE の両方で待ち受け、LAN はアドレスの変化に合わせて自動で開き直す（`ResilientLan`）。モバイルは LAN で見つけた相手と同期し、残った相手とだけ BLE で同期する（同じ相手と両方では同期しない）。モバイルのペアリングは BLE のみ。
- [ ] **P2-18** 計測と障害試験: ペアリング所要時間（目標 ~3s）、BLE スループット、切断・電源断・時計ずれ注入 — 結果を `docs/poc-report.md` に記録（依存: P2-17）
- [x] **P2-19** 端末失効: レジストリから削除 → VK-* ローテーション → 残存端末へ再配布 — 失効端末が以後の op を復号できないテスト（依存: P2-13）

### Gate G: Go/No-Go
- [ ] **G-01** PoC レポートのレビュー、未達項目の対処方針決定、`crypto.md`/`sync.md`/`pairing.md`/`ble.md` をバージョン 1 として凍結 — ユーザー承認（依存: P1-12, P1-15, P2-18, P2-19）

### Phase 3: Vault Core Daemon（第 1 層）
- [ ] **P3-01** `zp-ipc`: protobuf API 定義（解錠・CRUD・TOTP・同期 op 受け渡し・承認要求）と名前付きパイプ／UDS 実装、接続元プロセス検証（PID → 実行ファイル署名／パス） — 未許可プロセスが拒否される（依存: G-01）
- [ ] **P3-02** `zp-vaultd`: デーモン化（単一インスタンス、自動ロック、セッション管理）し CLI を IPC クライアントへ移行（依存: P3-01）
- [ ] **P3-03** Windows サンドボックス: ネットワーク capability なしの AppContainer / 制限トークンで起動 — デーモン内からのソケット作成が OS に拒否される実証テスト（依存: P3-02）
- [ ] **P3-04** ドメイン別プロセス分離: TOTP / パスキー用ワーカーを別プロセス化し、VK-T/VK-K はそのプロセスのみが保持 — P 側プロセスのメモリダンプに T の鍵素材がない（依存: P3-02）
- [ ] **P3-05** `zp-syncd` を本番構成へ: vaultd とは IPC で暗号文 op のみ授受 — syncd のメモリに金庫鍵が存在しない（依存: P3-02, P2-17）
- [ ] **P3-06** プロセス硬化（コアダンプ無効、デバッガ接続拒否、DLL 検索パス固定、クリップボード自動消去 API） — チェックリスト消化（依存: P3-03）
- [ ] **P3-07** インストーラとサービス登録（ログオン時起動、コード署名の準備） — クリーン環境でインストール → 起動（依存: P3-05）

### Phase 4: デスクトップ UI + ブラウザ拡張（第 2 層）
- [ ] **P4-01** Tauri 2 アプリ骨格と IPC クライアント結合、解錠画面 — 起動 <500ms（依存: P3-02）
- [ ] **P4-02** 金庫 UI（一覧・検索・詳細・編集・パスワード生成器・TOTP 表示は生体認証後のみ）（依存: P4-01, P1-13）
- [ ] **P4-03** ペアリング UI（QR 表示、端末一覧、失効）と同期状態表示（依存: P4-01, P3-05）
- [ ] **P4-04** `zp-nmh` Native Messaging ホストと拡張 ID 許可リスト（依存: P3-01）
- [ ] **P4-05** WXT 拡張: フォーム検出、オリジン厳密一致（eTLD+1 + フィッシング対策）、インライン候補、入力 — 主要 20 サイトで動作確認（依存: P4-04）
- [ ] **P4-06** 拡張: 保存／更新提案、TOTP 自動入力（デーモン側で生体認証）（依存: P4-05）
- [ ] **P4-07** インポート（Bitwarden / 1Password / Chrome CSV）と暗号化エクスポート（依存: P4-02）

### Phase 5: パスキーエンジン（原則④）
- [ ] **P5-01** `passkey` クレート群の評価（ライセンス・保守状況・CredentialStore 差し替え可否）→ 採用 or 自作を ADR 化（依存: G-01）
- [ ] **P5-02** `zp-passkey`: クレデンシャル生成・保管（VK-K ドメイン、秘密鍵は `zp-vaultd` のパスキーワーカー外に出さない）（依存: P5-01, P3-04）
- [ ] **P5-03** `zp-passkey`: `makeCredential` / `getAssertion`（authenticatorData、attestation `none`、UV=生体認証、signCount 方針） — WebAuthn 適合テストベクタ（依存: P5-02）
- [ ] **P5-04** 拡張: `navigator.credentials.create/get` の仲介とデーモン連携 — webauthn.io で登録・認証（依存: P5-03, P4-05）
- [ ] **P5-05** パスキーの端末間同期の検証（PC で登録 → Android で認証は P6 で確認、ここでは PC 2 台） （依存: P5-04）

### Phase 6: モバイル
- [ ] **P6-01** `zp-ffi`: UniFFI で公開 API を確定（モバイルは単一プロセス内でコアを動かし、Android は `isolatedProcess` サービスに金庫を分離）（依存: G-01）
- [ ] **P6-02** Android: Keystore(StrongBox) + BiometricPrompt による `HardwareKeyStore`（依存: P6-01）
- [ ] **P6-03** Android: Compose UI（解錠・一覧・詳細・QR ペアリング）（依存: P6-02）
- [ ] **P6-04** Android: フォアグラウンド／バックグラウンド同期（BLE セントラル + LAN、電池影響を計測）（依存: P6-03, P2-17）
- [ ] **P6-05** Android: Autofill Service と Credential Manager プロバイダ（パスワード + パスキー）（依存: P6-03, P5-03）
- [ ] **P6-06** iOS: Xcode プロジェクト、Secure Enclave + LocalAuthentication の `HardwareKeyStore`（**要 Mac**）（依存: P6-01）
- [ ] **P6-07** iOS: SwiftUI UI、CoreBluetooth セントラル（バックグラウンド復元）、Network.framework + Bonjour（ローカルネットワーク権限）（依存: P6-06）
- [ ] **P6-08** iOS: ASCredentialProviderExtension（パスワード + パスキー、App Group で金庫共有）（依存: P6-07, P5-03）
- [ ] **P6-09** macOS: デスクトップアプリ移植（App Sandbox でネット権限なしの vaultd、CoreBluetooth ペリフェラル、Touch ID）（依存: P6-06, P4-03）
- [ ] **P6-10** Linux: 移植（seccomp/Landlock、`bluer`、生体認証は TPM/fprintd のベストエフォート）（依存: P4-03）

### Phase 7: Agent Broker（第 3 層）
- [ ] **P7-01** `docs/spec/broker.md`: 権限モデル（オリジン束縛・単回・短寿命のログイン許可、承認 UI 文言、監査ログ）と、AI に返してよい情報の範囲を仕様化（依存: G-01）
- [ ] **P7-02** `zp-broker`: MCP サーバー（`list_logins` はメタデータのみ、`request_login`）（依存: P7-01, P3-01）
- [ ] **P7-03** 承認フロー: 要求 → 手元端末で生体認証 → 一時許可発行（ペア済みスマホでの承認にも対応）（依存: P7-02, P4-02）
- [ ] **P7-04** ログイン代行: 拡張経由で対象タブへ直接入力し、MCP 応答・ログ・DOM 読み取り経路に秘密が出ないことを検証（依存: P7-03, P4-05）
- [ ] **P7-05** 監査ログ UI と許可の即時取り消し、プロンプトインジェクション想定の悪用テスト（依存: P7-04）

### Phase 8: 堅牢化・リリース
- [ ] **P8-01** 脅威モデル改訂と全仕様の最終整合（依存: P5-05, P6-05, P7-05）
- [ ] **P8-02** 外部セキュリティ監査（暗号設計 + 実装）の実施と指摘対応（依存: P8-01）
- [ ] **P8-03** 再現可能ビルド、コード署名、SBOM、署名付きアップデート配布方式の決定（「運営サーバーゼロ」と更新配布の整合を ADR 化）（依存: P8-01）
- [ ] **P8-04** ドキュメント（ユーザーガイド、復旧手順、セキュリティホワイトペーパー）（依存: P8-01）
- [ ] **P8-05** ベータ配布とフィードバック対応（依存: P8-02, P8-03, P8-04）

## 5. 主要リスクと対策

| リスク | 対策 |
|---|---|
| BLE のペリフェラル実装が OS ごとに別物、iOS のバックグラウンド制約 | P2-15/16 で最初に実機検証。不可なら「BLE は発見のみ、転送は Wi-Fi Direct / ローカル Wi-Fi」に縮退（G-01 で判断） |
| 全端末紛失 = データ消失（サーバーなしの宿命） | P1-14 リカバリーキットを初期から必須導線にする |
| Windows でデーモンのネット権限剥奪が想定どおり効かない | P3-03 で実証。不可なら WFP ルール + 依存検査（P0-05）の二重化 |
| 自作同期ロジックの収束バグ | P2-05 を純粋ロジックに保ち proptest で徹底検証 |
| 自作暗号プロトコルの設計ミス | プリミティブは監査済みクレートのみ、構成は Noise 等の標準に限定、P8-02 で外部監査 |
| 「あらゆるパスキー」の範囲（RS256、デバイス束縛型） | 初期は ES256/EdDSA の同期可能パスキーに限定し、範囲を ADR で明示 |

## 6. 検証方法（End-to-End）

- **Phase 1**: `cargo test --workspace`、`cargo fuzz run <target>`、`zp-cli` で init → add → lock → unlock → get → totp を手動実行。DB ファイルのバイナリ走査で平文が出ないこと。
- **Phase 2**: PC 2 台（または PC + Android）で `zp-cli pair` → 片方で追加・編集・削除 → 他方に反映。Wi-Fi オフで BLE のみ同期。Wireshark で LAN 外宛パケット 0 件。
- **Phase 3 以降**: サンドボックス下でのソケット作成失敗テスト、webauthn.io でのパスキー登録・認証、MCP クライアントから `request_login` を呼び応答に秘密が含まれないことの確認。
- 各フェーズの Exit Criteria（§3）を満たしたら次フェーズへ。

## 7. 運用ルール（自律実行用）

### 7.1 タスクの進め方
1. 依存がすべて完了済みで最も ID の若いタスクを 1 つ選ぶ。
2. 実装 → テスト → 完了条件を確認 → `.claude/PLAN.md` の該当行を `[x]` に更新 → コミット → push。
3. 仕様変更が必要になったら、先に `docs/spec/` と ADR を更新してから実装する。
4. 完了条件を満たせない場合は `[ ]` のまま理由をタスク直下に追記し、ユーザーに判断を仰ぐ。

### 7.2 Git / GitHub 運用（コードベースと履歴を綺麗に保つ）
- **ブランチ**: `main` へ直接コミットしない。1 タスク = 1 トピックブランチ（例: `feat/p1-03-envelope`, `docs/p0-03-threat-model`）。
- **コミット**: Conventional Commits（`feat(crypto): ...` / `fix` / `docs` / `test` / `chore` / `ci`）+ 本文にタスク ID（例: `Refs: P1-03`）。1 コミット = 1 つの論理的変更。WIP・「fix typo の連打」は push 前に整理する（push 済みブランチの履歴書き換えはトピックブランチ内に限る。`main` への force push は禁止）。
- **push と統合**: タスク完了ごとにブランチを push → PR 作成（`gh`）→ CI 緑を確認 → **squash merge** で `main` に 1 タスク 1 コミットとして取り込み → ブランチ削除。`main` は常にビルド・テストが通る状態を保つ。
- **コミット前チェック**: `cargo fmt --check` / `cargo clippy -- -D warnings` / `cargo test`（該当する場合は拡張・UI の lint とテスト）。`git status` と `git diff --staged` で意図しないファイルが含まれていないことを確認し、`git add -A` の無差別使用は避ける。
- **`.gitignore`**（P0-00 で整備、スタック追加時に都度更新）:
  - Rust: `target/`, `**/*.rs.bk`（`Cargo.lock` はコミットする）
  - Node / 拡張 / Tauri: `node_modules/`, `dist/`, `.output/`, `.wxt/`, `apps/desktop/src-tauri/target/`, `apps/desktop/src-tauri/gen/`
  - Android / iOS: `.gradle/`, `build/`, `local.properties`, `*.keystore`, `*.jks`, `DerivedData/`, `xcuserdata/`, `Pods/`
  - 秘密・ローカルデータ: `.env*`, `*.pem`, `*.key`, `*.p12`, `*.db`, `*.sqlite*`, `*.zpvault`, ファジングの `corpus/` `artifacts/`
  - エディタ / OS / ツール: `.vscode/`（共有設定を除く）, `.idea/`, `.DS_Store`, `Thumbs.db`, `.claude/settings.local.json`, `.claude/worktrees/`
  - `.claude/PLAN.md` は**コミット対象**（進捗の正本）。
- **コミットしてはいけないもの**: 鍵・証明書・実データの金庫ファイル・テスト用以外の秘密、生成物、巨大バイナリ。テストベクタは `tests/vectors/` に小さなテキストで置く。
- コミットメッセージ・PR 本文に帰属表記（Co-Authored-By 等）は付けない。
