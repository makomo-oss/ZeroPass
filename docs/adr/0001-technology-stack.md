# ADR-0001: 技術スタック

- 状態: 採用
- 日付: 2026-11-11
- 関連: PLAN §1、脅威モデル §5.9

## 背景

ZeroPass は Windows / macOS / Linux / Android / iOS で同じ金庫・同期・パスキーのロジックを動かす必要がある。秘密を扱うため、メモリ安全性と秘密の確実な消去が必須で、依存ライブラリの監査可能性も重要である。

## 決定

1. **コアは Rust（stable、edition 2024）で書く。** ツールチェーンは `rust-toolchain.toml` で固定する。
2. **暗号プリミティブは監査済みの RustCrypto / dalek 実装のみ使う。**
   - AEAD: XChaCha20-Poly1305（`chacha20poly1305`）
   - パスワード KDF: Argon2id（`argon2`）
   - 鍵導出: HKDF-SHA256（`hkdf`、`sha2`）。SHA-1 は TOTP 互換のためだけに使う
   - 鍵交換・署名: X25519（`x25519-dalek`）、Ed25519（`ed25519-dalek`）
   - パスキー: P-256 ECDSA（`p256`）を必須、EdDSA に対応。RS256 は初期スコープ外
   - 乱数: OS の CSPRNG（`getrandom`）のみ
   - 秘密のメモリ: `zeroize`、`secrecy`、ページロック
3. **端末間チャネルは Noise Protocol（`snow`）。** TLS は使わない。
4. **ストレージは SQLite（`rusqlite`、bundled）＋アイテム単位のエンベロープ暗号。** SQLCipher は使わない。
5. **直列化は Protocol Buffers（`prost`）。** IPC と同期ワイヤで共通にする。
6. **UI**: デスクトップは Tauri 2 + Svelte + TypeScript、モバイルは Kotlin / Jetpack Compose と Swift / SwiftUI のネイティブシェル。コアとは UniFFI で接続する。
7. **ブラウザ拡張**は WXT + TypeScript（MV3）、デーモンとは Native Messaging ホスト（Rust）経由で通信する。
8. **AI 連携**は MCP サーバー（公式 Rust SDK `rmcp`、stdio）として提供する。
9. **品質基盤**: cargo-deny、cargo-audit、cargo-fuzz、proptest、criterion、GitHub Actions。OpenSSL は依存禁止。

## 検討した代替案

| 案 | 却下理由 |
|---|---|
| Go / C++ のコア | Go は GC により秘密の消去が保証しにくく、モバイル組込みも重い。C++ はメモリ安全性の担保コストが高い |
| AES-256-GCM | 96 bit ノンスのためランダムノンスの安全な使用回数に上限があり、AES-NI のない端末で定数時間性が落ちる |
| TLS（rustls）で端末間通信 | 証明書と CA が前提。サーバーレスの相互認証にはピン留めの自作が必要になり、Noise の方が素直 |
| SQLCipher | C 依存で全 OS のビルドが複雑。DB 全体暗号ではドメインごとに鍵を分けられず、同期層が暗号文のまま op を扱えない |
| Automerge 等の汎用 CRDT | 平文でのマージが前提。本用途はアイテム単位 LWW で十分（ADR-0003） |
| Electron | 起動が遅く重い。バックエンドが Node.js になりコアと別言語 |
| Flutter / React Native のモバイル UI | Autofill Service、Credential Manager、ASCredentialProviderExtension、生体認証付きキーストアはネイティブ実装が必須で、共通 UI の利点が小さい |
| JSON / CBOR の IPC | スキーマ進化とコード生成の面で Protobuf が優る（CBOR は WebAuthn 部分でのみ使う） |

## 結果

- 全プラットフォームで同一の暗号・同期実装を共有できる。
- Rust・Kotlin・Swift・TypeScript の 4 言語を扱う必要がある。プラットフォーム固有コードは薄く保ち、ロジックはできる限り Rust 側に置く。
- クレートのバージョンは導入時の最新安定版を採用し、`Cargo.lock` で固定する。
- 1Password 製 `passkey` クレート群の採用可否は P5-01 で別途 ADR にする。
