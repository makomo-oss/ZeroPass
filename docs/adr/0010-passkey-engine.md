# ADR-0010: パスキーエンジンは `passkey` クレート群を使わず、監査済み暗号プリミティブの上に `zp-passkey` として自作する

- 状態: 採用
- 日付: 2026-11-19
- 関連: [ADR-0001](0001-technology-stack.md)、[ADR-0004](0004-process-architecture.md)、[ADR-0007](0007-domain-processes-and-key-agent.md)、脅威モデル §5.4（G7・G8）、PLAN §5、タスク P5-01〜P5-05、`docs/spec/passkey.md`

## 背景

ADR-0001 で、1Password 製の `passkey` クレート群（`1Password/passkey-rs`：`passkey-authenticator`・`passkey-types`・`passkey-crypto`・`passkey-client`）の採用可否は P5-01 で評価して ADR にすると定めていた。また PLAN §5 と脅威モデル §5.4 は、初期スコープのパスキーの範囲（ES256 / EdDSA の同期可能パスキー、RS256 やデバイス束縛型は初期スコープ外）と `signCount` の方針（0 固定）を ADR に明記することを求めている。

着手時点（2026-11-19）で `passkey` クレート群を評価した結果:

- **ライセンス**: `MIT OR Apache-2.0`（`deny.toml` の許可リストに適合し、GPL-3.0-only とも互換）。
- **保守状況**: 1Password により 2025〜2026 年も継続的に保守されており、`passkey-authenticator` 0.6.0・`passkey-client` 0.5.0・`passkey-crypto` 0.1 等が公開されている。ただし `0.x` で、0.5 → 0.6 で `passkey-crypto` の分離や `Authenticator::new` の破壊的変更が入るなど、API はなお変動している。
- **`CredentialStore` の差し替え可否**: `passkey-authenticator::CredentialStore` トレイトで保管先を差し替えられる。ただし ZeroPass の設計と次の点で噛み合わない:
  1. **非同期ランタイムの要求**: `CredentialStore`・`UserValidationMethod`・`Authenticator` の操作は `async` 前提である。`zp-vaultd` は現在 `tokio` や非同期ランタイムを一切持たない純粋な同期スレッドモデルで動いており（オフライン依存の監査対象）、非同期実行器を持ち込む必要がある。
  2. **秘密鍵の表現とメモリ消去**: `passkey-types::Passkey` は秘密鍵を `coset::CoseKey`（内部は `Vec<(Label, ciborium::Value)>`）で保持する。`coset::CoseKey` / `ciborium::Value` は `Zeroize` / `ZeroizeOnDrop` を実装しておらず、ZeroPass が全秘密型に課している「Drop 時の確実なメモリ消去・`Debug` 非表示」と、既存の `zp_vault::model::PasskeyCredential`（PKCS #8 DER + `ZeroizeOnDrop`）との間で不要な形式変換と秘密バイトのコピーが生じる。
  3. **依存ツリーの重複と肥大化**: `passkey-authenticator` / `passkey-types` / `passkey-crypto` / `coset` に加え、`passkey-client` を使うと `public-suffix`（既存の `zp-origin` の `psl` と重複）やオプションの `reqwest` まで抱える。また ZeroPass は `sha2 0.11`・`ed25519-dalek 3.0`・`getrandom 0.4` の世代に揃えており、`passkey-crypto` 経由で旧世代の暗号クレートが重複するおそれがある（`aws-lc-rs` バックエンドは C 依存であり ADR-0001 の pure-Rust 方針に反する）。
  4. **モバイル OS プロバイダ（Phase 6）との接点**: Android Credential Manager や iOS `ASCredentialProviderExtension` は `clientDataJSON` ではなく **`clientDataHash`（32 バイト）** と `rpId` を直接渡す。CTAP2 全体の状態機械を丸ごと抱えるより、`clientDataHash` を直接受け取る小さな WebAuthn 認証器コアの方が、デスクトップ拡張（Phase 5）とモバイル（Phase 6）の両方に素直につながる。

## 決定

### 1. `passkey` クレート群は採用せず、`crates/zp-passkey` を自作する

暗号プリミティブ自体は一切自作せず、監査済みの純粋 Rust クレートだけを使う:

- **ES256（COSE alg `-7`）**: `p256`（RustCrypto、ECDSA + PKCS #8 + `zeroize`）
- **EdDSA（COSE alg `-8`）**: `ed25519-dalek`（既存、`zeroize` + `pkcs8`）
- **ハッシュ・乱数**: `sha2`・`getrandom`（既存）
- **CBOR**: `ciborium`（Apache-2.0、確定的な小規模 CBOR エンコード／デコードに限定）
- **オリジン / RP ID 検証**: `zp-origin`（既存、組み込み PSL）

`zp-passkey` は `scripts/check-offline-deps.sh` の検査対象に加え、ネットワーク系クレートが入らないことを CI で保証する。同期関数のみで実装し、`zp-vaultd` に非同期ランタイムを入れない。

### 2. 初期スコープ（対応するパスキーの範囲）

| 項目 | 決定 | 理由 |
|---|---|---|
| 署名アルゴリズム | **ES256（`-7`）必須、EdDSA（`-8`）対応** | WebAuthn の事実上必須アルゴリズムと現代的楕円曲線。RS256（`-257`）は `rsa` クレートのタイミング脆弱性（Marvin）と需要を踏まえ初期スコープ外（ADR-0001） |
| 種類 | **同期可能なマルチデバイス・ディスカバラブルクレデンシャル**（`BE=1`, `BS=1`） | ZeroPass の原則④（OS 非依存・端末間同期）。単一端末に束縛するデバイス束縛型（`BE=0`）は初期スコープ外 |
| Attestation | **`none` のみ**（`{ "fmt": "none", "attStmt": {}, "authData": ... }`） | ユーザー追跡を防ぎ、同期可能パスキーの標準的慣行に従う。AAGUID は ZeroPass 固有の固定 16 バイト値（`docs/spec/passkey.md`） |
| User Verification（UV） | **常に `UP=1`・`UV=1`** | 登録・認証のたびに金庫デーモン側で Passkey ドメインを施錠し、鍵エージェント（Windows Hello 等）で解錠し直して生体認証を必須化する（`BridgeTotp` と同じ原則） |
| `signCount` | **常に `0` 固定** | オフライン近接同期する複数端末間で単調増加カウンタを共有すると、未同期の端末からの認証で RP 側にクローン誤検知を引き起こす。W3C WebAuthn Level 2/3 でも同期可能クレデンシャルでは `signCount = 0` が許容・推奨されている |
| 秘密鍵の保管と境界 | **VK-K ドメインに PKCS #8 DER で保存し、`zp-vaultd` のパスキーワーカー外に出さない** | 既存の `PasskeyCredential` 形式をそのまま使い、生成・署名はすべてパスキーワーカー内で完結させる（ADR-0007、G7） |
| RP ID 検証 | **拡張のオリジンを金庫デーモン側で検証** | `https`（および開発用の `http://localhost` / `http://127.0.0.1`）で、ページのホストが `rpId` と一致するかそのサブドメインであり、かつ `rpId` が公開サフィックス自身でないことを `zp-origin` で確認する（G8） |

## 検討した代替案

| 案 | 却下理由 |
|---|---|
| `passkey-authenticator` + `passkey-types` を採用し、`CredentialStore` を実装する | `async` 必須によるランタイム導入、`coset::CoseKey` の `Zeroize` 非対応と既存 `PasskeyCredential` との変換コスト、依存ツリーと暗号クレート世代の重複が、自前実装のコスト（数百行）を上回る |
| `passkey` クレート群一式（`passkey-client` 含む）を採用する | 上記に加え、`public-suffix` が `zp-origin` と重複し、オプションの `reqwest` 経路も抱える。ブラウザ拡張からの要求はすでにオリジン確定済みであり、`passkey-client` の層が過剰 |
| `signCount` を端末ごと・同期ごとに増やす | オフライン同期では端末 A と端末 B が互いに未同期のまま認証する場面が必ず起き、値が前後して RP 側でアカウントロックやクローン誤検知を招く |
| RS256（`-257`）を初期から対応する | `rsa` クレートは Marvin 攻撃の懸念があり（ADR-0001）、現代の WebAuthn RP はすべて ES256 を受け入れる |

## 結果（トレードオフ・今後の課題）

- **利点**:
  - `zp-passkey` の実装は小さく監査しやすい（プロトコル層数百行、暗号プリミティブは `p256` / `ed25519-dalek` / `sha2` のみ）。
  - すべての秘密鍵を `ZeroizeOnDrop` + `Debug` 非表示で一貫して管理でき、`zp-vaultd` の同期モデルと既存の `PasskeyCredential` 形式にそのまま載る。
  - `clientDataHash` を直接受け取るコア API により、Phase 5 のブラウザ拡張と Phase 6 の Android / iOS ネイティブプロバイダの両方から再利用しやすい。
- **トレードオフ**:
  - WebAuthn 仕様の細部（authenticatorData のビット配置、COSE Key の正準 CBOR、ECDSA 署名の ASN.1 DER、RP ID の有効ドメイン判定、`excludeCredentials` / `allowCredentials` の扱い）を自前で保守する責任が生じる。これを補うため、P5-03 で WebAuthn 適合テストベクタと検証器による往復テスト、P5-04 で実サイト（`webauthn.io`）を含む E2E テストを必須とする。
  - `signCount = 0` 固定のため、万一パスキー秘密鍵が流出して他所で複製使用されても RP 側のカウンタでは検知できない（脅威モデル §5.4 の既知のトレードオフ）。
  - CTAP2 拡張（`prf`、`largeBlob`、`hmac-secret`、`credProps` 等）は初期スコープ外とし、必要になった段階で `docs/spec/passkey.md` を拡張する（`credProps` の `rk: true` 返却など軽量なものは必要に応じて追加）。
