# Architecture Decision Records

重要な設計判断を 1 件 1 ファイルで記録する。決定を覆すときは既存 ADR を書き換えず、新しい ADR を追加して旧 ADR の状態を「置き換え済み（ADR-XXXX）」にする。

| ADR | タイトル | 状態 |
|---|---|---|
| [0001](0001-technology-stack.md) | 技術スタック | 採用 |
| [0002](0002-key-hierarchy.md) | 鍵階層とドメイン分離 | 採用 |
| [0003](0003-sync-model.md) | 同期モデル | 採用 |
| [0004](0004-process-architecture.md) | プロセス構成と権限分離 | 採用 |
| [0005](0005-noise-patterns-and-sans-io.md) | Noise のパターンと入出力を持たないプロトコル実装 | 採用 |
| [0006](0006-windows-sandbox.md) | Windows では vaultd を AppContainer で動かす | 採用 |
| [0007](0007-domain-processes-and-key-agent.md) | 金庫デーモンをドメインごとのプロセスに分け、Windows Hello は鍵エージェントが外から使う | 採用 |
| [0008](0008-windows-installation.md) | Windows ではマシン全体に（Program Files へ）インストールし、ログオン時は Run キーから起動する | 採用 |
| [0009](0009-desktop-application.md) | デスクトップアプリは Tauri の埋め込みページだけを表示し、金庫には IPC の UI として接続する | 採用 |
| [0010](0010-passkey-engine.md) | パスキーエンジンは自作し、1Password の `passkey` クレート群は採用しない | 採用 |
| [0011](0011-hardware-domains-later.md) | TOTP とパスキーのドメインは、後から受け取る・作ることができる | 採用 |
| [0012](0012-android-vault-process.md) | Android では金庫を分離プロセスのメモリ上で開き、ファイルと鍵ストアはアプリのプロセスが受け持つ | 採用 |

## テンプレート

```markdown
# ADR-XXXX: タイトル

- 状態: 提案 / 採用 / 却下 / 置き換え済み（ADR-YYYY）
- 日付: YYYY-MM-DD
- 関連: タスク ID、脅威モデルの節

## 背景
## 決定
## 検討した代替案
## 結果（トレードオフ・今後の課題）
```
