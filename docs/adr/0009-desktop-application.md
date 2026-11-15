# ADR-0009: デスクトップアプリは Tauri の埋め込みページだけを表示し、金庫には IPC の UI として接続する

- 状態: 採用
- 日付: 2026-11-16
- 関連: [ADR-0001](0001-technology-stack.md)、[ADR-0004](0004-process-architecture.md)、[ADR-0008](0008-windows-installation.md)、脅威モデル §4（B1）、タスク P4-01〜P4-03、`docs/spec/ipc.md` §3・§5

## 背景

P4-01 で、デスクトップアプリ（ADR-0001 の Tauri 2 + Svelte + TypeScript）の骨格を作る。ADR-0004 は UI に「ネットワークなし」を求め、P3-09 は `zp-cli` の依存ツリーからネットワーク系クレートを除き、依存の検査（`scripts/check-offline-deps.sh`）の対象にした。デスクトップアプリも同じ扱いにしたいが、Tauri はウェブビュー（Windows は WebView2、macOS と Linux は WebKit）を使う。ウェブビューはブラウザのエンジンであり、それ自体はネットワークを使える。

着手時に調べて分かったこと:

- `tauri` 2.12 は、**Android と iOS 向けにだけ** HTTP クライアント（`reqwest`、その下の `hyper`・`mio`・`socket2`）に依存する。Windows・macOS・Linux 向けの依存ツリーにネットワーク系クレートはない。Linux 向けには `soup3`（WebKitGTK の HTTP ライブラリの束縛。wry が独自のスキームを登録するのに使う）が入る。
- Tauri は、`custom-protocol` 機能がなく `devUrl` が設定されていれば、開発用サーバー（`http://localhost:…`）からページを読む。`frontendDist` のディレクトリは、コンパイル時に存在しなければならない。
- Linux では GTK 3 の束縛が、保守されていない手続きマクロ `proc-macro-error`（RUSTSEC-2024-0370）をコンパイル時に使い、`glib` 0.18（RUSTSEC-2024-0429）に依存する。

## 決定

1. **配置**: アプリは `apps/desktop/src-tauri`（ワークスペースのメンバー、パッケージ `zeropass-desktop`）で、実行ファイル名は `zeropass`。金庫デーモンは、同じディレクトリの `zeropass` に UI の役割を与える（`ipc.md` §3.1）。Tauri のバンドラ・アップデータは使わず、ほかのプログラムと一緒に Program Files へインストールする（ADR-0008。スタートメニューに登録する）。
2. **常に本番のビルド**: `tauri` の `custom-protocol` 機能を常に有効にし、`devUrl` を設定しない。ページは `apps/desktop/dist` からコンパイル時に埋め込まれ、どこからも読み込まない。デバッガ（devtools）はデバッグビルドでだけ有効。Tauri CLI は使わず、`cargo build` だけでビルドする。
   - Node.js なしでもワークスペースをビルド・テストできるように、`dist` がなければ `build.rs` が「UI がビルドされていない」と書いた代わりのページを置く。パッケージのスクリプトは UI をビルドしてから Rust をビルドし、代わりのページなら失敗する。
3. **ページに許すこと**:
   - CSP: `default-src 'self'`、`connect-src ipc: http://ipc.localhost`（Tauri の IPC だけ）、`object-src`・`frame-src`・`worker-src`・`form-action`・`base-uri` は `'none'`。インラインのスクリプトとスタイルは許さない。
   - 移動はアプリ自身のページ（`tauri://localhost`、Windows では `http(s)://tauri.localhost`）だけ。新しいウィンドウとダウンロードは拒否する。
   - ウェブビューは InPrivate（incognito）で動かし、ページの状態をディスクに残さない。
   - Tauri のコアのプラグイン（ウィンドウ、イベント、パスなど）の権限はページに与えない（`capabilities/default.json` は空）。`dynamic-acl` 機能は無効で、実行時に権限は増えない。ページが呼べるのは、アプリ自身のコマンドだけである。
4. **金庫との接続**: アプリは `zp-cli` と同じく `zp-client` を通じて金庫デーモンと同期デーモンに接続し、デーモンが動いていなければ起動する（金庫デーモンはサンドボックスの中で）。IPC の要求はすべてワーカースレッドで行う（Windows Hello の確認やペアリングの待ちで、ウィンドウを止めない）。Hello の要る操作では、鍵エージェントをコンソールの窓なしで起動する（`zp_client::set_windowed`）。
5. **秘密の扱い**: ページに平文を渡すのは、利用者が見ると決めたときだけにする（パスワードの表示は項目ごと・その都度）。クリップボードへのコピーは Rust 側で項目 ID から行い（`zp-clipboard`、履歴とクラウド同期に載せず、30 秒で消す）、パスワードをページに渡さない。
6. **依存の検査**: `zeropass-desktop` を、デスクトップの対象（Windows・macOS・Linux の x86_64 / aarch64）ごとに依存の検査にかける。Android・iOS 向けにはビルドしないので、その対象は検査しない。
7. **Linux の GTK 3 の束縛に関する勧告は記録して無視する**（`deny.toml`、`.cargo/audit.toml`）。`proc-macro-error`（RUSTSEC-2024-0370、保守されていない）はコンパイル時だけ動く手続きマクロで、出荷するプログラムには含まれない。`glib` 0.18 の GVariant の文字列の反復子の不健全さ（RUSTSEC-2024-0429）は、ZeroPass が GVariant を扱わないので影響しない。どちらも、Tauri が GTK 3 を使う限り直せない。

## 検討した代替案

| 案 | 却下理由 |
|---|---|
| Rust ネイティブの GUI（egui、iced、Slint）に変える | ネットワーク系クレートが入らないことはビルドで示せるが、Tauri でもデスクトップの対象では入らないと分かった（ウェブビュー自体の通信は CSP と移動の制限で抑える）。ADR-0001 の決定を覆すほどの差がなく、IME・アクセシビリティ・見た目の作り込みでは Tauri のほうが手間が少ない |
| デスクトップアプリをワークスペースの外に置く | ロックファイルが 2 つになり、`cargo-deny` と依存の検査から外れる。ほかのプログラムと同じディレクトリに出力するのにも工夫が要る |
| Tauri CLI（`tauri build`）でビルドする | `custom-protocol` を付け忘れると開発用の設定でビルドされる。`cargo build` だけで本番のビルドになるほうが、パッケージのスクリプトと CI が単純になる |
| ページに Tauri のクリップボードやダイアログのプラグインを許す | ページが乗っ取られたときにできることが増える。必要な操作はアプリ自身のコマンドとして、Rust 側で行う |

## 結果

- デスクトップアプリの Rust 側は、デスクトップの対象ではネットワーク系クレートに依存しない（CI で検査）。
- **ウェブビューのエンジンはネットワークを使える。** 防ぐのは、CSP、移動・新しいウィンドウ・ダウンロードの拒否、埋め込みのページだけを表示すること、である。ページ（とその依存の npm パッケージ）が乗っ取られれば、CSP の範囲内でしか通信できないが、表示中の平文は読める。ページの依存は最小限（Svelte と `@tauri-apps/api`）に保ち、`package-lock.json` で固定し、CI で `npm audit` を行う。
- **WebView2 は環境変数を読む**（`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` でデバッグ用のポートを開く、`WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` で別のランタイムを使う、など）。同じ利用者のプログラムはこれらを設定でき、アプリのページを読める。同じ利用者のマルウェアは脅威モデルの防御範囲外（§6 の「部分的に防御」）であり、IPC のパスの照合（`ipc.md` §3.3）と同じ限界である。
- 起動時間（プロセスの開始から、最初の画面＝解錠画面が描かれるまで。リリースビルド、金庫デーモンが動いている状態）は約 0.3 秒（P4-01）。WebView2 がその利用者のデータを初めて作るとき（インストール後の最初の起動）は 2 秒ほどかかる。
- Linux の CI には WebKitGTK の開発用ファイルが要る。
