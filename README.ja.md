# otx-lookup

**OTX のコミュニティ報告（pulse）から、IoC にキャンペーンの文脈を与える CLI 兼ローカル MCP サーバー。**

同じ棚に並ぶ他の lookup ツールは、いずれも「1 つの IoC → 1 つの属性」に答える — 帰属（[asn-lookup](https://github.com/nlink-jp/asn-lookup)）、登録情報（[whois-lookup](https://github.com/nlink-jp/whois-lookup)）、評判（[abuse-lookup](https://github.com/nlink-jp/abuse-lookup)）、関係（[rdns-lookup](https://github.com/nlink-jp/rdns-lookup)）、現在の解決結果（[doh-lookup](https://github.com/nlink-jp/doh-lookup)）、ハッシュの正体（[malware-lookup](https://github.com/nlink-jp/malware-lookup)）、URL の挙動（[urlscan-lookup](https://github.com/nlink-jp/urlscan-lookup)）。しかしトリアージの本題である「**この IoC は既知のキャンペーンの一部なのか**」に答えられるものは、そこに無い。

otx-lookup は [LevelBlue Open Threat Exchange](https://otx.alienvault.com/) に投稿されたコミュニティ報告 — pulse — を読み、その IoC について何が主張されているかを示す。**アドバーサリ、マルウェアファミリ、ATT&CK テクニック、標的業種・標的国、誰がいつ報告したか**。そこから同じ pulse に載る他の IoC へピボットすれば、孤立したアラートがキャンペーンの一部として見えてくる。

第三者インデックスを読むだけなので、**調査対象にパケットが一切届かない**。`rdns-lookup` と同様、トリアージの初手に置ける。**API キーは任意** — すべての indicator section と pulse 詳細は匿名で引ける。

> **このツールが返すのは「主張」であって「判定」ではない。** pulse はコミュニティ投稿であり質はまちまちである。作者・投票数・誤検知フラグ・検証記録を結果に併記するので、重みはあなたが決める。otx-lookup が IoC を悪性と断定することはない。

## インストール

```bash
make build  # → dist/otx-lookup
```

## 使い方

```bash
# IoC のキャンペーン文脈 — 型は形から自動判定される
otx-lookup lookup 203.0.113.10
otx-lookup lookup evil.example.com
otx-lookup lookup 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
otx-lookup lookup CVE-2021-44228

# 姉妹ツールと重複する section は既定で出さない。必要なら明示する
otx-lookup lookup 203.0.113.10 --sections reputation,passive_dns

# 設定済みの API キーを使わずに照会する（OTX アカウントに記録させない）
otx-lookup lookup 203.0.113.10 --anonymous

# pulse を読み、そこに載る IoC へピボットする（--indicators は API キー必須）
otx-lookup pulse 693096c1cabeccbc6b3a5def
otx-lookup pulse 693096c1cabeccbc6b3a5def --indicators

# pulse 検索（API キー必須）
otx-lookup search "qakbot"

# 機械可読出力。複数対象のときは JSONL
otx-lookup lookup --json 203.0.113.10
otx-lookup lookup --json 203.0.113.10 evil.example.com

# バルク入力: 引数・ファイル・標準入力。レート予算に対してペーシングする
otx-lookup lookup --input targets.txt
cut -d, -f2 alerts.csv | otx-lookup lookup --json

# キャッシュ
otx-lookup cache status
otx-lookup cache clear
```

### 既定で出さない section と、その理由

OTX には姉妹ツール 4 本と重複する section がある。既定で出すと同じ問いに答えが 2 つ並び、どちらを信じるかの根拠が無くなる。よって `--sections` によるオプトインとする。

| Section | 担当ツール | OTX 版が「セカンドオピニオン」に留まる理由 |
|---|---|---|
| `reputation` | abuse-lookup | AbuseIPDB は報告元が辿れてスコアが付く |
| `passive_dns` | rdns-lookup | この問いのために作られた 60 億件のインデックス |
| `malware` / `analysis` | malware-lookup | 3 ソースを重ねて 1 つの判定にしている |
| `url_list` | urlscan-lookup | 実際に URL を読み込んだサンドボックス |

OTX にしか無いもの — pulse とそこにぶら下がる情報 — が既定で得られるものである。

### 終了コード

| Code | 意味 |
|---|---|
| 0 | 全対象の照会が完了した（pulse 0 件も正常な答え） |
| 1 | 上流障害で一部が引けなかった（引けた分は出力する） |
| 2 | エラー — 入力不正、設定不正 |

## MCP サーバー

```bash
otx-lookup mcp
```

ツール: `lookup_indicator` / `get_pulse` / `search_pulses` / `cache_status` / `get_usage`。**まず `get_usage` を呼ぶこと** — 完全なリファレンス、結果スキーマ、エラー復旧表が返る。tool エラーは構造化 JSON（`{code, message}`）。pulse が 0 件なのは正常な結果であってエラーではない。大きい結果は `workspace_root` にファイル出力し、パスと件数サマリのみ返すので、エージェントのコンテキストを溢れさせない。

Claude Code への登録:

```json
{
  "mcpServers": {
    "otx-lookup": {
      "command": "otx-lookup",
      "args": ["mcp"]
    }
  }
}
```

## 設定

**優先順位: フラグ > 環境変数 > 設定ファイル > 組み込み既定。** 設定ファイルは任意。[config.example.toml](config.example.toml) を参照。

| 設定 | TOML | Env | 既定 |
|---|---|---|---|
| API キー | `[api] key` | `OTX_LOOKUP_API_KEY` / `OTX_API_KEY` | (なし) |
| API ルート | `[api] base_url` | `OTX_LOOKUP_BASE_URL` | `https://otx.alienvault.com/api/v1` |
| 表示 pulse 件数 | `[query] default_limit` | `OTX_LOOKUP_DEFAULT_LIMIT` | `10` |
| キャッシュ TTL（時間） | `[cache] ttl_hours` | `OTX_LOOKUP_CACHE_TTL_HOURS` | `24` |
| キャッシュ dir | `[cache] dir` | `OTX_LOOKUP_CACHE_DIR` | `~/.cache/otx-lookup` |
| ネットワークタイムアウト | `[network] timeout_seconds` | `OTX_LOOKUP_TIMEOUT_SECONDS` | `30` |
| 1 時間あたり要求予算 | `[ratelimit] max_per_hour` | `OTX_LOOKUP_MAX_PER_HOUR` | (キーの有無から決定) |
| MCP inline 上限 | `[mcp] inline_max_records` | `OTX_LOOKUP_MCP_INLINE_MAX` | `200` |
| MCP workspace | `[mcp] workspace` | `OTX_LOOKUP_WORKSPACE` | (なし) |

`OTX_LOOKUP_API_KEY` に加えて `OTX_API_KEY` も受け付ける。公式 OTX SDK 群が慣習的に使っている変数名であり、それ用に整えた環境がそのまま動くようにするため。

### API キーで何が変わり、何は変わらないか

[otx.alienvault.com](https://otx.alienvault.com/) の無料アカウントでキーが 1 本発行される。OTX にスコープの概念は無いので、そのキーはアカウント全体の権限を持つ。キーが無い場合:

| | 匿名 | キーあり |
|---|---|---|
| indicator の全 section（全型） | 可 | 可 |
| pulse 詳細・関連 pulse | 可 | 可 |
| pulse 内の IoC 一覧 | 不可 | 可 |
| pulse 検索 | 不可 | 可 |
| レート上限 | 1,000 req/h | 10,000 req/h |

キーを付けた照会は OTX アカウントに記録される。キーを必要としない照会について、意図的にキーを使わないのが `--anonymous` である。

## 規約と帰属

**OTX は非商用利用に限り無料**（[End User Agreement](https://www.levelblue.com/legal/otx-eula-terms)）。OTX のデータを自前のツールに組み込むこと自体は DirectConnect API の本来用途だが、非商用制限の遵守は利用者の責任である。

本ツールは API を直接叩き、SDK を依存に持たない。公式の [OTX-Go-SDK](https://github.com/AlienVault-OTX/OTX-Go-SDK)（Apache-2.0）はリクエスト形式の参考にした。同 SDK が実装しているのは `users/me` / `subscriptions` / `pulses/{id}` のみで、最終コミットは Go modules 以前のものである。

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
