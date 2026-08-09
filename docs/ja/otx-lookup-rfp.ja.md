# RFP: otx-lookup

> Generated: 2026-08-09
> Status: Draft

## 1. Problem Statement

既存の lookup 群（asn-lookup / whois-lookup / abuse-lookup / rdns-lookup /
doh-lookup / tor-exit-lookup / icloud-relay-lookup / mac-lookup /
malware-lookup / urlscan-lookup）はいずれも「1 つの IoC → 1 つの属性」を返す。
帰属、登録情報、評判、関係、現在の解決結果 — どれも個々の事実であって、
トリアージで本当に知りたい「**この IoC は既知のキャンペーンの一部なのか**」には
答えられない。

otx-lookup は LevelBlue Open Threat Exchange (OTX) のコミュニティ報告
（pulse）を引き、IoC に **adversary / malware family / ATT&CK テクニック /
標的業種・標的国 / 報告時期・報告者**という文脈を付与する。さらに同じ pulse に
載っている**関連 IoC へのピボット**を可能にし、単発のアラートを既知の
キャンペーン像に接続する。

第三者インデックスを読むだけなので**調査対象に一切パケットが届かない**。
rdns-lookup と同じくトリアージの初手に置ける位置づけになる。

利用者は自分（nlink-jp のセキュリティ調査・IR 業務）。

## 2. Functional Specification

### Commands / API Surface

```
otx-lookup lookup <indicator>...     # IoC 照会（型自動判定）
otx-lookup pulse <pulse_id>          # pulse 詳細
otx-lookup search <query>            # pulse 検索（API キー必須）
otx-lookup cache status|clear        # キャッシュ操作
otx-lookup mcp                       # MCP サーバとして起動
otx-lookup --version                 # 版数（brew test が叩く）
```

**型自動判定**: IPv4 / IPv6 / domain / hostname / URL / file hash（32=MD5,
40=SHA1, 64=SHA256）/ CVE-\d{4}-\d+。malware-lookup と同じ「桁数と形から
判定する単一入口」方式。

**主要フラグ**:

| フラグ | 対象 | 意味 |
|---|---|---|
| `--sections a,b,c` | lookup | 既定で出さない section を明示取得 |
| `--anonymous` | 全体 | API キーが設定されていても使わずに照会する |
| `--indicators` | pulse | pulse 内の IoC 一覧を展開（API キー必須） |
| `--input FILE` | lookup | バルク入力（`-` で stdin） |
| `--limit N` | lookup / search | 表示・取得件数 |
| `--json` | 全体 | 機械可読出力（複数対象時は JSONL） |

### Input / Output

**既定出力（human-readable text）** は pulse_info を中心に構成する:

- pulse 件数（上流の総数 vs 取得件数を必ず併記）
- 直近の pulse: 名前 / 作者 / created・modified / TLP / indicator_count
- 全 pulse から集約した文脈: adversary, malware_families, attack_ids
  (ATT&CK), industries, targeted_countries, tags
- `references` の外部 URL（一次情報への導線）
- `false_positive` フラグと `validation`（誤検知申告と検証記録）

**既定で出さないもの**: `reputation` / `passive_dns` / `malware` /
`url_list` — それぞれ abuse-lookup / rdns-lookup / malware-lookup /
urlscan-lookup が専任で担っており、既定で重ねると「どのツールの答えを
信じるのか」が曖昧になる。必要なときだけ `--sections` で明示取得する。

**バルク**: 複数引数 / `--input FILE` / stdin。複数対象時の `--json` は
JSONL。レート予算に対してペーシングする。

**exit 契約**（malware-lookup / rdns-lookup 踏襲）:

| Code | 意味 |
|---|---|
| 0 | 全対象の照会が完了した（pulse 0 件も正常な答え） |
| 1 | 上流障害で一部が引けなかった（引けた分は出力する） |
| 2 | 使用法エラー — 入力不正、設定不正 |

**MCP tools**: `lookup_indicator` / `get_pulse` / `search_pulses` /
`cache_status` / `get_usage`。`get_usage` が正典（mcp-tactics はパラメータを
書かない方針）。tool エラーは構造化 JSON `{code, message}`。pulse の IoC 一覧の
ような大きい結果は `workspace_root` にファイル出力し、パスと件数サマリのみ
返す（rdns-lookup の `inline_max_records` と同型）。

### Configuration

sectioned TOML `~/.config/otx-lookup/config.toml`（macOS は `~/.config` も
探索）。precedence は **flag > 環境変数 > config file > 組み込み既定**。

| 設定 | TOML | Env | 既定 |
|---|---|---|---|
| API キー | `[api] key` | `OTX_LOOKUP_API_KEY` / `OTX_API_KEY` | (なし) |
| API ルート | `[api] base_url` | `OTX_LOOKUP_BASE_URL` | `https://otx.alienvault.com/api/v1` |
| 表示 pulse 件数 | `[query] default_limit` | `OTX_LOOKUP_DEFAULT_LIMIT` | 10 |
| キャッシュ TTL | `[cache] ttl_hours` | `OTX_LOOKUP_CACHE_TTL_HOURS` | 24 |
| キャッシュ dir | `[cache] dir` | `OTX_LOOKUP_CACHE_DIR` | `~/.cache/otx-lookup` |
| タイムアウト | `[network] timeout_seconds` | `OTX_LOOKUP_TIMEOUT_SECONDS` | 30 |
| レート下限 | `[ratelimit] min_remaining` | `OTX_LOOKUP_MIN_REMAINING` | (要調整) |
| MCP inline 上限 | `[mcp] inline_max_records` | `OTX_LOOKUP_MCP_INLINE_MAX` | 200 |
| MCP workspace | `[mcp] workspace` | `OTX_LOOKUP_WORKSPACE` | (なし) |

`OTX_API_KEY` を別名で受けるのは、OTX 公式 SDK 群が同名の環境変数を使う
慣習があるため。キーは秘密情報なので config.example.toml にはプレース
ホルダのみ置く。

### External Dependencies

- **LevelBlue OTX DirectConnect API**（`https://otx.alienvault.com/api/v1`、
  認証ヘッダ `X-OTX-API-KEY`）。API キーは**任意** — 無くても indicators
  照会と pulse 詳細は動く（graceful degradation）。
- Go 標準ライブラリ + 既存 lookup 群と同じ内製 MCP レイヤ。**公式
  OTX-Go-SDK は依存にしない**（理由は §3）。

## 3. Design Decisions

### なぜ Go か

cybersecurity-series の lookup 群（asn / whois / abuse / rdns / doh / tor /
relay / mac / malware / urlscan）が全て Go で、単一バイナリ配布・
Developer ID 署名 + notarize・homebrew tap という配布経路を共有している。
otx-lookup も同じ棚に並べる以上、言語を変える理由がない。

### 公式 OTX-Go-SDK を依存にしない

[AlienVault-OTX/OTX-Go-SDK](https://github.com/AlienVault-OTX/OTX-Go-SDK)
を調査した結果（2026-08-09 実測）:

| 項目 | 実測値 |
|---|---|
| 最終 push | 2021-10-28 |
| コミット数 | 15 |
| `go.mod` | 無し（`src/otxapi/` の GOPATH 時代レイアウト） |
| 実装範囲 | `users/me` / `subscriptions` / `pulses/{id}` の 3 系統のみ |
| License | Apache-2.0 |

決定的なのは最終行で、**本ツールの中核である `indicators/*` が丸ごと
未実装**である。依存として抱えても書く量はほとんど減らず、
モジュール非対応のため `go.mod` 側で吸収する手間が増える。

したがって **REST 直叩き + Apache-2.0 の inspired-by 帰属**とする
（splunk-mcp / chrome-pilot-mcp と同じ判断）。型定義と `X-OTX-API-KEY` の
扱いは参考にする。

### 既存 nlink-jp ツールとの補完関係

| ツール | 答えるもの | otx-lookup との関係 |
|---|---|---|
| asn-lookup | 帰属（AS・国） | 直交 |
| whois-lookup | 登録情報 | 直交 |
| abuse-lookup | 評判（AbuseIPDB） | **重複** — OTX `reputation` は既定オフ |
| rdns-lookup | 関係（DNS 索引） | **重複** — OTX `passive_dns` は既定オフ |
| doh-lookup | 現在の解決結果 | 直交 |
| malware-lookup | ハッシュの正体 | **重複** — OTX `analysis` は既定オフ |
| urlscan-lookup | URL の挙動 | **重複** — OTX `url_list` は既定オフ |
| **otx-lookup** | **キャンペーン文脈と関連 IoC** | **他に担い手がいない** |

重複部分を既定オフにすることで、otx-lookup は「pulse 専任」として棚に
収まる。重複情報が必要なときは `--sections` が逃げ道になる。

### 関連 IoC へのピボットは 2 段階手動

`lookup` で pulse ID を見て、`pulse <id> --indicators` で展開する。
「その IoC が載る全 pulse の全 IoC を一発集約」する `pivot` ワンショットも
検討したが、以下の理由で採らない:

- pulse 数 × ページングでリクエストが予測不能に膨らむ
- pulse はコミュニティ投稿で**品質がまちまち** — 自動集約すると
  低品質 pulse の IoC が黙って混入する。どの pulse を信じるかは
  アナリストの判断であり、その判断点を消してはならない

### 明示的にスコープ外

- **書き込み系すべて** — pulse の作成 / 編集 / 削除、購読 / 購読解除、
  ユーザーの follow / unfollow。調査ツールが書き込み権限を持つ理由がない。
- **`submit_file` / `submit_url`** — 検体や URL を外部にアップロードする
  行為であり、自組織の関心を外部に晒す。設計として持たない。
- **STIX 2.1 / CSV エクスポート** — STIX 化は incident-research Skill が
  ADR-010 で既に担っている。`--json` を食わせれば済む。
- **`pulses/subscribed` によるフィード同期** — DirectConnect の本来用途だが、
  それは「IoC を SIEM に流し込む」パイプラインであって lookup ツールの
  仕事ではない。必要になったら別プロジェクトを立てる。

## 4. Development Plan

### Phase 1: Core

- `internal/config`（sectioned TOML + env + precedence）
- `internal/cache`（TTL、degraded 結果はキャッシュしない）
- `internal/indicator`（型自動判定 — IPv4/IPv6/domain/hostname/URL/hash/CVE）
- `internal/otx`（REST クライアント: indicators 全 section、pulse detail、
  pulse related。`httptest` でテスト）
- `internal/engine`（pulse_info → 文脈サマリの集約。純関数として書く）
- CLI `lookup` サブコマンド（`--sections` / `--json` / `--limit` /
  `--anonymous` / バルク入力）、exit 契約
- unit + integration テスト

**独立レビュー可**。この時点で「IoC にキャンペーン文脈を付ける」という
中核価値は完成している。

### Phase 2: Features

- `pulse` サブコマンド（詳細 + `--indicators`。IoC 一覧は API キー必須）
- `search` サブコマンド（API キー必須）
- `cache status|clear`
- MCP サーバ（`lookup_indicator` / `get_pulse` / `search_pulses` /
  `cache_status` / `get_usage`、workspace ファイル媒介、構造化エラー）
- キー有無による機能差の graceful degradation を全経路で検証

**独立レビュー可**。

### Phase 3: Release

- README.md / README.ja.md / `docs/{en,ja}` 3 層 / AGENTS.md /
  CHANGELOG.md / config.example.toml / LICENSE
- e2e（live 検証。fixture は「pulse が付く安定した IoC」「pulse 0 件の
  クリーンな IoC」「false_positive が立つ IoC」を選定）
- `make build-all` → 署名 + notarize → GitHub release
- 統合: cybersecurity-series submodule / org profile /
  nlink-web-site (EN+JA) / homebrew-tap formula /
  **mcp-tactics Skill 追随（19→20 サーバ。行を足すだけでなく序列の端点を
  再導出する）** / `check-org.sh` all green

## 5. Required API Scopes / Permissions

- **OAuth スコープ / IAM ロール: なし。**
- LevelBlue OTX の API キー 1 本のみ（otx.alienvault.com の無料アカウント
  設定画面で取得）。スコープの概念は無く、キーはアカウント全体の権限を持つ。
- **キーは任意**。未設定でも `indicators/*` 全 section と `pulses/{id}`、
  `pulses/{id}/related` は匿名で引ける。キーが解禁するのは
  `pulses/{id}/indicators`（pulse 内 IoC 一覧）、`search/pulses`、
  `pulses/subscribed` の 3 系統とレート上限の引き上げ。

## 6. Series Placement

Series: **cybersecurity-series**

Reason: 脅威インテリジェンスの照会ツールであり、既存の lookup 群
（asn / whois / abuse / rdns / doh / tor / relay / mac / malware /
urlscan）と同じ棚・同じ形（Go / CLI + MCP / 単一バイナリ / tap 配布）に
収まる。util-series は汎用データ変換 CLI の棚であり、対象読者が違う。

## 7. External Platform Constraints

**実測値（2026-08-09 live 確認）**:

- **レート制限**: 匿名 1,000 req/h、API キーあり 10,000 req/h。
  **レスポンスヘッダにレート残量が返らない**（観測できたのは
  `X-OTX-ACTIVE` のみ）。rdns-lookup のように上流から残量をもらえないので、
  **クライアント側で自前カウントしてペーシングする**必要がある。
- **匿名 / 認証の境界**:

  | エンドポイント | 匿名 |
  |---|---|
  | `indicators/{type}/{ind}/{section}` 全 section | 200 |
  | `pulses/{id}` | 200 |
  | `pulses/{id}/related` | 200 |
  | `pulses/{id}/indicators` | **403** |
  | `search/pulses` | **403** |
  | `pulses/subscribed` | **403** |

- **型ごとの section**:

  | 型 | sections |
  |---|---|
  | IPv4 | general, geo, reputation, url_list, passive_dns, malware, nids_list, http_scans |
  | domain / hostname | general, geo, url_list, passive_dns, malware, whois, http_scans |
  | file | general, analysis |
  | url | general, url_list, http_scans, screenshot |
  | cve | general, nids_list, malware |

- **`pulse_info.count` は頭打ちしうる** — `example.com` で count=50 を観測
  しており、ページ内の件数を返している可能性が高い。rdns-lookup の
  「上流が持つ件数 vs 取得した件数を必ず併記する」原則を踏襲し、
  **部分的な答えを完全な答えと誤認させない**。
- **pulse の品質はまちまち** — コミュニティ投稿なので、作者・投票数・
  `false_positive`・`validation` を出して判断材料にする。自動で
  「悪性/良性」を断定しない。
- **EULA は非商用限定** — 「OTX is free to end users for non-commercial
  use」。VirusTotal のような「ワークフロー組み込み禁止」条項は無く、
  DirectConnect でのツール連携はむしろ公式が推奨する用途だが、
  **非商用限定である旨は README に明記する**（malware-lookup の
  MalwareBazaar / Spamhaus 注記と同じ扱い）。
- **LevelBlue へのリブランドが進行中** — ドキュメントが
  `alienvault.com` / `cybersecurity.att.com` / `levelblue.com` に分散して
  いる。API ホスト `otx.alienvault.com` は現役だが、
  **将来の移行に備えて `base_url` は設定可能にしておく**。

---

## Discussion Log

**2026-08-09**

1. **発端** — ユーザーが OTX-Go-SDK の存在を示し、「このコードを参考に
   OTX の情報を参照して調査する CLI + MCP サーバー実装を検討したい」と提起。

2. **SDK の評価** — `gh api` で実測。最終 push 2021-10-28、`go.mod` 無し、
   実装は 3 系統のみで `indicators/*` が未実装。**依存にせず REST 直叩き**
   と決定。Apache-2.0 なので inspired-by 帰属で扱う。

3. **API の実地調査** — 匿名で各エンドポイントを叩き、認証境界・型ごとの
   section・`pulse_info` の構造・レート制限を確認。**匿名で indicators が
   全部引ける**という事実が、後の「API キーは任意」という設計判断の
   根拠になった。

4. **存在理由の絞り込み** — OTX の `reputation` / `passive_dns` /
   `malware` / `url_list` は既存 lookup 4 本と正面衝突する。一方
   `pulse_info`（adversary / malware_families / attack_ids / industries /
   targeted_countries）は**他に担い手がいない**。よって「評判ツール」では
   なく「**文脈付与＋ピボット**ツール」として位置づけ、重複 section は
   既定オフ・`--sections` で明示取得とした。

5. **スコープの選択肢** — (a) lookup 単機能、(b) 文脈＋ピボット、
   (c) 全部入り、の 3 案を提示。**(b) 文脈＋ピボット**を採用。

6. **API キーの扱い** — 必須 / 任意の 2 案。実測で匿名でも中核機能が
   動くことが分かっていたため **任意（graceful degradation）**を採用。
   malware-lookup の MalwareBazaar キーと同じ扱い。加えて、キーを使うと
   照会が OTX アカウントに紐づいて記録されるため、**`--anonymous` で
   明示的にキーを使わない照会**もできるようにした。

7. **ピボットの実装形** — `pivot` ワンショット案を検討したが却下。
   pulse 数 × ページングでリクエストが膨らむこと、および pulse の品質が
   まちまちで**どの pulse を信じるかはアナリストの判断**であることから、
   **2 段階手動**（lookup → `pulse <id> --indicators`）とした。

8. **バルク入力** — rdns-lookup 同型の `--input` / stdin を採用。
   10,000 req/h という緩いレート制限がこれを現実的にしている。

9. **エクスポート形式** — STIX 2.1 / CSV を検討したが、**text + JSON のみ**。
   STIX 化は incident-research Skill が ADR-010 で既に担っており、
   `--json` を食わせれば繋がるため、役割を重ねない。

10. **OpSec 上の位置づけ** — 第三者インデックスの照会であり調査対象に
    パケットが届かないため、mcp-tactics の 4 段ドクトリンでは
    **tier 2（サードパーティ照会）**。ただし **API キーを使うと照会が
    OTX アカウントに記録される**点は、フリート追随（19→20 サーバ）で
    序列の端点を再導出する際に検討が必要。
