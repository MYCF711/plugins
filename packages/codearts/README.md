# @magpie-community/opencode-codearts-auth

Signs in to **Huawei Cloud** once and serves two providers in OpenCode and magpie:

- **CodeArts** (华为云码道, the CodeArts Agent coding plans: Trial, personal and enterprise
  credit plans) — provider id `codearts`: GLM, DeepSeek, openPangu and more.
- **OfficeAce** (华为云 AgentArts / MaaS) — provider id `officeace`: GLM, DeepSeek, Qwen, Kimi
  and 盘古 models, its credit buckets and its daily check-in.

One Huawei Cloud IAM account, one sign-in: the STS credentials one sign-in yields sign both
vendors' APIs (measured, see below), so signing in at either card signs in the other. OfficeAce
was its own package (`officeace-auth`) until 0.3.0; accounts signed in there are read from where
magpie already keeps them and keep working — no second sign-in.

> **Unofficial.** This package is not affiliated with, authorized or endorsed by Huawei,
> Huawei Cloud or CodeArts; their names and marks belong to their owners. It talks to the
> non-public APIs the CodeArts client uses and identifies itself the way that client does
> (including claiming the daily free benefit and check-in), which may not be allowed by Huawei
> Cloud's terms of service, and those APIs may change at any time. Use it at your own risk,
> including the risk of restrictions on your account.

## Install

```sh
magpie plugin add @magpie-community/opencode-codearts-auth
magpie plugin login codearts      # one sign-in; the OfficeAce card gets the same account
```

or install it from magpie's Plugins tab and sign in there. **Coming from `officeace-auth`?**
Nothing to do: the account is stored under the same provider id (`officeace`) and in the same
credential shape, so it is read as it is. Remove the old package first (both cannot serve one
provider id: magpie asks which one if they are both installed).

## Sign-in

**Sign in with Huawei Cloud** opens Huawei Cloud's consent page. The plugin listens on a
loopback port (`127.0.0.1`, ≥ 10000) for the redirect and exchanges the code at Huawei Cloud
STS — a PKCE flow whose token requests carry an ES256 DPoP proof, as the CodeArts client does.
STS answers with temporary AK/SK/security-token credentials and a refresh token. The callback
server takes one GET to `/oauth/callback`, exactly; one that comes back without a code (the
portal's error) fails the sign-in at once.

**Where it is kept:** the whole credential (AK/SK/security token, expiry, refresh token, the
PKCE verifier and the DPoP private key) is a JSON string in the account's `access` field, in
magpie's (or OpenCode's) own account store. `auth.refresh` renews it 30 minutes before it
expires, reusing the same verifier and DPoP key; a stale credential met on a request
(`401`, `APIG.0602`) is renewed once and the request sent again. A refresh token is spent once
per account, however many loaders ask; a renewal that only fails for now (STS unreachable)
answers `503` and keeps the sign-in, and only one STS turns away for good marks it.

**The card's name:** the account is shown by its **phone number** (`138****8000`, masked the way
the other magpie cards mask theirs), read once after signing in from Huawei Cloud IAM —
`GET https://iam.cn-north-4.myhuaweicloud.com/v3.0/OS-USER/users/{principal_id}`, signed with
the same temporary credentials — and kept on the credential as `user_phone`. The refresh token
names the signer only by IAM's own ids (`hw12323`, and the URN
`iam::<domain>:user:<name>`), which read as an ID nobody can tell apart from another account's;
the account name is the fallback when the phone can't be read, and the URN never is.

`accountId` is the account's identity — the URN, as before — and it never changes: magpie
keys the user's own name for the account, its proxy, model picks and a gateway key's list by
it, so a re-sign-in and a renewal give the same value back. The card's name is usage's `user`,
which shows `user_phone` once a sign-in or renewal has read it. IAM is *not* one of the hosts the plugin signs forwarded requests for
(`SIGNED_HOSTS`): the one phone read is made by the plugin itself, for that one URL.

## Models

The account's live list: CodeArts' builtin models, plus the free models of its daily benefit
once today's benefit has been claimed (`POST /api/v1/benefit/claim`, once a Beijing day, as the
client does; a `benefit not found` on a day not yet claimed claims it too). Each model's credit
rate (the client's 「消耗系数」) is reported as magpie's `rate`,
with its reasoning flag and limits, from the account's main agent (`build`) model list. Before
signing in, a short built-in catalog stands in.

## Requests

- Every request is signed with Huawei's SDK-HMAC-SHA256 using the temporary credentials, and
  only for CodeArts' own two hosts, `snap-access.cn-north-4.myhuaweicloud.com` and
  `opengw.developer.huaweicloud.com`: a request anywhere else (an overridden `api`) is refused
  before the credentials leave, and no signed or token request follows a redirect.
- The gateway allows 3 concurrent sessions per account and tells them apart by
  `x-ot-session-id`; the plugin sends one stable session id per account (and a fresh trace per
  request) like the client, keeps at most 3 chats in flight per account, retries
  `TM.00001041` with backoff, and waits in the gateway's own queue (`429` +
  `queue-status: queued`) the way the client does. Only then does magpie get a `429`. Since
  0.2.3, when magpie has another candidate after this request (`x-magpie-fallback: 1`), a queued
  request leaves the queue at once and answers `503` with the queue's `Retry-After`
  ("CodeArts queued the request; try again in 20s"), and magpie asks the next.
- Chats always go upstream as streams — CodeArts meters only streamed answers — and are folded
  back into one `chat.completion` when the caller asked for JSON.
- `thinking: { type: "enabled" }` is sent unless the caller set it, so the reasoning lands in
  `reasoning_content` and `content` is only the reply.
- Errors the gateway puts inside a `200` stream (spent quota, unknown model) come back as
  `429` / `400` / `502` with the vendor's words. The `codearts/` prefix is stripped and output
  budgets are clamped to 65536.
- CodeArts takes tool names of up to 64 characters. A longer one (an MCP tool such as
  `mcp__plugin_android-emulator_android-emulator__android_discover_project`) goes as its first
  55 characters, `_` and 8 hex of its SHA-256, and the tool calls in the answer, streamed or
  not, carry the agent's own name again.
- Every model is listed as text only (`modalities.input: ["text"]`, `image: false`): CodeArts
  answers an image with `InferHub.001001020.406` "The request model is not multimodal". Since
  0.2.4 magpie is told so, and describes an image for the model or leaves it out. That refusal,
  inside a `200` or with any status, comes back as a `400`, not a `502` an agent would ask again.

## Usage and check-in

- Usage: the credit buckets of `snap-manager/v1/statistics/plugin` (only the package total
  pauses the account; the basic / on-demand / bonus buckets are shown aside) and the free daily
  token pool.
- When each credit batch expires is read from the CodeArts console's own calls
  (`snap-manager/v1/package/credit/page`, `v1/ops/credit/*`); when those can't be read, the
  plugin falls back to a small ledger of the check-ins it claimed,
  `~/.config/magpie/codearts-checkins.json` (or `MAGPIE_CODEARTS_LEDGER`). This part is still
  being checked against more accounts — trust the CodeArts console where they differ.
- `auth.checkin`: the client's 「限时福利 → 每日领取」 — `GET /v1/ops/delivery?channel=IDE`,
  `POST /v1/ops/claim`, then `POST /v1/ops/confirm` when the claim answers an id. A claim whose
  confirm failed is kept in that ledger for the day and confirmed at the next check-in; one the
  client leaves unconfirmed (`id: null`) never is. Turn on
  *Auto check-in* for CodeArts under **Settings → Usage → Plugins**.

## OfficeAce (the second provider)

**Signing in once.** The officeace card offers the same 「Sign in with Huawei Cloud」 as the
CodeArts card, because it is the same credential: a CodeArts STS triple signs OfficeAce's
subscription API (V11-HMAC) and passes its CLAW permission check, and an OfficeAce triple signs
CodeArts' `snap-access` calls. A sign-in at either card writes both records — the one magpie
saves for the provider signed in at, and the other provider's, in that provider's own shape.
A record written this way lives at `<provider>#<hash of the account's identity>`, so signing in
at that provider's own card later lands on the same account instead of adding a second one.
A sign-in is the only thing that creates an OfficeAce account: a listing never adopts one from
another provider's record, so an account the user signed out of cannot come back by itself.

**From `officeace-auth`.** That package's records are read unchanged: the account is under the
same provider id and its `access` field holds the same JSON (`modelAppKey`, `securityToken`,
`dpopPrivateJwk`, `refreshToken` …). Its refresh token is still spent at the OAuth client it was
issued to (`pdp5_for_agentarts`), so those accounts keep renewing too.

**What a record is named, and what a renewal may touch.** `accountId` is the vendor's own stable
id — the IAM domain id, as the record `officeace-auth` wrote carried — and never the masked
phone: magpie hangs a user's own name for the account, its proxy and a gateway key off
`accountId`, so the phone belongs only in `usage().user` (#483, magpie#4416). A renewal never
renames an account: the stored `accountId` and `uid` stand exactly as written — the domain id, or
the phone `officeace-auth` 0.1.14 stored — and a value computed from the credential is only
filled in when the record has none. A new sign-in names its account by the domain id.

**A record is renewed only with its own refresh token.** The unit of coordination is the refresh
chain: the OAuth client a token was issued to plus the token's lineage (a rotation keeps its
parent's, so a record still holding the spent token is known to be on the same chain). Two records
written from one sign-in hold the same token and are one chain — that token is spent once however
many hooks ask.
An `officeace-auth` record beside a CodeArts record holds a different token (issuer
`pdp5_for_agentarts` against `codearts-agent`), so it is another chain: it spends its own token,
keeps its own MaaS pair, and a renewal that fails fails — it is never handed the other record's
credential. Neither record's renewal writes the other: the two only share the sign-in that created
them, never a credential afterwards. The first of the two to renew spends the shared token; the
other one's next renewal is refused (`STS5.1806`) and asks for the sign-in again. That is
deliberate — writing the new credential into the other record is exactly what used to bring a
removed account back — and it is the price stated under *Known limits*.

**Models.** OfficeAce's catalog (`GET {maas}/v2/models`) is a registry, not a promise: 26 entries,
most of which answer `404 ModelArts.81009 Invalid model` at chat. The plugin cuts it down to the
billable list (`GET {subscription}/v1/model-token-rates`, 9 entries) and never lists three ids
measured to always 404. A rates read that fails keeps the last good table — an empty one would
put the un-callable ids back in front of the user. Before a sign-in a built-in table of 10 stands
in. Names carry the account's multiplier (`GLM-5.3 · x0.18`), and the vendor's trailing newline in
`model_name` is trimmed.

**Requests.** MaaS wants `Authorization: Basic base64(appKey:appSecret)`; the plugin rewrites the
SDK's Bearer header, strips the `officeace/` model prefix, and sends the request to the MaaS base
the account's own credential names (official direct when it names none). A `401` (or a `4xx`
naming the Basic pair) renews the credential once and sends it again — but only when the renewal
changed the pair; the same pair would get the same refusal. An account that signed in without
opening MaaS gets a `400` saying so, not an empty Basic header sent upstream.

**Usage and check-in.** `GET {subscription}/v1/subscription`: plan buckets (`skus[].quotas`) and
activity bonuses (`bonus_skus`) become magpie windows; a `.trial` bucket carries no expiry and
gets none invented; an expired bucket is folded away (`aside`) and takes no part in routing. The
check-in is `POST {subscription}/v1/subscription/bonus/claim` once a Beijing day: a 2xx with no
`bonus_skus` is 「今日已无新增可领」 (`done`), not a failure. Turn on *Auto check-in* for OfficeAce
under **Settings → Usage → Plugins**.

**Known limits.**

- STS spends a refresh token once, and the two records of one sign-in share one token. Only the
  first of them to renew gets a new one; **the other record's next renewal fails (`STS5.1806`)
  and asks for the sign-in again**. That is the price of never writing one record from another —
  and the reason a record the user removed can never come back: a renewal writes no other
  record, whether it was listed, used, or not seen at all. Two separate magpie processes renewing
  the same account at the same moment still race; the loser asks again and is signed out only if
  the token stays spent.
- `officeace-auth` and this package cannot both serve the `officeace` provider id. Magpie asks
  which plugin serves it; remove the old one.

## Options

| Option | Default | What it does |
|---|---|---|
| `maxInflight` | `3` | chats in flight per account; it can only lower the vendor's cap of 3 sessions |
| `retryBudgetMs` | `150000` | how long to retry `TM.00001041` before answering `429` |
| `retryDelays` | `[2000,4000,6000,8000,10000]` | retry waits in ms (the last repeats) |
| `queueBudgetMs` | `300000` | how long to wait in the gateway's queue |
| `thinking` | `true` | `false` stops adding `thinking: { type: "enabled" }` |

## Credits

First written by [yuweihao17](https://github.com/yuweihao17/codearts); this version carries the
fixes of [yuweihao17/codearts#8](https://github.com/yuweihao17/codearts/pull/8). It builds on the
measurements and code of [HuHong-Tao](https://github.com/yuweihao17/codearts/pull/6) and
[ReachForStar](https://github.com/ReachForStar/codearts), and on the CodeArts channel of
[Ebony-Vinyl/dsh-our-free-model](https://github.com/Ebony-Vinyl/dsh-our-free-model).

## 中文

一次**华为云 OAuth 登录**，在 OpenCode 和 magpie 里同时服务两个供应商：

- **华为云码道（CodeArts Agent）**的编码套餐（体验版、个人与企业积分套餐），模型为 GLM、DeepSeek、
  openPangu 等。provider id：`codearts`。
- **OfficeAce（华为云 AgentArts / MaaS）**：GLM、DeepSeek、Qwen、Kimi、盘古等模型，分桶积分与每日签到。
  provider id：`officeace`。

同一次登录换到的 STS 凭据对两家的接口都有效（已实测，见下），所以在任一张卡片上登录，另一张也就登录了。
OfficeAce 在 0.3.0 之前是独立的 `officeace-auth` 包：那些账号按 magpie 原有的位置与形状读取，**不用重新登录**。

> **非官方插件**：与华为、华为云及 CodeArts（码道）没有任何关联，也未获其授权或认可。插件调用的是
> 码道客户端使用的非公开接口，并以与官方客户端相同的方式标识自己（含自动领取每日免费权益与签到），
> 这可能不符合华为云的服务条款，接口也可能随时变更。使用风险（包括账号受限）由使用者自行承担。

- **登录**：华为云 OAuth（PKCE + DPoP），本机 `127.0.0.1`（端口 ≥ 10000）接收回调，向 STS 换取临时
  AK/SK/security-token；回调只接受精确的 `/oauth/callback` GET，回调不带 code（portal 报错）时立即判定登录失败。完整凭据（含 refresh_token、PKCE verifier、DPoP 私钥）以 JSON 存在账号的
  `access` 字段里，保存在 magpie / OpenCode 自己的账号存储中；过期前 30 分钟自动续期，请求遇到临时凭据
  过期时就地续期并重发一次。同一账号的 refresh_token 只用一次；续期只是暂时失败（如 STS 连不上）时返回
  `503` 并保留登录，只有被 STS 明确拒绝才标记需要重新登录。账号标识取自 refresh_token，重复登录不会多出账号。
- **模型**：账号实时的内置模型列表；领取当日免费权益成功后，再加上免费模型（每个北京自然日领一次，与
  客户端一致；当天还没领取时遇到 `benefit not found` 也会先领取再重发）。每个模型的「消耗系数」作为 magpie 的倍率上报，来自账号主智能体（`build`）的模型列表。
- **请求**：SDK-HMAC-SHA256 签名，只签给码道自己的两个主机（`snap-access.cn-north-4.myhuaweicloud.com`、
  `opengw.developer.huaweicloud.com`），发往其他地址（如改过的 `api`）的请求在凭据发出前就被拒绝，签名请求和令牌请求都不跟随重定向；像客户端一样发送 `x-ot-session-id` 会话头（每账号一个会话），账号内
  在途请求不超过 3 个，`TM.00001041` 退避重试，网关排队时按客户端的方式等待（0.2.3 起，magpie 在这个请求之后还有别的账号、供应商或路由组成员时（`x-magpie-fallback: 1`），排队的请求立即退出队列并以 `503` 加队列的 `Retry-After` 回答，magpie 随即改问下一个）；总是以流式请求上游（码道
  只对流式回答计量积分），调用方要非流式时折叠回 JSON；默认注入 `thinking: { type: "enabled" }`，思考与
  正文分开；200 里内嵌的错误换算为 `429` / `400` / `502` 并带厂商原话；码道只接受不超过 64 个字符的工具名，
  更长的（如 MCP 工具名）发出时缩为前 55 个字符 + `_` + 8 位 SHA-256，回答（流式与非流式）里的工具调用再换回原名。
  0.2.4 起所有模型都声明为只收文本（码道对图片回 `InferHub.001001020.406`「The request model is not multimodal」），
  magpie 会替模型描述图片或把图片略去；这个拒绝不论放在 200 里还是带别的状态码，都换算为 `400`，而不是让智能体反复重试的 `502`。
- **用量与签到**：总积分决定账号是否可用，其余积分桶只做明细；另有每日免费额度窗口。各批积分的到期
  时间读自码道控制台同一批接口，读不到时退回插件的签到账本 `~/.config/magpie/codearts-checkins.json`
  （这部分仍在用更多账号验证，请以控制台为准）。`auth.checkin` 与客户端「限时福利 → 每日领取」一致
  （插件领取后确认失败的，当天记在签到账本里，下次签到时补确认；客户端本就不确认的 `id: null` 领取不会被确认），
  在 **设置 → 用量 → Plugins** 打开「每日自动签到」即可。
- **OfficeAce（第二个供应商）**：officeace 卡片提供与 CodeArts 卡片相同的「华为云登录」，因为它是同一份凭据：
  码道的 STS 三元组能签 OfficeAce 的订阅接口（V11-HMAC）并通过它的 CLAW 权限校验，反之 OfficeAce 的三元组也能签
  码道的 `snap-access` 接口。在任一张卡片登录都会写出**两条记录**（magpie 保存当前供应商的那条，插件写另一家的，
  各自用它自己的形状）；这样写出的记录放在 `<provider>#<账号身份哈希>` 上，之后在该供应商自己的卡片登录会合并到
  同一账号，而不是多出一行。**只有登录会创建 OfficeAce 账号**：列模型时不会从另一家的记录「带入」一个账号，
  用户登出的账号不会自己回来。老 `officeace-auth` 的记录原样读取：provider id 相同、`access` 里的 JSON 形状相同，
  续期仍走它签发时的 OAuth 客户端（`pdp5_for_agentarts`）。
- **账号名与续期边界**：`accountId` 用厂商自己的稳定 id（IAM 域名 id，与老 `officeace-auth` 记录里的一致），
  **绝不是打码手机号**（#483、magpie#4416；magpie 把用户给账号起的名字、代理、网关 key 都挂在 `accountId` 上，
  手机号只出现在 `usage().user`）。续期不会重命名账号：记录里已有的 `accountId`/`uid` 原样保留（域名 id，或
  `officeace-auth` 0.1.14 存下的手机号），只在该值为空时才补一个。新登录写的 `accountId` 是域名 id。
  续期只花**这条记录自己的 refresh token**：协调单位是「refresh chain = 签发它的 OAuth 客户端 + token 的血缘」
  （轮换后的新 token 记在父 token 同一血缘上，仍算同一条链）。
  同一次登录写出的两条记录持有同一个 token，算同一条链，一个进程内只花一次；老 `officeace-auth` 记录与码道记录
  是两个 token（`pdp5_for_agentarts` 与 `codearts-agent`），各花各的，各自保留自己的 MaaS 凭据，续期失败就是失败，
  绝不会借用另一条记录的凭据；先续期的那条记录仍会把新凭据推给本包写过的另一条。
- **OfficeAce 的模型**：目录 `/v2/models` 是注册表（26 条，多数对话时回 `404 ModelArts.81009 Invalid model`），
  插件只保留计费清单（`/v1/model-token-rates`，9 条）里的，并永不列出三个实测必 404 的 id；倍率表读取失败时保留上
  一份好表（空表会让不可调的 id 全部回到用户面前）；未登录时用 10 个内置模型兜底。模型名带上倍率（`GLM-5.3 · x0.18`），
  上游 `model_name` 的尾部换行会去掉。
- **OfficeAce 的请求**：MaaS 要 `Authorization: Basic base64(appKey:appSecret)`，插件把 SDK 的 Bearer 改写掉，
  去掉 `officeace/` 前缀，发到凭据里自带的 MaaS 地址（为空时用官方直连）。`401`（或 4xx 但报文点名这对 Basic 凭据）
  会先续期一次再重发，**但只有续期真的换了这对凭据时才重发**。已登录但没开通 MaaS 的账号会得到一条说清原因的 `400`，
  不会把空的 Basic 头发给上游。
- **OfficeAce 的用量与签到**：`/v1/subscription` 的套餐桶（`skus[].quotas`）与活动桶（`bonus_skus`）转成 magpie 的窗口；
  `.trial` 桶没有到期时间就不显示；已过期的桶收进折叠区（`aside`）且不参与路由。签到是每个北京自然日一次
  `POST /v1/subscription/bonus/claim`：2xx 但 `bonus_skus` 为空是「今日已无新增可领」（`done`），不是失败。
- **已知限制**：STS 的 refresh_token 只能用一次，同一次登录写出的两条记录共用同一个 token。先续期的一方拿到新 token；
  **另一条记录下次续期会失败（`STS5.1806`）并要求重新登录**。这是「续期绝不写另一条记录」的代价，换来的是：
  用户删掉的账号永远不会被写回来（无论它此前有没有被列出/使用过、有没有重启）。两个 magpie 进程同时续期仍可能撞车，
  输的一方重试，只有 token 一直是被消费状态才标记需重新登录。
  另外，`officeace-auth` 与本包不能同时服务 `officeace` 这个 provider id，magpie 会让你选一个，装之前先卸掉旧的。
- **致谢**：原作者 [yuweihao17](https://github.com/yuweihao17/codearts)；HuHong-Tao、ReachForStar 的
  实测与实现；[Ebony-Vinyl/dsh-our-free-model](https://github.com/Ebony-Vinyl/dsh-our-free-model)。

## License

MIT — see [LICENSE](./LICENSE).
