# @magpie-community/opencode-workbuddy-auth

Signs in to the plans of WorkBuddy, Tencent's desktop agent from CodeBuddy.
It has one provider for each of WorkBuddy's two builds:

| Provider id | Build | API |
|---|---|---|
| `workbuddy` | WorkBuddy, the China build (CodeBuddy plan) | `https://copilot.tencent.com/v2` |
| `workbuddy-ai` | WorkBuddy AI, the international build | `https://www.workbuddy.ai/v2` |

The package exports `WorkBuddyAuthPlugin` (`workbuddy`) and
`WorkBuddyAIAuthPlugin` (`workbuddy-ai`).

## Signing in

- **Account (browser).** Opens Tencent's sign-in page for the build, the
  one WorkBuddy's desktop app opens. The plugin then asks WorkBuddy for the
  token every second until you're signed in, for 5 minutes at most. Nothing
  needs to be pasted.
- **Desktop's sign-in.** Uses the account WorkBuddy desktop is signed in
  to. Nothing is copied: the app's file is read on each request, and never
  changed:
  - macOS: `~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/workbuddy-desktop[-ai].info`
  - Windows: `~/AppData/Local/CodeBuddyExtension/…`
  - Linux: `~/.local/share/CodeBuddyExtension/…`

  WorkBuddy 5.6 and later keep the sign-in encrypted, which only the app
  opens, so this way fails there and says so: use the browser sign-in.
- **API key** (since 0.1.37). A key made on the build's own keys page
  (`https://www.workbuddy.cn/profile/keys` for `workbuddy`,
  `https://www.workbuddy.ai/profile/keys` for `workbuddy-ai`), sent as
  WorkBuddy's own CLI sends one: `X-API-Key` and `Authorization: Bearer`,
  both the key, and `X-User-Id: anonymous_<the key's last 8 characters>`,
  to the same API as the other sign-ins. A key isn't renewed; a refused one
  says to check it. A key's credits are unknown (WorkBuddy's own client reads
  none with a key), and its models are `/v3/config`'s only for `ck_`/`pt_`
  keys, as the CLI asks; any other key keeps the list below.

A browser sign-in is kept as an OpenCode `oauth` auth: the access and
refresh tokens, their expiry, the user id and the domain; desktop's as a
marker, `{"type": "oauth", "source": "desktop", "accountId", "uid"}`. OpenCode keeps it in
`auth.json`; magpie keeps it in `plugin-auth.json`. The access token is
refreshed a minute before it ends, and the new one is saved. If the refresh
fails, the old token is used while it lasts.

In magpie (0.1.684 or later) the plugin also gives `auth.refresh` with
`refreshLead` of 5 minutes: magpie renews a browser sign-in (an hour's
token) 5 minutes before it ends, once for the account, before its
requests, models and usage ask, and saves what it gives. It goes through
the same one-refresh-at-a-time as a request's refresh, so a refresh token
is never spent twice. A failed renewal, a refresh token past its end
included, doesn't mark the account, as the built-in never did; magpie
tries again later, and the old token is used meanwhile.
OpenCode doesn't call `auth.refresh`; the check before each request stays.

An enterprise (team) account is asked for as the enterprise. A browser
sign-in keeps the enterprise id WorkBuddy names for the account (from
`/login/account`, else its account list), and desktop's is read from the
app's file. Every request then carries `X-Enterprise-Id` and `X-Tenant-Id`,
as WorkBuddy's own client sends them; without them WorkBuddy answers as the
personal account, with the personal plan's models. A browser sign-in made
before 0.1.13 has no enterprise id kept: sign in again.

Which account a browser sign-in gives is chosen on WorkBuddy's own sign-in
page. After a phone sign-in it lists the person's accounts (personal, a
team, 「WorkBuddy 教育公益版」…) and binds the one picked to the sign-in, so
to add an education or team account, pick it there. Its account is named
with the enterprise too (`nickname · enterprise name`, or the end of the
enterprise id when WorkBuddy names none): one person's personal and
enterprise accounts share the uid and the nickname, and magpie keeps one
account per name and uid, so before 0.2.1 signing in to the enterprise
account replaced the personal one. An enterprise account signed in before
0.2.1 keeps its old name until its Sign in again, which renames it in
place; its free-model window, read from usage rows kept under the old
name, starts again from the new one.

Desktop's sign-in is refreshed only when the app hasn't refreshed it
itself, and the new token is kept in memory, never written back, as magpie's
built-in WorkBuddy does.

A chat or usage read WorkBuddy answers 401 (since 0.1.31) is renewed once,
whatever the token's time, and sent once more. A token another process
saved since is taken first instead of spending the refresh token again. A
desktop sign-in is never renewed for it: the app's file is read again, and
its token is used if the app signed in again. A 401 again, or no new
token, ends in a 401 that says to sign in again (Providers → WorkBuddy →
this account's Sign in again in magpie; WorkBuddy desktop for a desktop
sign-in). The plugin marks the account expired in magpie
(`X-Magpie-Sign-In: expired`, usage's `signIn`) only on WorkBuddy's word
that the sign-in is gone: the refresh token refused (401, `invalid_grant`),
or the access token refused (`WWW-Authenticate: … error="invalid_token"`)
with no refresh token left to renew it with or just after renewing. A
failed renewal for another reason, or a bare 401 without `invalid_token`,
leaves the account as it is; a desktop sign-in is never marked. A 401
after a renewal takes a mark off (`renewed`).

## Requests

Chats are chat completions (`@ai-sdk/openai-compatible`) at `<API>/chat/completions`.
They are streamed only; WorkBuddy refuses a chat that isn't.

**On WorkBuddy (China), the Claude models are served on Anthropic's Messages
API** instead: `@ai-sdk/anthropic` at `<endpoint>/v1/messages` (streamed only
as well). `claude-opus-5.5`, `claude-sonnet-5.5`, `claude-opus-5` and
`claude-opus-4.8-1m` answered there when each model of `/v3/config`'s `cli`
agent was asked on 2026-10-24; `glm-5.3` and `deepseek-v4.1-flash` answered
500, `gpt-5.5` and `kimi-k3-1` 400, so every other model stays on chat.
WorkBuddy AI has no such route (`/v1/messages` is `404 Route Not Found` there
for every model), so all its models stay on chat, a Claude one too.

A Messages request goes as the agent sent it: no default system message, no
`max_completion_tokens`/`developer` rewrites, no tool reshaping, and nothing
moved for a refused system prompt — Claude Code's own prompt is taken as it
is, billing line and all, where a chat answers 11128 to it. One thing is
left out: a `thinking` block with no `signature`. A conversation that began
on chat (or on another provider) carries such blocks, and once a signed one
from this route sits beside them WorkBuddy refuses the whole request, 11159
"Invalid `signature` in `thinking` block … bound to a different
conversation", on every try. Signed blocks go back as they came. It carries
WorkBuddy's headers as a chat does, the same conversation and turn ids
included: a tool result in a `user` message of `tool_result` blocks answers
the step before it, as a `role: "tool"` message does in a chat.

The point of the route is effort. A chat carries `reasoning_effort` alone,
and WorkBuddy's chat endpoint answers at about the same length whatever it
says: asked the same question four times each (2026-10-24,
`claude-opus-5.5`), the median answer was 3884 output tokens at `low`, 5144
at `max` and 5715 at a value that isn't a level at all. Messages carries
`output_config.effort`, and `max` is honored there: a median of 30850
against 5748 at `low`, same model and question, four runs each. A Claude
model on Messages therefore lists `max` in its levels even where
`/v3/config` stops at `xhigh`.

`/v1/messages/count_tokens` **is not served** (404). magpie treats a 404 on
count_tokens as "no counter" (`unsupportedCount`) and answers with its own
estimate.

Each chat carries WorkBuddy's headers:
- `Authorization`, `X-User-Id`, `X-Domain`, `X-Product: SaaS`, `X-IDE-Type: WorkBuddy`;
- the desktop CLI's `User-Agent`, `WorkBuddy/<app> <appName>/<app> CLI/<cli>`:
  `WorkBuddy/5.9.3 WorkBuddy/5.9.3 CLI/2.165.0` on the China build and
  `WorkBuddy/5.9.3 workbuddy-ai/5.9.3 CLI/2.165.0` on WorkBuddy AI, each
  build's current app on 2026-10-29; `X-IDE-Version` is the app's version.
  A User-Agent not starting `WorkBuddy/<version>` is answered error 10085;
- the client's, which WorkBuddy's usage list shows as the client that asked
  (使用端): `X-Agent-Purpose: conversation`, `X-IDE-Name: WorkBuddy`,
  `X-IDE-Version`, `X-Agent-Intent: craft`, `X-Requested-With`. Both builds
  send them, as WorkBuddy's own client does; a chat without them is counted
  under no client at all;
- the conversation's ids: `X-Conversation-ID`, `X-Conversation-Request-ID`,
  `X-Conversation-Message-ID`, `X-Request-ID`. WorkBuddy's backend counts a
  user send as one request by `X-Conversation-Request-ID`, so every step of
  one send — a tool result sent back, a retry — carries the same one, and
  the user's next message carries another. Both ids are one account's own,
  as WorkBuddy's client is signed in as one: a conversation sent as another
  account (another of a group, or a sign-in saved since) carries that
  account's ids, never the same ones under two `X-User-Id`s. The
  conversation's is the session magpie (or OpenCode) names the request by,
  else the chat's first user message; nothing is made up when neither names
  one, a made-up conversation of the request's own being what splits one
  conversation into many in the usage detail;
- what the CLI adds to a model request alone: `X-Agent-Type: main` on both
  builds, `X-Agent-Runtime: local-agent` (new in 5.9),
  `Accept: application/json`, and the `X-Stainless-*` headers of the OpenAI
  SDK it sends through (openai 6.25.0 on Electron 37's Node v22.21.1, a
  1200s timeout, no retries).

Not sent: `X-Device-Token`, which the desktop app gets from Tencent's
native device SDK before each prompt, and a `traceparent`, which the CLI
adds only while its server-side tracing is on.

A chat that doesn't open with a system message is given WorkBuddy's
default one, as the app does.

WorkBuddy refuses some agents' identity lines as an "unapproved channel"
(11128), so those lines are reworded before a chat goes out. Since 0.1.27
(#279) that includes DeepSeek Harness's opening line. Since 0.2.3 a refusal
of words not reworded yet is answered first by saying the same line with one
more comma — a vendor matches such a line whole and exactly, so the comma
passes it while the line still names the harness (measured 2026-10-30; a word
added after the product name did not pass, the comma did). The comma is set in
the system and assistant messages only — the two WorkBuddy reads — so the
user's own words and tools' results go out as they were sent. A system prompt
whose comma passed is remembered while the plugin is loaded, as a moved one
is, and its next chats go with the comma already in before the first send:
otherwise every turn, and every step of a tool loop, would pay the refusal
once. Only a chat refused still is sent once more, since 0.1.29, with the
system prompt moved into the first user message (inside `<instructions>` tags)
and WorkBuddy's default system prompt in its place: WorkBuddy checks only the
system and assistant messages, and the line it matched is then in neither. A system message later
in the chat becomes a user message where it stands. The plugin remembers each
refused system prompt while it is loaded, so that agent's next chats go moved
at once. The move can't reach an assistant message, so words the model quotes
back into one keep that chat refused until they are in the list reworded in
every message (since 0.1.30, the "Web GUI whose URL the runtime context names"
line, #291); otherwise only a new chat clears it. A refusal that stands after
the move ends in a hint that names no one client (since 0.1.28): WorkBuddy
refused words in this client's prompt; use it from Hermes, OpenCode or Pi, or
add another provider to the group. Since 0.2.3 that hint is preceded by the
address of [REFUSED.md](REFUSED.md), which says what the check reads, how a
line is reworded to pass it, and how to turn such a line off in an agent that
has a switch for it — so the error carries its own fix, for the person who
reads it or the agent they paste it to. Neither refusal rests the account.

The loader also translates OpenAI-compatible request spellings WorkBuddy
doesn't take: `max_completion_tokens` becomes `max_tokens`, `developer`
messages become `system`, an object `tool_choice` becomes WorkBuddy's
string form, and an earlier assistant turn's `reasoning_content` (or
`reasoning_details` text) goes as `reasoning`, the field WorkBuddy's own
client sends. WorkBuddy drops `reasoning_content`, so a client such as Grok
Build that sends it lost its earlier thinking; nothing is folded into the
message's content.

A chat's tools are given shapes WorkBuddy's models take. Without them
WorkBuddy AI answers 400 "Invalid request parameters" (11133), DeepSeek's
models to each shape below and Kimi's, GPT's, Gemini's and GLM's to some:
- a tool's parameters with no `type`, empty, or a union (`anyOf`, `oneOf`,
  `allOf`) at the root are an object, the union's fields merged;
- a `pattern`'s `\0` is `\u0000`, which matches the same;
- a tuple's `items` (a list) is one schema any of them fits;
- an `enum` with no `type` takes its values' type (or that and `"null"`),
  and an `enum` of several types is an `anyOf` of one typed `enum` for
  each, at any depth; an empty `enum` is left out (Kimi and DeepSeek, an
  MCP server's tools, #122);
- `true` and `false` where a schema goes are `{}` and `{"not": {}}`
  (`additionalProperties` is left); a `required` that isn't a list, and a
  `type` JSON Schema doesn't name, are left out, and `"String"` is
  `"string"`;
- a tool's name with a character other than letters, digits, `_` and `-`
  (`.`, `:`, `/`, a space, CJK) is sent with `_` there, and the model's
  calls come back under the tool's own name.

WorkBuddy AI's `gemini-3.8-flash` answers 400 "the conversation must end
with a user message" (11153) to a chat whose tool results are followed by
the user's message, as magpie sends Claude Code's reminders, words typed
mid-task and a tool's images. Such a chat goes again with an empty
assistant message between the results and the user's message, which it
serves; a model that refused it once gets it that way from then on, until
the plugin restarts. A chat ending with the assistant's message (a prefill)
is refused as before.

## Models

When you are signed in, the models are the ones WorkBuddy's product config
gives its CLI agent (`GET /v3/config`), with their context, image input and
reasoning levels. Until then, or if WorkBuddy doesn't answer, the list below
is used.

`workbuddy`:
- Auto
- Hy4 preview, Hy3, Hy3-X
- Deepseek-V4.1-Flash, Deepseek-V4-Pro
- GLM-5.3, GLM-5.3-Flash, GLM-5.2, GLM-5.1, GLM-5v-Turbo
- MiniMax-M3
- Kimi-K3, Kimi-K2.7-Code, Kimi-K2.6

`workbuddy-ai`:
- Default, Fast, Balanced, Primary, Deep
- GPT-5.5, GPT-5.4, GPT-5.3-Codex
- Gemini-3.1-Pro, Gemini-3.5-Flash
- GLM-5.3, GLM-5.2
- Hy3
- Kimi-K3, Kimi-K2.6
- MiniMax-M3

A model's reasoning levels are its variants (`reasoningEffort`). A chat
that names no level goes at the model's own default from the config
(`reasoning.defaultEffort`, "high" for DeepSeek-V4.1-Flash), as WorkBuddy's
client sends it: WorkBuddy doesn't think when a chat names none, so
OpenCode's default variant got answers without thinking. An effort the
client names, `none` too, goes as it came.

A chat goes gzipped (`Content-Encoding: gzip`), as WorkBuddy's own client
sends its model requests (`RequestBodyGzip` in both builds' product.json).
Claude's Messages route goes as it came, and so does anything that isn't a
chat completion: magpie's drawings (`/v2/images/generations`,
`/v2/images/edits`) go as plain JSON, which is all the images API reads.

A model's price is its `credits` ("x0.29") and the config's
`modelPromotions`. A discount for whole days (Step-5-Preview's 独家限免) is
the price now, with the price before it (`rateWas`). A price that holds only
some hours of the day (Hy4 preview, free 23:00–8:00) is given as its full
price, never as free: magpie keeps the list until it asks again, so a list
asked for at night would say "free" all day (#121).

### Free models only

Each site (WorkBuddy, WorkBuddy AI) has a "Free models only" switch in its
provider settings in magpie, off by default (#430). When it is on:

- the list holds only the models the site serves at no cost now. A model free
  only at night, or one with no price, counts as paid;
- a request for any other model is answered by the plugin with a 404
  `model_not_found` and never sent, so no credits are spent. magpie rests
  only that model and tries the next provider;
- if the price list can't be read, nothing is sent (503), since whether the
  model is free is unknown. An API key WorkBuddy lists no prices for lists
  no models.

The price list is read again at most once a minute for requests.

## Credits in magpie

magpie's usage card shows the account's credits from the resource summary.
It also says when the soonest credits left run out (`runsOutAt`, and how
many: `runsOut`), from the paid and free package lists WorkBuddy's own
client reads. The daily Free Plan slice isn't counted: it ends at the same
midnight on every account. magpie's smart routing spends the account whose
credits run out first.

An enterprise (team) account's resource summary lists no packages. Its
credits are read from the enterprise meter
(`/billing/meter/get-enterprise-user-usage`), the one WorkBuddy's own usage
page reads: the cycle's credits used of its limit, and when the cycle
resets (magpie #1904).

## The free model's daily window (WorkBuddy AI)

The credits above are not the only limit. `deepseek-v4.1-flash` is served at
`x0.00` and costs the plan nothing, yet WorkBuddy AI refuses it long before
160 credits are touched:

```
429 usage exceeds frequency limit, but don't worry, your usage will reset at
2026-10-20 19:47:41 UTC+8, alternatively, you can switch to the other models
to continue using it.
```

That is a token allowance of its own — per account, per 24 hours, about 1e8
tokens, counted as prompt + cache-read + completion. Nothing the vendor
answers with reports it, so the plugin rebuilds the current window from
magpie's `usage.jsonl` and gives it to the card as **Free model tokens**
beside **Credits**. `quota alert` and `magpie quota` show it too; before,
the card read 0% on an account that was already refused.

What is measured, and what is easy to read wrongly:

- **`cache_read` counts.** Prompt and completion alone are 20× smaller and
  never approach the cap, so a window read that way looks empty while full.
- **The window is fixed, not sliding.** It runs 24 hours from the first
  request answered after the previous window ended, not from the reset
  instant; a gap between the two means the new window starts later.
- **`deepseek-v4.1-flash-sg` shares the window.** It is the paid id of the
  same model (`ModelRateLimitCap` in the product config), not a second
  allowance — switching to it continues the same window, at `x0.03`.
- **1e8 is an estimate within 0.2%.** The largest value seen to still be
  answered is 100,183,315, and the next request is refused, so it cannot be
  probed higher.
- **A refusal is exact, and the sum is not.** The ledger is this machine's
  only: one window was refused at 92,792,962 because the rest of that
  account's spending happened on another machine, which read as 93%. So a
  429 whose named reset is still ahead makes the window full — `used: 100`,
  `resetsAt` the reset the vendor named — whatever the rows add up to. The
  sum carries the window only until the first refusal.
- **The card names both ids**, `deepseek-v4.1-flash` and
  `deepseek-v4.1-flash-sg`: magpie matches a window's models by exact id
  (only an `@size` suffix folds into the bare id), so one alone would leave
  the other unrestricted.
- **The ledger is read in magpie's own folder** (`appdir.Config()`: the
  portable data folder, `$XDG_CONFIG_HOME/magpie` when that is set (an
  absolute path, as `appdir.rooted` has it), or `~/.config/magpie`), from its
  end backwards — a heavy ledger runs to hundreds of MB.
  - The window is a chain, so where it now began depends on every window
    before it: read a slice of the ledger that starts mid-chain and every
    window after it is shifted (4% on an account two hours from its cap, or
    100% on one still served). The read therefore goes back until it reaches
    an edge this account's own rows spell out — a refusal whose reset can be
    read, or a gap of a day between two of its answered rows — plus a day
    below that, and with neither it reads to the file's start, where there is
    no earlier window to be shifted by.
  - Nothing bounds that by age, so two things keep a heavy ledger cheap: a
    line's time is read before the line is decoded, so a line under the edge
    (of any provider or account) ends the read at once; and a read past 24h
    with no answered free-model row of this account stops, since the window
    has lapsed and nothing would be reported. Both bounds leave out a line
    a client reported (`"source":"reported"`, #1874): magpie appends those
    dated where the client's call happened, so a backfilled row says nothing
    about where the file has got to.
  - `providerAccount` is the account's label. Two accounts sharing a label
    get its slot added (`pluginLabels`), the label no longer matches what
    their rows were written under, and the card reports no free window.
- **The offset comes from the refusal's words** (`UTC+8`, `GMT-5`,
  `UTC+05:30`). A reset whose offset cannot be read is no edge at all,
  rather than +08:00 guessed.

A window that has lapsed reports nothing rather than 0%: nothing is
exhausted, and the next request opens a fresh one. The China build is not
covered; its limit has not been measured.

## When free models work but a credit model does not

Check the failing account and model separately before concluding that the
wallet is empty:

- Use the exact API id from the account's model list. For example,
  `glm-5.3-flash` is the id; `GLM-5.3-Flash` is its display name. A route
  copied from another provider need not be a valid WorkBuddy model id.
- The WorkBuddy 5.6+ encrypted-desktop message means this sign-in cannot
  be read, not that the account has zero credits. Use **Account (browser)**
  for the same build/region. Keep the old entry until the new identity and
  model list are confirmed. The desktop file is not decrypted or changed.
- An account restricted by WorkBuddy is a different failure. Code 11140
  with its unusual-activity message calls for **Submit feedback** in
  WorkBuddy; signing in repeatedly or changing the model does not lift it.
  See [magpie#1849](https://github.com/yetone/magpie/issues/1849).
- Inspect each attempted provider/account in magpie's routing details.
  A ZCode trial quota failure, another provider's insufficient credits, or
  one account's restriction is not the balance of every WorkBuddy account.

A model response confirms that the selected account can answer. It does
not, without a matching vendor usage record, prove how many credits that
request deducted. A usage-read error means the balance is unknown.

The encrypted-desktop result can be reproduced without an account using
`packages/workbuddy/usage.test.mjs` in an isolated temporary HOME (and
USERPROFILE on Windows). It covers sign-in, usage and chat against a
synthetic sealed desktop file, and checks that the file stays unchanged.
A successful browser authorization alone is not a migration: compare the
returned identity with the intended desktop account before replacing its
entry. An already signed-in browser can simply renew another saved account.


## Not here

magpie's built-in WorkBuddy does more than this package: several accounts
under one provider.

OpenCode's plugin API has no place for these.

Credit multipliers accept the international catalog's `x0.34 credits` text as well as `x0.34`. An empty credits value (for example Auto) stays unknown, never free.

## Daily check-in

The account's daily credits are claimed through the billing meter. magpie
can run it once a day per account when its WorkBuddy check-in switch is on;
Settings → Usage → Plugins has that switch and a *Check in now* button.
The activity status is read first: inactive is `inactive`, a day already
checked in is `done`, and only an active unchecked day is claimed. A claim
that WorkBuddy answers 1001, 1002 or 1003 is `done`, `ineligible` or
`inactive`. A claim turned away 401 while the account's credits still read
is `ineligible`: that check-in takes WorkBuddy's own app. A transient
billing failure is retried twice before the card shows the failure.
Only WorkBuddy (China) checks in: the AI build has no claim endpoint, and
its plugin carries no check-in hook.
A request that gets no answer at all leaves the hook as a thrown error, so
magpie retries it on its 1-minute offline backoff rather than the 30-minute
one it gives a failed answer (#149).

An `inactive` answer is kept for the whole Beijing day: the plugin host
gives it no recheck, and a manual refresh reads the kept one (tracked in
[yetone/magpie#2696](https://github.com/yetone/magpie/issues/2696)).
