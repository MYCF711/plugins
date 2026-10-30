// @magpie-community/opencode-loomy-auth — the Loomy (讯飞) provider plugin
// for OpenCode and magpie.
//
// Signs in with a Loomy account (SMS code or a pasted session), forwards
// chat completions to its OpenAI-compatible model gateway, lists its models,
// reads its two point wallets, and presses its daily first-login grant (the
// 每日赠送积分 refresh). Request shapes are ported from aimod-cc/agent2api
// (MIT), providers/loomy, rewritten for magpie's plugin API.

import { createHash, createHmac, randomUUID } from "node:crypto"

const ID = "loomy"
const NAME = "Loomy（讯飞）"

// the three planes (agent2api endpoints.rs; env-overridable the same way)
const env = (name, fallback) => {
  const v = process.env[name]?.trim()
  return v ? v.replace(/\/+$/, "") : fallback
}
const integrationBase = () => env("LOOMY_POINTS_BASE_URL", "https://loomyad.xunfei.cn")
// the account host is the Loomy client's own CAccount domain: it comes from
// the install package's encrypted .env.prod (VITE_XFYUN_BASE_URL, unpacked
// from app.asar with the client's own env-file-crypto.js) — xfinfr.com is
// xfyun's account infrastructure, not a third-party host (reference
// endpoints.rs, itself sourced from the installed client)
const xfyunBase = () => env("LOOMY_XFYUN_BASE_URL", "https://account.xfinfr.com")
const accessKeyId = () => env("LOOMY_XFYUN_ACCESS_KEY_ID", "2thryby66wxi53sk")
const accessKeySecret = () => env("LOOMY_XFYUN_ACCESS_KEY_SECRET", "zsak6eadrbawz683wf5r3m2snrwj868r")
const appId = () => env("LOOMY_XFYUN_APP_ID", "GM3LOOMY")
const modelBase = () => `${integrationBase()}/api/v1`

// business codes (agent2api client.rs): 000000 ok; 020002/100002 sign-in gone
const OK = "000000"
const AUTH_CODES = new Set(["020002", "100002"])

const REQUEST_TIMEOUT = 20_000


// the chat models the live /api/v1/models returned on 2026-10-16 (the image
// models are served through the same gateway too, but only chat models
// register as provider models). The live list replaces or extends this —
// entries here only make the picker usable before the first sign-in.
const STATIC_MODELS = {
  "DeepSeek-V4.1-Flash": { name: "DeepSeek V4.1 Flash (x2.0)", limit: { context: 1_048_576, output: 384_000 } },
  "deepseek-v4-flash-0731": { name: "DeepSeek V4 Flash 0731 (x3.0)", limit: { context: 1_048_576, output: 384_000 } },
  "MiniMax-M3": { name: "MiniMax M3 (x4.0)", limit: { context: 1_048_576, output: 512_000 } },
  "Kimi-k2.6": { name: "Kimi k2.6 (x6.5)", limit: { context: 262_144, output: 65_536 } },
  "qwen-3.8-max": { name: "Qwen 3.8 Max (x12.0)", limit: { context: 1_000_000, output: 65_536 } },
  "GLM-5.3-Flash": { name: "GLM 5.3 Flash (x0.8)", limit: { context: 1_048_576, output: 131_072 } },
  "qwen3.8-flash": { name: "qwen 3.8 flash (x0.8)", limit: { context: 1_000_000, output: 131_072 } },
  "spark-x": { name: "Spark-X2.5 (限时免费) (x0.0)", limit: { context: 1_048_576, output: 65_536 } },
  "mimo-v2.5": { name: "MiMo V2.5 (x3.3)", limit: { context: 1_048_576, output: 131_072 } },
  auto: { name: "自动 · 均衡" },
}

// the client's _makeBase() envelope for the account domain
const makeBase = () => ({
  appid: appId(),
  modelid: "Web",
  version: "1.0.0",
  devid: "web",
  ua: "Loomy|Desktop|Electron|macOS",
  traceid: [...createHash("md5").update(randomUUID()).digest().slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join(""),
})

// ── small helpers ──────────────────────────────────────────────────────────

const toNum = (v) => {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() ? Number(v) : NaN
  return Number.isFinite(n) ? n : null
}
const codeOf = (payload) => String(payload?.code ?? "").trim()
const messageOf = (payload) => String(payload?.desc ?? payload?.message ?? "").trim()

const beijingMidnight = () => Math.floor((Date.now() + 8 * 3600e3) / 86400e3) * 86400e3 + 86400e3 - 8 * 3600e3

class SignedOut extends Error {}
const expired = (message) => Object.assign(new Error(message), { signIn: "expired" })

const errorResponse = (status, message) =>
  new Response(JSON.stringify({ error: { message } }), { status, headers: { "content-type": "application/json" } })

/**
 * 「内容太长了，请精简输入或开启新对话」 covers two very different situations:
 * the request really is bigger than the model's window, and the upstream is
 * merely busy. Neither wording names 「上下文」, so magpie's `tooLongRe`
 * (`internal/gateway/gateway.go`) does not match it: the try is filed as an
 * error that rests the account, the group's other members are never asked, and
 * the whole turn fails.
 *
 * The request itself tells the two apart, so classify by size instead of
 * trusting the wording:
 *
 *   · far below the declared window ⇒ not a length problem ⇒ 502, which magpie
 *     retries on another account in seconds
 *   · otherwise ⇒ rewrite to a wording `tooLongRe` knows, so the agent
 *     compacts instead of the turn failing
 *
 * Measured 2026-10-30: an 838,400-token request succeeded while a 373,924-token
 * one was refused this way, and the same window carried `429 模型服务当前繁忙`.
 *
 * ⚠ History: the 502 branch was removed on review. A fixed character threshold
 * knows nothing about the model's own window (Kimi-k2.6 is 262,144 tokens, but
 * 1.5M ASCII characters is already ~375k tokens), so it reported genuine
 * over-length requests as upstream failures — magpie then retried every account
 * and the turn ended in 502. This version only rewrites the wording; it never
 * changes the status.
 */
const TOO_LONG_SAID = /内容太长(了)?|内容过长/
const TOO_LONG_REWORDED = "上下文超出长度限制"

function retryableRefusal(status, body) {
  if (status !== 400 && status !== 413 && status !== 422) return null
  if (!TOO_LONG_SAID.test(body)) return null
  return new Response(body.replace(TOO_LONG_SAID, TOO_LONG_REWORDED), {
    status,
    headers: { "content-type": "application/json", "x-loomy-vendor-status": String(status) },
  })
}

async function bodyText(input, init) {
  const b = init.body ?? (input instanceof Request ? await input.clone().text() : undefined)
  return typeof b === "string" ? b : new TextDecoder().decode(b)
}

// ── the account domain's HMAC-SHA1 signature (agent2api sign.rs, itself a
// copy of the client's electron/xfyun/sign.js). Nine parts, \n-joined; the
// last two (signed headers, canonicalized headers) are always empty here.
// This is client-fingerprint reproduction, not a security boundary.

function escapeSegment(segment) {
  return encodeURIComponent(segment).replace(/[!'()*]/g, (ch) => "%" + ch.charCodeAt(0).toString(16).toUpperCase())
}
function escapedPath(path) {
  let clean = path.startsWith("/") ? path : `/${path}`
  if (clean.length > 1 && clean.endsWith("/")) clean = clean.slice(0, -1)
  return clean.split("/").map(escapeSegment).join("/")
}
function contentMD5(bodyString) {
  if (!bodyString) return ""
  return createHash("md5").update(bodyString).digest("base64")
}
function utcDateString() {
  return new Date().toUTCString()
}
function signHeaders(method, path, bodyString) {
  const md5 = contentMD5(bodyString)
  const date = utcDateString()
  const nonce = randomUUID() // with hyphens, as the client signs it
  const stringToSign = [method.toUpperCase(), escapedPath(path), "", md5, "application/json", date, nonce, "", ""].join("\n")
  const signature = createHmac("sha1", accessKeySecret()).update(stringToSign).digest("base64")
  const headers = {
    Authorization: `account ${accessKeyId()}:${signature}`,
    Date: date,
    Nonce: nonce,
    "Content-Type": "application/json",
  }
  if (md5) headers["Content-MD5"] = md5
  return headers
}

// one signed POST on the account domain (the login chain); the signature
// must cover the exact bytes sent, so the body is serialized once here
async function signedPost(pathname, body) {
  const bodyString = JSON.stringify(body)
  const res = await fetch(xfyunBase() + pathname, {
    method: "POST",
    headers: signHeaders("POST", pathname, bodyString),
    body: bodyString,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT),
  })
  const payload = await res.json().catch(() => null)
  if (!payload) throw new Error(`Loomy 账号接口返回了无法解析的内容（HTTP ${res.status}）`)
  if (!res.ok) throw new Error(`Loomy 账号接口返回 HTTP ${res.status}: ${messageOf(payload)}`)
  return payload
}

// one request on the integration gateway with the session's double headers
// (the model and points gateways prefer different header names; the client
// sends both, and so does this)
async function tokenRequest(method, path, session, body) {
  if (!session?.trim()) throw new SignedOut("Loomy 账号缺少 session")
  const init = {
    method,
    headers: { token: session, Authorization: `Bearer ${session}` },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT),
  }
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json"
    init.body = JSON.stringify(body)
  }
  const res = await fetch(integrationBase() + path, init)
  if (res.status === 401 || res.status === 403) throw expired("Loomy 登录态已失效，请重新登录")
  const payload = await res.json().catch(() => null)
  if (!res.ok) throw new Error(`Loomy 接口返回 HTTP ${res.status}`)
  if (!payload) throw new Error("Loomy 接口返回了无法解析的内容")
  return payload
}


// the phone number as the client normalizes it (agent2api login.rs)
function normalizePhone(raw) {
  const trimmed = String(raw ?? "").replace(/[\s-]/g, "")
  let digits = trimmed.replace(/^\+86/, "")
  if (digits.length === 13 && digits.startsWith("86")) digits = digits.slice(2)
  if (/^1[3-9]\d{9}$/.test(digits)) return digits
  return null
}

// ── chat body adaptation ───────────────────────────────────────────────────

// the thinking levels Loomy's client offers are low/medium/high; a wider
// level the agent asked is folded into them, off/none and unknowns are left
// off (agent2api mod.rs reasoning_patch)
function foldReasoning(body) {
  let changed = false
  const of = (v) => {
    if (v === "minimal" || v === "low") return "low"
    if (v === "medium") return "medium"
    if (v === "high" || v === "max") return "high"
    return null
  }
  if (typeof body.reasoning_effort === "string") {
    const folded = of(body.reasoning_effort)
    if (folded !== body.reasoning_effort) {
      if (folded) body.reasoning_effort = folded
      else delete body.reasoning_effort
      changed = true
    }
  }
  if (body.reasoning && typeof body.reasoning === "object" && typeof body.reasoning.effort === "string") {
    const folded = of(body.reasoning.effort)
    if (folded !== body.reasoning.effort) {
      if (folded) body.reasoning.effort = folded
      else delete body.reasoning.effort
      changed = true
    }
  }
  return changed
}

// deepseek models on Loomy read images only as <image_base64> markers, not
// OpenAI image_url parts; data-URI images are turned into the marker and
// merged into the text before them (agent2api images.rs)
function prefersTagFormat(model) {
  return String(model ?? "").toLowerCase().includes("deepseek")
}
function toTagText(part) {
  const kind = String(part?.type ?? "").trim().toLowerCase()
  if (kind !== "image_url" && kind !== "input_image") return null
  const url = typeof part.image_url === "string" ? part.image_url : part.image_url?.url
  if (typeof url !== "string" || !url.startsWith("data:")) return null
  return `<image_base64>${url}</image_base64>`
}
function rewriteImagesToTags(body) {
  let converted = 0
  for (const message of body.messages ?? []) {
    if (!Array.isArray(message.content)) continue
    for (let i = message.content.length - 1; i >= 0; i--) {
      const tag = toTagText(message.content[i])
      if (!tag) continue
      message.content.splice(i, 1)
      const prev = i > 0 && message.content[i - 1]?.type === "text" ? message.content[i - 1] : null
      if (prev) prev.text += `\n${tag}`
      else if (message.content[i]?.type === "text") message.content[i].text = `${tag}\n${message.content[i].text}`
      else message.content.splice(i, 0, { type: "text", text: tag })
      converted++
    }
  }
  return converted
}

// the vendor's /models: OpenAI-shaped entries whose capabilities say what a
// model does, and whose display name ends in its point rate "(x3.0)"
// (agent2api models.rs)
function splitRateSuffix(name) {
  const trimmed = String(name ?? "").trimEnd()
  for (const [close, open] of [
    [")", "("],
    ["）", "（"],
  ]) {
    if (!trimmed.endsWith(close)) continue
    const body = trimmed.slice(0, -1)
    const at = body.lastIndexOf(open)
    if (at < 0) continue
    const inner = body.slice(at + 1).trim()
    if (!/^x\d+(\.\d+)?$/i.test(inner)) return { name: trimmed, rate: undefined }
    const bare = body.slice(0, at).trimEnd()
    return { name: bare || trimmed, rate: inner.toLowerCase() }
  }
  return { name: trimmed, rate: undefined }
}
function catalogModel(entry) {
  const id = String(entry?.id ?? "").trim()
  if (!id) return null
  const caps = entry?.capabilities ?? {}
  const { name, rate } = splitRateSuffix(entry?.name ?? entry?.display_name ?? id)
  const config = { name: name || id }
  const limit = {}
  const context = toNum(entry?.context_window ?? entry?.context_length ?? entry?.limit?.context)
  const output = toNum(entry?.max_tokens ?? entry?.limit?.output)
  if (context != null) limit.context = context
  if (output != null) limit.output = output
  if (Object.keys(limit).length) config.limit = limit
  if (caps.reasoning) config.reasoning = true
  if (caps.function_calling) config.tool_call = true
  if (caps.vision) config.modalities = { input: ["text", "image"], output: ["text"] }
  if (rate) config.rate = rate
  return { id, config }
}

// ── the plugin ─────────────────────────────────────────────────────────────

export async function LoomyAuthPlugin({ client } = {}) {
  const methods = []

  methods.push({
    type: "oauth",
    label: "短信验证码登录（SMS sign-in）",
    prompts: [{ type: "text", key: "phone", message: "手机号（中国大陆 11 位）", validate: (v) => (normalizePhone(v) ? undefined : "请填写 11 位中国大陆手机号") }],
    authorize: async (inputs) => {
      const phone = normalizePhone(inputs?.phone)
      if (!phone) return { type: "failed", error: "请填写 11 位中国大陆手机号" }
      // send the code now; the code the user pastes next completes it
      let msgid
      try {
        const sent = await signedPost("/login/phone/sendMsgCode", { base: makeBase(), param: { ccode: "86", phone, expire: 300 } })
        if (codeOf(sent) !== OK) return { type: "failed", error: `验证码发送失败：${messageOf(sent) || `code=${codeOf(sent)}`}` }
        msgid = sent?.data?.msgid
        if (!msgid) return { type: "failed", error: "验证码发送成功但上游没有返回 msgid" }
      } catch (e) {
        return { type: "failed", error: String(e?.message ?? e) }
      }
      return {
        url: "",
        instructions: `验证码已发送到 ${phone.slice(0, 3)}****${phone.slice(-4)}，请输入收到的 6 位验证码。`,
        method: "code",
        callback: async (code) => {
          const mcode = String(code ?? "").trim()
          if (!/^\d{6}$/.test(mcode)) return { type: "failed", error: "请输入 6 位数字验证码" }
          try {
            const answer = await signedPost("/login/phone/checkCode", {
              base: makeBase(),
              param: { ccode: "86", phone, mcode, msgid, expire: 1209600 },
            })
            if (AUTH_CODES.has(codeOf(answer)))
              return { type: "failed", error: "登录失败：登录态已失效，请重新获取验证码" }
            if (codeOf(answer) !== OK) return { type: "failed", error: `登录失败：${messageOf(answer) || `code=${codeOf(answer)}`}` }
            const session = String(answer?.data?.session ?? "").trim()
            if (!session) return { type: "failed", error: "登录成功但上游没有返回 session" }
            return {
              type: "success",
              refresh: "",
              access: session,
              expires: Date.now() + 14 * 86400e3, // the session the client asks for is 14 days
              accountId: `${phone.slice(0, 3)}****${phone.slice(-4)}`,
              userId: String(answer?.data?.userid ?? ""),
              source: "sms",
            }
          } catch (e) {
            return { type: "failed", error: String(e?.message ?? e) }
          }
        },
      }
    },
  })
  methods.push({
    type: "oauth",
    label: "手动粘贴 session（Paste token）",
    prompts: [{ type: "text", key: "session", message: "session（token 头的值，14 天有效）", validate: (v) => (v && v.trim() ? undefined : "必填") }],
    // an oauth authorize() hands back {url, method, instructions, callback}
    // and the host finishes the sign-in by calling callback() — returning
    // the account directly leaves the host on a callback that doesn't exist
    authorize: async (inputs) => {
      const session = String(inputs?.session ?? "").trim()
      if (!session) return { type: "failed", error: "session 必填" }
      return {
        url: "",
        instructions: "已取到粘贴的 session，确认即完成登录。",
        method: "auto",
        callback: async () => ({ type: "success", refresh: "", access: session, expires: 0, accountId: "手动粘贴", source: "manual" }),
      }
    },
  })

  return {
    auth: {
      provider: ID,
      // Loomy has no renewal: a session lives 14 days, and its end is
      // refreshed only by signing in again (SMS or import)
      async loader(getAuth) {
        const a = await getAuth()
        if (a?.type !== "oauth") return {}
        return {
          baseURL: modelBase(),
          apiKey: "loomy",
          async fetch(input, init = {}) {
            const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
            if (!/\/chat\/completions$/.test(new URL(url).pathname))
              return errorResponse(404, "only chat completions are served")
            let chat
            try {
              chat = JSON.parse(await bodyText(input, init))
            } catch {
              return errorResponse(400, "a request that isn't JSON")
            }
            const session = (await getAuth())?.access ?? a.access
            if (!session) return errorResponse(401, "Loomy 登录态缺失，请重新登录")

            // the body as Loomy's own client writes it: reasoning folded to
            // its three levels, and deepseek's images as base64 markers
            try {
              foldReasoning(chat)
              if (prefersTagFormat(chat.model)) rewriteImagesToTags(chat)
            } catch {}
            let res
            try {
              res = await fetch(`${modelBase()}/chat/completions`, {
                method: "POST",
                headers: {
                  // charset=utf-8 is load-bearing: without it the upstream
                  // reads the body as GBK and CJK text arrives corrupted
                  "Content-Type": "application/json;charset=utf-8",
                  Accept: "text/event-stream",
                  token: session,
                  Authorization: `Bearer ${session}`,
                },
                body: JSON.stringify(chat),
                signal: init.signal,
              })
            } catch (e) {
              return errorResponse(502, e?.message ?? String(e))
            }
            if (res.status === 401 || res.status === 403) return errorResponse(401, "Loomy 登录态已失效，请重新登录")
            if (!res.ok) {
              const raw = await res.text().catch(() => "")
              const refusal = retryableRefusal(res.status, raw)
              if (refusal) return refusal
              return errorResponse(res.status, `Loomy 上游返回 ${res.status}: ${raw.slice(0, 4096) || "无错误说明"}`)
            }
            // the answer streams through as it came (OpenAI-shaped)
            return res
          },
        }
      },
      async usage(getAuth) {
        try {
          const a = await getAuth()
          if (a?.type !== "oauth") return { error: "not signed in", signIn: "kept" }
          const payload = await tokenRequest("GET", "/api/v2/points/records?pageNo=1&pageSize=1&direction=debit&granularity=chat", a.access)
          const code = codeOf(payload)
          if (AUTH_CODES.has(code)) return { error: "Loomy 登录态已失效，请重新登录", signIn: "expired" }
          if (code !== OK) return { error: `积分查询失败：${messageOf(payload) || `code=${code}`}`, signIn: "kept" }
          const data = payload?.data?.data ?? payload?.data ?? {}
          const daily = toNum(data.dailyBalance)
          const permanent = toNum(data.balance)
          // this endpoint is a records list, so a reply without the balance
          // fields is a realistic case — "unknown" must not read as a
          // confident zero
          const pairPresent = toNum(data.dailyLimitPoints) != null && toNum(data.dailyRemainingPoints) != null
          if (daily == null && permanent == null && !pairPresent)
            return { error: `积分响应没有返回余额字段（${JSON.stringify(data).slice(0, 120)}）`, signIn: "kept" }
          // the daily wallet from the vendor's own numbers: spent is
          // dailyLimitPoints - dailyRemainingPoints. When the pair is absent
          // the wallet is an amount with no limit — a made-up limit would
          // always read as full
          const dailyLimit = toNum(data.dailyLimitPoints)
          const dailyRemaining = toNum(data.dailyRemainingPoints)

          // the daily wallet shows from whichever numbers came back: the
          // limit/remaining pair alone is enough (remaining IS its number);
          // with only dailyBalance it is an amount without a limit; with
          // neither, no daily wallet at all — a missing one is not 0
          const dailyWallet =
            dailyLimit != null && dailyRemaining != null
              ? { name: "每日赠送积分", used: Math.max(0, dailyLimit - dailyRemaining), amount: dailyRemaining, limit: dailyLimit, unit: "credits", resetsAt: beijingMidnight(), span: 86400 }
              : daily != null
                ? { name: "每日赠送积分", used: 0, display: `${daily} credits`, aside: true }
                : null
          const windows = [
            ...(dailyWallet ? [dailyWallet] : []),
            ...(permanent != null ? [{ name: "永久积分", used: 0, display: `${permanent} credits`, aside: true }] : []),
          ]
          // no `signIn` on a clean read: that absence is how magpie takes an
          // expired mark back off the account (Loomy has no renewal, so a
          // "kept" here would leave a transient 401's lapse on forever)
          return { plan: NAME, user: a.name || a.accountId, windows }
        } catch (e) {
          return { error: String(e?.message ?? e), signIn: e?.signIn === "expired" ? "expired" : "kept" }
        }
      },
      // the daily grant: the first login of the vendor's day refreshes the
      // daily wallet; the same call pressed here keeps it refreshed for an
      // account that isn't logging in (agent2api checkin.rs). The endpoint
      // answers success whether it granted or not, so claimed vs done is
      // decided by the daily balance around the call: up means the day's
      // grant landed, flat means it was already in (or carries no daily
      // wallet) — "done", with the refreshed balance in the message either way
      async checkin(getAuth) {
        const a = await getAuth()
        if (a?.type !== "oauth" || !a.access) throw new SignedOut("Loomy：未登录")
        const readDaily = async () => {
          const rec = await tokenRequest("GET", "/api/v2/points/records?pageNo=1&pageSize=1&direction=debit&granularity=chat", a.access)
          return toNum(rec?.data?.data?.dailyBalance ?? rec?.data?.dailyBalance)
        }
        let before
        try {
          before = await readDaily()
        } catch (e) {
          if (e?.signIn === "expired" || e instanceof SignedOut) throw expired("Loomy 登录态已失效，无法刷新每日积分（请重新登录）")
          // without the pre-read there is no honest claimed/done verdict —
          // say failed with the reason rather than "already done"
          return { outcome: "failed", message: `无法读取签到前余额，未执行每日刷新：${e?.message ?? e}` }
        }
        let payload
        try {
          payload = await tokenRequest("POST", "/api/v1/points/first-login", a.access, {})
        } catch (e) {
          if (e?.signIn === "expired" || e instanceof SignedOut) throw expired("Loomy 登录态已失效，无法刷新每日积分（请重新登录）")
          return { outcome: "failed", message: `每日积分刷新失败：${e?.message ?? e}` }
        }
        const code = codeOf(payload)
        if (AUTH_CODES.has(code)) throw expired("Loomy 登录态已失效，无法刷新每日积分（请重新登录）")
        if (code !== OK) return { outcome: "failed", message: `每日积分刷新失败：${messageOf(payload) || `code=${code}`}` }
        const after = toNum(payload?.data?.dailyBalance ?? payload?.data?.data?.dailyBalance) ?? (await readDaily().catch(() => null))
        const dailyMsg = after != null ? `每日赠送积分已刷新（当前 ${after}）` : "每日赠送积分已刷新"
        if (before != null && after != null && after > before) return { outcome: "claimed", credit: after - before, message: `${dailyMsg}；今日首登奖励 +${after - before}` }
        return { outcome: "done", message: dailyMsg }
      },
      methods,
    },
    async config(config) {
      config.provider ??= {}
      const was = config.provider[ID] ?? {}
      // the static table (captured from the live endpoint) keeps the picker
      // usable before the first sign-in; the models hook extends it from
      // /api/v1/models once signed in
      config.provider[ID] = {
        name: NAME,
        npm: "@ai-sdk/openai-compatible",
        api: modelBase(),
        ...was,
        models: { ...STATIC_MODELS, ...(was.models ?? {}) },
      }
    },
    provider: {
      id: ID,
      async models(p, { auth } = {}) {
        if (auth?.type !== "oauth" || !auth.access) return p.models
        try {
          const payload = await tokenRequest("GET", "/api/v1/models", auth.access)
          if (codeOf(payload) && codeOf(payload) !== OK) return p.models
          const entries = Array.isArray(payload?.data) ? payload.data : []
          for (const entry of entries) {
            const m = catalogModel(entry)
            if (!m) continue
            p.models[m.id] = m.config
          }
          return p.models
        } catch {
          return p.models
        }
      },
    },
  }
}

// for tests
export const _internal = {
  retryableRefusal,
  ID,
  NAME,
  STATIC_MODELS,
  signHeaders,
  escapedPath,
  contentMD5,
  foldReasoning,
  prefersTagFormat,
  rewriteImagesToTags,
  splitRateSuffix,
  catalogModel,
  normalizePhone,
  makeBase,
  toNum,
  beijingMidnight,
}
