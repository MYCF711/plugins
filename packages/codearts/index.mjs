// CodeArts (华为云码道 代码智能体) as a magpie / OpenCode provider plugin.
//
// CodeArts, Huawei Cloud's coding agent (码道), serves its models over an
// OpenAI-compatible Chat Completions API at
// https://snap-access.cn-north-4.myhuaweicloud.com/api/v2 — but unlike a plain
// OpenAI-compatible provider it does NOT take an API key. Requests are signed
// with临时 AK/SK/security-token credentials using Huawei's SDK-HMAC-SHA256
// scheme, and those credentials are obtained by signing in to Huawei Cloud
// with OAuth.
//
// This plugin implements exactly that flow, mirroring the real CodeArts agent
// (and the `Ebony-Vinyl/dsh-our-free-model` CodeArts channel, which this plugin
// is modelled on):
//
//   1. `auth.methods[0]` is `{ type: "oauth" }`. `authorize()` starts a
//      loopback callback server on 127.0.0.1 (port >= 10000), returns the
//      Huawei Cloud portal URL for magpie to open, and completes with the
//      credentials once the browser is redirected back with an auth code.
//   2. The sign-in is PKCE: a random code_verifier is sent to the STS token
//      endpoint together with the code and the S256 challenge's pre-image. It
//      is also a DPoP flow: a fresh ES256 (P-256) key pair signs each token
//      request, and the private key JWK is persisted so refresh requests can
//      sign with it too.
//   3. STS answers with rotating AK/SK/security-token credentials plus a
//      refresh_token. The whole credential (including the verifier and DPoP
//      key) is stored as JSON in the account's `access` field.
//   4. `auth.refresh` silently renews before expiry via `grant_type =
//      refresh_token`; the same verifier and DPoP key are reused.
//   5. Every model request is signed with SDK-HMAC-SHA256 in the loader's
//      `fetch`, and the account's live model list + quota are read from
//      signed GETs.
//   6. The gateway caps an account at 3 concurrent sessions (`TM.00001041`).
//      Each account keeps one stable session id (`x-ot-session-id`), at most
//      3 of its chats are in flight, and a cap answer is retried until a
//      session frees, then handed to magpie as a 429 so it can fail over.
//   7. Chats always go upstream as SSE streams: CodeArts meters only streamed
//      answers, so a caller that asked for JSON gets the stream folded back.
//   8. `auth.checkin` presses the daily 「每日领取」 check-in the way the
//      CodeArts IDE does (`/v1/ops/delivery` → `/claim` → `/confirm`).
//
// It imitates @magpie-community/opencode-workbuddy-auth for structure but
// replaces its browser sign-in + bearer-token requests with CodeArts' OAuth +
// signed-request flow. See README.md.

import { createHash, createHmac } from "node:crypto"
import { createServer } from "node:http"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

const PROVIDER = "codearts"
const NPM = "@ai-sdk/openai-compatible" // chat completions

// ---- endpoints & flow constants --------------------------------------------

// Chat Completions base (loader `baseURL`). A chat goes to
// `${CHAT_API_BASE}/chat/completions`.
const CHAT_API_BASE = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2"
// Snap-access manager host: model list, account/quota, check-in.
const SNAP_HOST = "https://snap-access.cn-north-4.myhuaweicloud.com"
const SNAP_MODEL_BUILTIN_URL = `${SNAP_HOST}/v1/model/builtin`
const SNAP_STATISTICS_URL = `${SNAP_HOST}/snap-manager/v1/statistics/plugin`
// opengw gateway config: the benefit/free-quota model set.
const OPENGW_HOST = "https://opengw.developer.huaweicloud.com"
const OPENGW_GATEWAY_CONFIG_URL = `${OPENGW_HOST}/api/v1/gateway/config`
// The only hosts the account's credentials are signed for and sent to: the
// two the plugin itself calls, by name. STS takes the refresh token, never a
// signature, and the portal only ever opens in the browser.
const SIGNED_HOSTS = new Set([SNAP_HOST, OPENGW_HOST].map((u) => new URL(u).host))

// Huawei Cloud IAM: the one place an account's own phone number can be read
// with the credentials a sign-in already carries (`GET /v3.0/OS-USER/users/
// {principal_id}` answers `user.phone`, measured `0086-13800138000`).
//
// Deliberately NOT in SIGNED_HOSTS. magpie forwards requests through this
// plugin's `fetch`, and that set is the fence around the account's temporary
// credentials; adding IAM to it would let an `api` override carry them to
// another service. The plugin's own GET is signed here, by this one function,
// for this one URL — nothing forwarded ever reaches IAM signed.
const IAM_HOST = "https://iam.cn-north-4.myhuaweicloud.com"
const IAM_USER_URL = (userId) => `${IAM_HOST}/v3.0/OS-USER/users/${encodeURIComponent(userId)}`
const IAM_TIMEOUT_MS = 8_000
// The phone never changes for one IAM user, and the card asks often: one read
// per account is enough, kept in memory for IAM_PHONE_TTL_MS (a failed read
// included, so a card refresh does not ask IAM again every time).
const IAM_PHONE_TTL_MS = 6 * 60 * 60 * 1000
// The daily free token pool a `maas_type: benefit` chat draws on (never the
// credit packages), so a free model's spend shows up in the usage panel.
const BENEFIT_BALANCE_URL = `${OPENGW_HOST}/api/v1/user/tokens/balance`
// The free models are the account's only once today's benefit is claimed: the
// CodeArts agent POSTs this before it lists them (`claimBenefit`), and leaves
// them out when it fails (4004 no benefit / expired, 4006 today's places gone).
const BENEFIT_CLAIM_URL = `${OPENGW_HOST}/api/v1/benefit/claim`
const BENEFIT_OK = "0000"
// The agent's own model list, with each model's credit rate (`credit[].
// ratio_display`, shown as "1.50x") and its parameters: the CodeAgent's detail.
const AGENT_LIST_URL = `${SNAP_HOST}/v1/agent-center/agents/useragents?offset=0&limit=100`
const AGENT_DETAIL_URL = (id) => `${SNAP_HOST}/v1/agent-center/agents/detail?agent_id=${encodeURIComponent(id)}`
const CODE_AGENT_ID = "CodeAgent"
// The agent the IDE reads its model list from (its CODE_AGENT_AGENT_ID): the
// one whose `original_id` is "build", 「自主规划与执行」; older lists call it
// CodeAgent. Its id, as the IDE asks for it, stands in when the list can't be read.
const MAIN_AGENT_ORIGINAL_IDS = ["build", CODE_AGENT_ID]
const MAIN_AGENT_FALLBACK_ID = "a8bcb36232554267a5142361cc25a393"
// Agents tried for a model list before giving up.
const AGENT_DETAIL_TRIES = 3
const AGENT_CENTER_HEADERS = { "Content-Type": "application/json", "Agent-Type": "AgentCenter", "X-Language": "zh-cn" }
// Check-in credits are good for 30 days from when they are given.
const CHECKIN_CREDIT_DAYS = 30
// Every credit batch with its own expiry, as the console's 「获取明细」 reads
// them (its /portal/snap-manager and /portal/promptcenter calls are these):
// the plan's and bought packages, then the campaigns' grants (sign-up, check-in).
const PACKAGE_CREDIT_PAGE_URL = `${SNAP_HOST}/snap-manager/v1/package/credit/page`
const PACKAGE_CREDIT_QUERIES = [
  { pageNum: 1, pageSize: 100, sortField: "created_time", sortOrder: "desc", packageTypes: ["basic", "ondemand"] },
  { pageNum: 1, pageSize: 100, packageTypes: ["bonus"] },
]
const OPS_CREDIT_OVERVIEW_URL = `${SNAP_HOST}/v1/ops/credit/overview`
const OPS_CREDIT_CAMPAIGN_URL = (id) => `${SNAP_HOST}/v1/ops/credit/campaign/${encodeURIComponent(id)}?pageNum=1&pageSize=100`
// The batches change slowly; read them again this often (and after a check-in).
const CREDIT_BATCHES_TTL_MS = 10 * 60 * 1000
// Daily check-in (「限时福利 → 每日领取」), as the IDE's ActivityWelfarePane calls it.
const OPS_DELIVERY_URL = `${SNAP_HOST}/v1/ops/delivery?channel=IDE`
const OPS_CLAIM_URL = `${SNAP_HOST}/v1/ops/claim`
const OPS_CONFIRM_URL = `${SNAP_HOST}/v1/ops/confirm`
const OPS_CHANNEL = "IDE"
const DAILY_CHECKIN_TYPE = "USER_LOGIN"
// States the IDE disables the claim button in: today's benefit is in already.
const CLAIMED_STATUSES = ["CLAIMED", "CONFIRMED", "CONSUMED"]
// Unsigned headers snap-access routes on (signing them breaks the signature).
const SNAP_EXTRA_HEADERS = { "Agent-Type": "PromptCenter", "X-Language": "zh-cn" }
// OAuth portal (new IAM flow) and the STS token endpoint.
const PORTAL_AUTHORIZE_BASE = "https://codearts.huaweicloud.com/portal/authorize"
const PORTAL_LOGIN_BASE = "https://codearts.huaweicloud.com/portal/login"
const STS_TOKEN_ENDPOINT = "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens"

// OAuth client id (equals the plugin's URI scheme) and local callback path.
const CLIENT_ID = "codearts-agent"
const REDIRECT_PATH = "/oauth/callback"
// What the portal expects the calling plugin to be called (reverse-engineered
// constants — the plugin/version match the real IDE extension, not this package).
const LOGIN_PLUGIN_NAME = "snap_AIIDE"
const LOGIN_PLUGIN_VERSION = "5.2.0"
const OAUTH_THEME = "2" // activeColorTheme.kind: 2 = Dark
const OAUTH_LOCALE = "zh-cn"

const GRANT_AUTHORIZATION_CODE = "authorization_code"
const GRANT_REFRESH_TOKEN = "refresh_token"

const TOKEN_TIMEOUT_MS = 60_000
const REQUEST_TIMEOUT_MS = 30_000
const OAUTH_CALLBACK_TIMEOUT_MS = 180_000
const MIN_CALLBACK_PORT = 10_000

// magpie renews this long before the credential expires.
const REFRESH_LEAD_MS = 30 * 60 * 1000
// The loader renews in-band only this close to expiry, well after magpie's own
// renewal, so the two never spend the one-time refresh token twice.
const INBAND_REFRESH_LEAD_MS = 2 * 60 * 1000

// The gateway allows 3 concurrent sessions per account; the 4th is answered
// `TM.00001041` (并发会话数已达上限(3个)) — as an HTTP 400, or as the first event
// of a 200 SSE stream — and a finished streaming session holds its slot for
// about a minute. Our own in-flight chats are capped first, and a cap answer is
// retried (re-signed each time) within a budget, then handed back as a 429.
const SESSION_LIMIT_ERROR = "TM.00001041"
// The gateway tells sessions apart by `x-ot-session-id` (the CodeArts agent
// sends its conversation id there; `Chat-Id`/`Session-Id` count for nothing):
// a request without it is a session of its own, held for about a minute, so
// three requests in a minute used to fill the account.
const SESSION_HEADER = "x-ot-session-id"
// A gateway that queues the request answers 429 with `queue-status: queued`
// and a `trace-id`; the agent polls this until the trace is `promoted`, then
// sends the request again, and DELETEs it when it gives up.
const TRACE_QUEUE_URL = (traceId) => `${SNAP_HOST}/api/v1/concurrency/trace-queues/${encodeURIComponent(traceId)}`
const QUEUE_BUDGET_MS = 300_000
/** magpie's: "1" when another candidate follows this request. */
const FALLBACK_HEADER = "x-magpie-fallback"
// Every chat of an account goes out under its one session id, so this gate is
// what keeps the account within the vendor's 3 sessions: an option may only
// lower it.
const ACCOUNT_MAX_INFLIGHT = 3
const SESSION_RETRY_DELAYS_MS = [2_000, 4_000, 6_000, 8_000, 10_000] // the last repeats
const SESSION_RETRY_BUDGET_MS = 150_000
// A body nobody drains must not hold an in-flight permit forever.
const PERMIT_MAX_HOLD_MS = 15 * 60 * 1000
// How much of a 200 body to read while looking for an embedded error.
const SSE_PEEK_LIMIT = 16 * 1024
// The gateway rejects a larger output budget (RANGE_VALIDATOR, 0..65536).
const MAX_OUTPUT_TOKENS = 65_536
// Left to its default the gateway streams the reasoning inside `content`, so a
// caller shows the thinking as the answer; asked for explicitly it goes to
// `reasoning_content` and `content` is the reply only.
const ENABLE_THINKING = { type: "enabled" }

// Benefits (free-quota) models require `maas_type: benefit` as a *signed*
// header, or the backend answers InferHub.002002009.404 "model is not
// registered". The authoritative list comes from opengw gateway/config at
// runtime; these are the known defaults so a cold start still works.
//
// The dated ids are the registered free models (measured: with the benefit
// header `deepseek-v4-flash-0731` answers 200 against the free pool, while the
// bare `deepseek-v4-flash` is a different, paid model that refuses the header
// with `InferHub.4005.200`), so they are sent exactly as published.
const BENEFIT_MODEL_FALLBACK = [
  "glm-5.3-flash",
  "deepseek-v4.1-flash",
  "deepseek-v4-flash-0731",
  "deepseek-v4-pro-0813",
]
// Which models draw on the free pool is each account's own answer, kept on the
// account's state (`state.benefit`, with its builtin ids in `state.regular`):
// the fallback stands only until that account's gateway/config has been read.
// An account without the free campaign lists `deepseek-v4.1-flash` as a plain
// builtin model, and the benefit header then gets `InferHub.4004.200 benefit
// not found`. Nothing about models is shared between accounts.

// Context windows (in tokens), keyed by the exact chat model id. Models
// without an entry leave the window to the backend's default.
const CONTEXT_WINDOWS = {
  "GLM-5.2": 202752,
  "glm-5.3-flash": 1048576,
  "deepseek-v4-flash": 1048576,
  "deepseek-v4-pro": 1048576,
  "deepseek-v4.1-flash": 1000000,
}

// The models offered before (or instead of) the account's own live list. `GLM-5`
// is gone: the endpoint answers `InferHub.002002009.404` for it.
const CATALOG = [
  { id: "GLM-5.2", name: "GLM-5.2" },
  { id: "GLM-5.1", name: "GLM-5.1" },
  { id: "glm-5.3-flash", name: "GLM-5.3 Flash" },
  { id: "openpangu-2.0-flash", name: "openPangu 2.0 Flash" },
  { id: "openpangu-2.0-pro", name: "openPangu 2.0 Pro" },
  { id: "deepseek-v4-flash-0731", name: "DeepSeek V4 Flash" },
  { id: "deepseek-v4-pro-0813", name: "DeepSeek V4 Pro" },
  { id: "deepseek-v4.1-flash", name: "DeepSeek V4.1 Flash" },
]

// Every model listed takes text alone: the vision ones (`-vl`) are left out
// (parseModelInfo), and the rest answer an image with
// `InferHub.001001020.406` "The request model is not multimodal". Said in so
// many words (`image: false`, not left out, which magpie reads as unknown),
// so magpie describes an image for the model or leaves it out, and an agent
// is told it takes none.
const TEXT_ONLY = { input: { text: true, image: false, audio: false, video: false, pdf: false } }

// ---- small helpers ---------------------------------------------------------

const firstOf = (...vs) => vs.find((v) => typeof v === "string" && v.trim())?.trim() ?? ""

const asRecord = (v) => (typeof v === "object" && v !== null && !Array.isArray(v) ? v : {})

function safeJson(text) {
  try {
    const parsed = JSON.parse(text)
    return typeof parsed === "object" && parsed !== null ? parsed : null
  } catch {
    return null
  }
}

function num(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v
  if (typeof v === "string" && v.trim()) {
    const n = Number(v)
    if (Number.isFinite(n)) return n
  }
  return 0
}

const clamp = (n) => Math.max(0, Math.min(100, n))

// prettify is a model id as a name: openpangu-2.0-flash -> "Openpangu 2.0 Flash"
function prettify(id) {
  return String(id)
    .split(/[-_]/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ")
}

// normalizeModelId drops a trailing 4-digit version tag: deepseek-v4-flash-0731
// -> deepseek-v4-flash. Only for display names and the CONTEXT_WINDOWS lookup:
// the dated id is the registered free model, so ids sent upstream keep it.
function normalizeModelId(id) {
  if (typeof id === "string" && id.length > 5) {
    const suffix = id.slice(-5)
    if (suffix.startsWith("-") && /^\d{4}$/.test(suffix.slice(1))) return id.slice(0, -5)
  }
  return id
}

const BEIJING_MS = 8 * 3600 * 1000

/** Today as CodeArts counts days: a Beijing (UTC+8) date, "2026-10-21". */
const beijingDay = (at = Date.now()) => new Date(at + BEIJING_MS).toISOString().slice(0, 10)

/** The next Beijing midnight after `at`, in ms: when a daily allowance comes back. */
const nextBeijingMidnight = (at = Date.now()) => Date.parse(`${beijingDay(at)}T00:00:00+08:00`) + 86_400_000

/**
 * A date as CodeArts writes it, in ms (undefined when it can't be read):
 * epoch seconds or ms, ISO, or a zone-less "2026-11-01[ 00:00:00]", which is
 * Beijing time.
 */
function vendorDate(v) {
  if (typeof v === "number" && Number.isFinite(v) && v > 0) return v < 1e11 ? v * 1000 : v
  if (typeof v !== "string" || !v.trim()) return undefined
  const s = v.trim()
  if (/^\d+$/.test(s)) return vendorDate(Number(s))
  const local = /^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}(?::\d{2})?))?$/.exec(s)
  const at = local ? Date.parse(`${local[1]}T${local[2] ?? "00:00:00"}+08:00`) : Date.parse(s)
  return Number.isNaN(at) ? undefined : at
}

/**
 * A model's credit rate (官方「消耗系数」, shown "1.50x"): `credit` is one price
 * tier or a list of them, `ratio_display` the multiple. 0 when it has none.
 */
function creditRateOf(credit) {
  const tier = asRecord(Array.isArray(credit) ? credit[0] : credit)
  const n = parseFloat(String(tier.ratio_display ?? tier.ratioDisplay ?? ""))
  return Number.isFinite(n) && n > 0 ? n : 0
}

// upstreamModelId drops the provider prefix a host may leave on the id
// (`codearts/deepseek-v4.1-flash`): the gateway knows only the bare id, and
// answers anything else `InferHub.002002009.404`, inside a 200 when streaming.
function upstreamModelId(id) {
  return typeof id === "string" && id.startsWith(`${PROVIDER}/`) ? id.slice(PROVIDER.length + 1) : id
}

// ---- WebCrypto primitives --------------------------------------------------

function subtle() {
  const c = globalThis.crypto
  if (!c?.subtle) throw new Error("CodeArts: WebCrypto (globalThis.crypto.subtle) is unavailable")
  return c.subtle
}

const typed = (u8) => (u8 instanceof Uint8Array ? u8 : new Uint8Array(u8))

function randomBytes(n) {
  const out = new Uint8Array(n)
  globalThis.crypto.getRandomValues(out)
  return out
}

const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("")

function randomHex(n) {
  return hex(randomBytes(n))
}

function b64url(u8) {
  let s = ""
  for (const b of u8) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

const utf8 = (s) => new TextEncoder().encode(s)

async function sha256Hex(data) {
  const digest = await subtle().digest("SHA-256", typed(data))
  return hex(new Uint8Array(digest))
}

async function hmacSha256Hex(key, data) {
  const cryptoKey = await subtle().importKey(
    "raw", typed(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  )
  const sig = await subtle().sign("HMAC", cryptoKey, typed(data))
  return hex(new Uint8Array(sig))
}

/** PKCE pair: a random 48-byte base64url verifier + its S256 challenge. */
async function generatePkcePair() {
  const codeVerifier = b64url(randomBytes(48))
  const digest = await subtle().digest("SHA-256", utf8(codeVerifier))
  return { codeVerifier, codeChallenge: b64url(new Uint8Array(digest)) }
}

/** Generate an ES256 (P-256) DPoP key pair as JWKs. */
async function generateDpopKeyPair() {
  const pair = await subtle().generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  const jwk = await subtle().exportKey("jwk", pair.privateKey)
  return {
    privateKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d },
    publicKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
  }
}

/** Recover a DPoP key pair from a persisted private JWK. */
function keyPairFromStoredJwk(jwk) {
  return {
    privateKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d },
    publicKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
  }
}

/** Sign a `dpop+jwt` proof (htm=method, htu=URL) with the DPoP private key. */
async function signDpopJws(keyPair, htm, htu) {
  const header = { alg: "ES256", typ: "dpop+jwt", jwk: keyPair.publicKeyJwk }
  const payload = { htm, htu, iat: Math.floor(Date.now() / 1000), jti: randomHex(32) }
  const signingInput = `${b64url(utf8(JSON.stringify(header)))}.${b64url(utf8(JSON.stringify(payload)))}`
  const key = await subtle().importKey(
    "jwk", keyPair.privateKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
  )
  const sig = await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(signingInput))
  // WebCrypto ECDSA returns raw r||s, which is exactly the JWS ES256 format.
  return `${signingInput}.${b64url(new Uint8Array(sig))}`
}

// ---- Huawei SDK-HMAC-SHA256 request signing --------------------------------

function buildCanonicalRequest(method, uri, query, headers, payloadHash) {
  const signedHeaders = [...headers.keys()].sort()
  const headerLines = signedHeaders.map((k) => `${k}:${headers.get(k) ?? ""}`)
  return [method, uri, query, headerLines.join("\n"), "", signedHeaders.join(";"), payloadHash].join("\n")
}

// RFC 3986: everything but the unreserved characters is %-encoded, as the
// gateway encodes it when it checks the signature.
const rfc3986 = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)

/** The query as the signature has it: pairs sorted by key, then value, each encoded. */
function canonicalQuery(url) {
  return [...url.searchParams.entries()]
    .sort(([a, x], [b, y]) => (a < b ? -1 : a > b ? 1 : x < y ? -1 : x > y ? 1 : 0))
    .map(([k, v]) => `${rfc3986(k)}=${rfc3986(v)}`)
    .join("&")
}

/**
 * Sign a Huawei request; returns the header map to merge into the request.
 * Extra headers (e.g. `maas_type: benefit`) participate in the canonical
 * request and must be sent verbatim, or the server rejects the signature.
 */
async function signRequestHuawei(ak, sk, securityToken, method, urlStr, body, extraHeaders, dateStampOverride) {
  const url = new URL(urlStr)
  let uri = url.pathname
  if (!uri.endsWith("/")) uri += "/"
  const query = canonicalQuery(url)
  const dateStamp = dateStampOverride
    ?? new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")
  const payloadHash = await sha256Hex(body)

  const headers = new Map()
  headers.set("host", url.host)
  headers.set("x-sdk-date", dateStamp)
  headers.set("x-sdk-content-sha256", payloadHash)
  headers.set("x-security-token", securityToken)
  if (extraHeaders !== undefined) {
    for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v)
  }
  if (method.toUpperCase() !== "GET") headers.set("content-type", "application/json")

  const signedHeaders = [...headers.keys()].sort()
  const canonicalRequest = buildCanonicalRequest(method.toUpperCase(), uri, query, headers, payloadHash)
  const canonicalHash = await sha256Hex(utf8(canonicalRequest))
  const stringToSign = `SDK-HMAC-SHA256\n${dateStamp}\n${canonicalHash}`
  const signature = await hmacSha256Hex(utf8(sk), utf8(stringToSign))
  headers.set(
    "Authorization",
    `SDK-HMAC-SHA256 Access=${ak},SignedHeaders=${signedHeaders.join(";")},Signature=${signature}`,
  )
  return headers
}

// ---- OAuth token exchange --------------------------------------------------

/** Normalize an STS token response into a persisted CodeArts credential. */
function credentialFromTokenResponse(token, codeVerifier, keyPair) {
  const c = token?.credentials ?? {}
  return {
    access_key_id: c.access_key_id ?? "",
    secret_access_key: c.secret_access_key ?? "",
    security_token: c.security_token ?? "",
    expires_at: c.expiration ?? "",
    refresh_token: token?.refresh_token,
    code_verifier: codeVerifier,
    dpop_private_key_jwk: keyPair.privateKeyJwk,
    // Minted once per sign-in and kept across refreshes: the account's one
    // upstream session, whichever process sends the request.
    session_id: randomHex(16),
  }
}

/** Base64url (or plain base64) text to a parsed JSON object, or null. */
function b64Json(s) {
  if (typeof s !== "string" || !s) return null
  try {
    const t = s.replace(/-/g, "+").replace(/_/g, "/")
    return safeJson(new TextDecoder().decode(Uint8Array.from(atob(t + "=".repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0))))
  } catch {
    return null
  }
}

/** The signer's claims from the refresh token's `user_profile`, or null. */
function profileOf(cred) {
  const token = typeof cred?.refresh_token === "string" ? cred.refresh_token : ""
  const parts = token.split(".")
  if (parts.length !== 3) return null
  const payload = b64Json(parts[1])
  const raw = payload?.user_profile
  return typeof raw === "string" ? (safeJson(raw) ?? b64Json(raw)) : asRecord(raw)
}

/**
 * Who signed in. STS answers with no user fields, so without this every
 * sign-in looked like a new account to magpie (one more `codearts#xxxxxx`);
 * the refresh_token is a JWT whose `user_profile` claim names the signer.
 * `id` tells accounts apart, `name` is what the usage card shows.
 *
 * The claim carries no phone number, only IAM's `account_name` (the `hw…`
 * string) and `principal_urn` — which is why the card used to show
 * `iam::<domain>:user:<name>`, an ID nobody can tell apart from another
 * account's. `user_phone` (read from IAM after sign-in, see
 * `fetchAccountPhone`) stands in front of them when it is there.
 *
 * `id` is the identity (the URN) and keeps every IAM shape; `name` is only
 * what a person can read. When the claim carries no such value, `name` is
 * empty and the host falls back to the provider's name — an IAM id is never
 * the name (the `accountId` / `uid` rule in magpie-plugin-scaffold, #27).
 */
function accountIdentityOf(cred) {
  const legacy = { id: firstOf(cred?.user_name, cred?.user_id), name: firstOf(cred?.user_name) }
  const profile = profileOf(cred)
  if (!profile) return { ...legacy, name: displayNameOf(cred?.user_phone, legacy.name) }
  const id = firstOf(profile.principal_urn, profile.account_name, profile.account_id, profile.user_id, legacy.id)
  const name = displayNameOf(cred?.user_phone, profile.user_name, profile.account_name, profile.domain_name, legacy.name)
  return { id, name }
}

// What IAM writes in place of a name: `iam::<domain>:user:<name>`, a `urn:…`,
// the bare 32-character domain id, the account's `hw…` name, or a uuid. The
// shapes are read as IDs wherever they appear; none of them is a name.
const IDENTIFIER_PATTERNS = [
  /::/, // iam::<domain>:user:<name> / arn:…
  /^urn:/i, // urn:…
  /^hw[0-9a-f]{6,}$/i, // Huawei IAM account name, e.g. hw123456789012345
  /^[0-9a-f]{8}-[0-9a-f]{4}-/i, // uuid
  /^[0-9a-f]{16,}$/i, // bare hash, incl. the 32-character domain id
]

/** Does this value look like an internal ID rather than a display name? */
function looksLikeIdentifier(value) {
  const s = String(value ?? "").trim()
  return !!s && IDENTIFIER_PATTERNS.some((re) => re.test(s))
}

/** The first candidate that a person can tell apart from another account. */
function displayNameOf(...candidates) {
  for (const candidate of candidates) {
    const name = firstOf(candidate)
    if (name && !looksLikeIdentifier(name)) return name
  }
  return ""
}

/**
 * A phone number as the cards show it: `0086-13800138000` → `138****8000`.
 * The area code Huawei answers with is dropped, and any number too short to
 * mask is not a name worth showing (empty, so the caller falls back).
 */
function maskPhone(raw) {
  let digits = String(raw ?? "").replace(/\D/g, "")
  // Huawei Cloud writes the country code as `0086-…`; a person's own number
  // may come as `+86 …`. Either is dropped when an 11-digit number follows.
  if (digits.length > 11 && digits.startsWith("0086")) digits = digits.slice(4)
  else if (digits.length > 11 && digits.startsWith("86")) digits = digits.slice(2)
  // a phone is 11 digits; a shorter run is not a number to mask
  if (digits.length < 11) return ""
  return `${digits.slice(0, 3)}****${digits.slice(-4)}`
}

// One phone read per IAM user, re-read after IAM_PHONE_TTL_MS. A failed read
// is cached too (an empty answer): without that, a card refresh asks IAM again
// every time, each able to wait the full timeout. Stale entries are dropped
// past a cap, so the map does not grow for the life of the host.
const IAM_PHONE_CAP = 1024
const phoneByIamUser = new Map()

function rememberPhone(iamUserId, phone) {
  if (phoneByIamUser.size >= IAM_PHONE_CAP) {
    for (const [k, v] of phoneByIamUser) if (Date.now() - v.at >= IAM_PHONE_TTL_MS) phoneByIamUser.delete(k)
    if (phoneByIamUser.size >= IAM_PHONE_CAP * 2) phoneByIamUser.clear()
  }
  phoneByIamUser.set(iamUserId, { at: Date.now(), phone })
}

/**
 * The account's own phone number, read from Huawei Cloud IAM with the
 * credentials the sign-in already holds. Best effort: `""` when the claim has
 * no `principal_id`, the call fails, or the answer carries no usable number —
 * a display name must never cost anyone a sign-in.
 */
async function fetchAccountPhone(cred, fetcher = globalThis.fetch) {
  const iamUserId = firstOf(profileOf(cred)?.principal_id, profileOf(cred)?.user_id)
  if (!iamUserId || !cred?.access_key_id || !cred?.security_token) return ""
  const hit = phoneByIamUser.get(iamUserId)
  if (hit && Date.now() - hit.at < IAM_PHONE_TTL_MS) return hit.phone
  try {
    const url = IAM_USER_URL(iamUserId)
    const signed = await signRequestHuawei(
      cred.access_key_id, cred.secret_access_key, cred.security_token,
      "GET", url, new Uint8Array(),
    )
    const headers = new Headers()
    signed.forEach((value, key) => {
      if (key !== "host") headers.set(key, value)
    })
    const res = await fetcher(url, {
      method: "GET",
      headers,
      redirect: "error",
      signal: AbortSignal.timeout(IAM_TIMEOUT_MS),
    })
    if (!res.ok) {
      rememberPhone(iamUserId, "")
      return ""
    }
    const body = await res.json().catch(() => null)
    const phone = maskPhone(body?.user?.phone)
    rememberPhone(iamUserId, phone)
    return phone
  } catch {
    rememberPhone(iamUserId, "")
    return ""
  }
}

/** `{ user_phone }` when the account has one to show, else `{}` (never throws). */
async function accountPhoneField(cred, fetcher) {
  try {
    const phone = await fetchAccountPhone(cred, fetcher)
    return phone ? { user_phone: phone } : {}
  } catch {
    return {}
  }
}

/** The credential a sign-in carries; magpie keeps it in the `access` field. */
function credentialOf(auth) {
  if (!auth || auth.type !== "oauth") return null
  const raw = typeof auth.access === "string" ? auth.access : ""
  if (!raw) return null
  const cred = safeJson(raw)
  if (!cred || typeof cred.access_key_id !== "string" || !cred.access_key_id) return null
  // Which OAuth client a refresh token may be spent at. A record read here is
  // one this package's CodeArts sign-in wrote, whatever an older one lacks.
  return { ...cred, oauth_client: firstOf(cred.oauth_client, "codearts-agent") }
}

function expiresFromCredential(cred) {
  if (cred?.expires_at) {
    const parsed = Date.parse(cred.expires_at)
    if (!Number.isNaN(parsed)) return parsed
  }
  return Date.now() + 86_400_000
}

/** POST the STS token endpoint with a DPoP proof; `label` is the card that asked. */
async function requestToken(body, keyPair, fetcher, label = "CodeArts") {
  const dpop = await signDpopJws(keyPair, "POST", STS_TOKEN_ENDPOINT)
  let response
  try {
    response = await fetcher(STS_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { DPoP: dpop, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
      // A 307/308 would send the refresh token and verifier on with the body.
      redirect: "error",
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    })
  } catch (e) {
    throw new Error(`${label} token request network error: ${String(e)}`)
  }
  let data = null
  try {
    data = await response.json()
  } catch {
    data = null
  }
  if (!response.ok || !data?.credentials) {
    const message = `${label} token request failed: ${response.status}${data ? ` ${JSON.stringify(data)}` : ""}`
    // Only refresh_token invalidation is terminal; a transient DPoP rejection
    // must not permanently mark the account.
    if (data?.error === "invalid_grant" || isDeadRefreshToken(message)) {
      throw Object.assign(new Error(message), { signIn: "expired" })
    }
    throw new Error(message)
  }
  return data
}

/**
 * A refresh STS turns away for good: the token expired, or the one-time token
 * was already spent (`STS5.1806`). Only signing in again brings the account
 * back; a network hiccup or DPoP rejection must not read as this.
 */
function isDeadRefreshToken(text) {
  return /ExpiredRefreshToken|STS5\.1806|invalid refresh token|refresh token has been used/i.test(String(text ?? ""))
}

const isPermanentRefreshFailure = (e) => e?.signIn === "expired" || isDeadRefreshToken(e?.message ?? e)

function exchangeAuthorizationCode(code, codeVerifier, port, keyPair, fetcher, label = "CodeArts") {
  return requestToken({
    client_id: CLIENT_ID,
    code,
    code_verifier: codeVerifier,
    grant_type: GRANT_AUTHORIZATION_CODE,
    redirect_uri: `http://127.0.0.1:${port}${REDIRECT_PATH}`,
  }, keyPair, fetcher, label)
}

function exchangeRefreshToken(refreshToken, codeVerifier, keyPair, fetcher) {
  return requestToken({
    client_id: CLIENT_ID,
    code_verifier: codeVerifier,
    grant_type: GRANT_REFRESH_TOKEN,
    refresh_token: refreshToken,
  }, keyPair, fetcher)
}

/** Refresh a stored credential, reusing its verifier + DPoP private key. */
async function refreshCredential(cred, fetcher) {
  const refreshToken = firstOf(cred.refresh_token)
  if (!refreshToken || !cred.code_verifier || !cred.dpop_private_key_jwk) {
    // Nothing to renew it with: it lapses for good, so the account is marked
    // to sign in again rather than retried forever.
    throw Object.assign(
      new Error("CodeArts: credential cannot be refreshed (missing refresh_token/code_verifier/dpop key); sign in again"),
      { signIn: "expired" },
    )
  }
  const keyPair = keyPairFromStoredJwk(cred.dpop_private_key_jwk)
  const token = await exchangeRefreshToken(refreshToken, cred.code_verifier, keyPair, fetcher)
  const next = credentialFromTokenResponse(token, cred.code_verifier, keyPair)
  if (!next.refresh_token) next.refresh_token = refreshToken
  // Preserve non-rotating identity fields a legacy login may have carried, and
  // the session id: it belongs to the account, not to the token.
  for (const k of ["domain_id", "user_id", "user_name", "session_id"]) {
    if (cred[k]) next[k] = cred[k]
  }
  return next
}

/**
 * The account's upstream session headers, the same in every process and across
 * refreshes: a fresh Chat-Id per request opened a new session each time and
 * pinned the 3-session cap. Credentials from before `session_id` existed fall
 * back to the signer's identity, then to the access key.
 */
async function accountSessionIds(cred) {
  const seed = firstOf(cred.session_id, accountIdentityOf(cred).id, cred.access_key_id)
  const digest = await sha256Hex(utf8(`codearts-session:${seed}`))
  return { sessionId: digest.slice(0, 32), chatId: digest.slice(32, 64) }
}

// ---- OAuth login: URL + loopback callback ----------------------------------

/** Build the Huawei Cloud portal authorize URL (params mirror the real IDE). */
function buildOAuthLoginUrl(port, pkce, ticketId) {
  return `${PORTAL_AUTHORIZE_BASE}?theme=${OAUTH_THEME}&locale=${OAUTH_LOCALE}`
    + `&uri_scheme=${CLIENT_ID}&client_id=${CLIENT_ID}&port=${port}`
    + `&code_challenge=${pkce.codeChallenge}&code_challenge_method=SHA-256`
    + `&ticket_id=${ticketId}&plugin-name=${LOGIN_PLUGIN_NAME}&plugin-version=${LOGIN_PLUGIN_VERSION}`
}

const buildPortalLoginResultUrl = (ok) =>
  `${PORTAL_LOGIN_BASE}?login_succeed=${ok}&uri_scheme=${CLIENT_ID}&locale=${OAUTH_LOCALE}`

/**
 * Start the loopback callback server, listening on 127.0.0.1:port>=10000. It
 * takes one thing: a GET to the callback path, exactly as sent, with the
 * authorization code, which it exchanges at STS (PKCE + DPoP), then sends the
 * browser on to the portal's own result page. A callback without a code ends
 * the sign-in at once, with the portal's own words when it gave any. The
 * redirect target is always that page, never a parameter of the request.
 */
function startOAuthCallbackServer(pkce, keyPair, fetcher, label = "CodeArts") {
  let resolveResult
  let rejectResult
  const result = new Promise((resolve, reject) => {
    resolveResult = resolve
    rejectResult = reject
  })
  let answered = false

  const server = createServer((request, response) => {
    // The path as sent, not as a URL would normalise it (`/oauth/./callback`).
    const raw = request.url ?? "/"
    const query = raw.indexOf("?")
    if ((query < 0 ? raw : raw.slice(0, query)) !== REDIRECT_PATH) {
      response.writeHead(404).end("Not found")
      return
    }
    if (request.method !== "GET") {
      response.writeHead(405, { Allow: "GET" }).end("Method not allowed")
      return
    }
    // One sign-in, one callback: another one for the same flow is refused.
    if (answered) {
      response.writeHead(409).end("This sign-in is already being completed")
      return
    }
    answered = true
    const url = new URL(raw, `http://127.0.0.1:${request.socket.localPort}`)
    const code = url.searchParams.get("code")
    if (!code) {
      response.writeHead(307, { Location: buildPortalLoginResultUrl(false) }).end()
      const said = firstOf(url.searchParams.get("error_description"), url.searchParams.get("error"))
      rejectResult(new Error(`CodeArts sign-in failed: ${said || "the callback came back without an authorization code"}`))
      return
    }
    const port = request.socket.localPort ?? 0
    void exchangeAuthorizationCode(code, pkce.codeVerifier, port, keyPair, fetcher, label).then(
      (token) => {
        response.writeHead(307, { Location: buildPortalLoginResultUrl(true) }).end()
        const cred = credentialFromTokenResponse(token, pkce.codeVerifier, keyPair)
        resolveResult({ access: JSON.stringify(cred), expires: expiresFromCredential(cred) })
      },
      (error) => {
        response.writeHead(307, { Location: buildPortalLoginResultUrl(false) }).end()
        rejectResult(error)
      },
    )
  })

  return listenOnCallbackPort(server).then((port) => ({ port, server, result }))
}

const CALLBACK_PORT_TRIES = 20
const randomCallbackPort = () => Math.floor(Math.random() * (65_536 - MIN_CALLBACK_PORT)) + MIN_CALLBACK_PORT

/**
 * Listen on 127.0.0.1: the port the system gives, or, when that is below
 * 10000, a random one >= 10000, another while the one picked is taken.
 */
function listenOnCallbackPort(server) {
  return new Promise((resolve, reject) => {
    let tries = 0
    const tryListen = (port) => {
      const failed = (e) => {
        if (port !== 0 && e?.code === "EADDRINUSE" && ++tries < CALLBACK_PORT_TRIES) tryListen(randomCallbackPort())
        else reject(e)
      }
      server.once("error", failed)
      server.listen(port, "127.0.0.1", () => {
        server.off("error", failed)
        const address = server.address()
        const assigned = typeof address === "object" && address ? address.port : 0
        if (assigned >= MIN_CALLBACK_PORT) {
          resolve(assigned)
          return
        }
        server.close(() => tryListen(randomCallbackPort()))
      })
    }
    tryListen(0)
  })
}

/**
 * Start an OAuth flow and return its login URL immediately (magpie opens it).
 * The result resolves once the browser is redirected back and STS answers;
 * the callback server is closed as soon as the result settles.
 */
async function startOAuthFlow(fetcher, label = "CodeArts") {
  const pkce = await generatePkcePair()
  const keyPair = await generateDpopKeyPair()
  const { port, server, result } = await startOAuthCallbackServer(pkce, keyPair, fetcher, label)
  // The authorize URL carries a ticket_id as the IDE's does; the code flow
  // itself never reads it back.
  const loginUrl = buildOAuthLoginUrl(port, pkce, randomHex(32))

  let closed = false
  const close = async () => {
    if (closed) return
    closed = true
    await new Promise((resolve) => server.close(() => resolve()))
  }

  const resultWithUrl = Promise.race([
    result,
    new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error("CodeArts OAuth login timed out")), OAUTH_CALLBACK_TIMEOUT_MS)
      timer.unref?.()
    }),
  ]).then((outcome) => ({ ...outcome, loginUrl }))

  // Settle in the background so an early result never becomes an unhandled
  // rejection, and so the listening socket is always released.
  resultWithUrl.catch(() => {}).finally(() => { void close() })

  return { loginUrl, result: resultWithUrl, close }
}

// ---- signed requests to CodeArts -------------------------------------------

/** Turn a request body (string / bytes / stream / blob) into bytes. */
async function toBytes(body) {
  if (body == null) return new Uint8Array()
  if (typeof body === "string") return utf8(body)
  if (body instanceof Uint8Array) return body
  if (body instanceof ArrayBuffer) return new Uint8Array(body)
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength)
  if (typeof body?.getReader === "function") {
    const chunks = []
    const reader = body.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(typed(value))
    }
    const total = chunks.reduce((n, c) => n + c.length, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const c of chunks) {
      out.set(c, offset)
      offset += c.length
    }
    return out
  }
  if (typeof body?.arrayBuffer === "function") return new Uint8Array(await body.arrayBuffer())
  return utf8(String(body))
}

/**
 * Is `model` one of the account's free models, sent with the signed
 * `maas_type: benefit` header? `state.benefit` is the account's own list once
 * read (null until then, when the fallback stands); one the gateway said has
 * no benefit (`state.noBenefit`) is not.
 */
function isBenefitModel(model, state) {
  const id = String(upstreamModelId(model) ?? "")
  const free = state?.benefit ? state.benefit.has(id) : BENEFIT_MODEL_FALLBACK.includes(id)
  return free && !state?.noBenefit?.has(id)
}

/** Can `model` be called without the benefit header: one of the account's builtin models, or not known yet? */
function isRegularModel(model, state) {
  return !state?.regular || state.regular.has(String(upstreamModelId(model) ?? ""))
}

/**
 * Reshape a chat body into what the gateway accepts and meters:
 * - the bare model id, without the host's `codearts/` prefix;
 * - thinking asked for explicitly (unless the caller said, or the plugin's
 *   `thinking: false` option), so `content` carries only the reply;
 * - the output budget inside the gateway's 65536;
 * - always `stream: true`. CodeArts meters only streamed answers — a
 *   non-streaming 200 returns tokens yet leaves the credits untouched — so a
 *   caller that asked for JSON gets the stream folded back (`fold`);
 * - tool names within the gateway's 64 characters (`names`, short → the
 *   agent's own, to put back in the answer; null when none was cut).
 * A body that is not a chat (no `model` + `messages`) gives null.
 */
function prepareChatBody(parsed, { thinking = true } = {}) {
  if (!parsed || typeof parsed.model !== "string" || !Array.isArray(parsed.messages)) return null
  const body = { ...parsed, model: upstreamModelId(parsed.model) }
  const names = shortenToolNames(body)
  // `injected`: ours to take back should a model refuse the parameter.
  const injected = thinking && body.thinking === undefined
  if (injected) body.thinking = ENABLE_THINKING
  for (const k of ["max_tokens", "max_completion_tokens"]) {
    if (typeof body[k] === "number" && body[k] > MAX_OUTPUT_TOKENS) body[k] = MAX_OUTPUT_TOKENS
  }
  const fold = body.stream !== true
  body.stream = true
  return { body, fold, injected, names }
}

// ---- tool names over the gateway's limit (#432) -----------------------------

/**
 * CodeArts turns away a function name over 64 characters ("Function name
 * […] length over limit, maximum is 64", InferHub.001001017.413), and an
 * agent's MCP tools are often longer: ZCode's android emulator tool is
 * `mcp__plugin_android-emulator_android-emulator__android_discover_project`,
 * 71. A longer name goes as magpie's FlatName cuts one: its first 55
 * characters, `_`, and 8 hex of its SHA-256, 64 in all. The same name is cut
 * the same way on every request, so a call in the history keeps matching its
 * tool, and two names that start alike differ in their hash.
 */
const TOOL_NAME_LIMIT = 64
const TOOL_NAME_KEEP = 55

function cutToolName(name, salt) {
  let head = name.slice(0, TOOL_NAME_KEEP)
  // never half a surrogate pair
  if (/[\uD800-\uDBFF]$/.test(head)) head = head.slice(0, -1)
  const hex = createHash("sha256").update(salt ? `${name}\u0000${salt}` : name).digest("hex")
  return `${head}_${hex.slice(0, 8)}`
}

/** Every place a body names a tool: its tools, its history's calls, tool_choice. */
function toolNameSlots(body) {
  const slots = []
  const slot = (obj, key) => {
    if (obj && typeof obj === "object" && typeof obj[key] === "string") slots.push({ obj, key })
  }
  for (const t of Array.isArray(body.tools) ? body.tools : []) slot(t?.function, "name")
  for (const f of Array.isArray(body.functions) ? body.functions : []) slot(f, "name")
  const choice = body.tool_choice
  if (choice && typeof choice === "object") slot(choice.function, "name")
  if (body.function_call && typeof body.function_call === "object") slot(body.function_call, "name")
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    if (!m || typeof m !== "object") continue
    for (const c of Array.isArray(m.tool_calls) ? m.tool_calls : []) slot(c?.function, "name")
    slot(m.function_call, "name")
    if (m.role === "tool" || m.role === "function") slot(m, "name")
  }
  return slots
}

/**
 * Cut every tool name over the limit in body, in place; the map of each cut
 * name to the agent's own, or null when every name fits. A cut name that is
 * another tool's own name, or another cut one's, is cut again with a salt,
 * so the map always leads back to one name.
 */
function shortenToolNames(body) {
  const slots = toolNameSlots(body)
  if (!slots.some((s) => s.obj[s.key].length > TOOL_NAME_LIMIT)) return null
  const taken = new Set(slots.map((s) => s.obj[s.key]).filter((n) => n.length <= TOOL_NAME_LIMIT))
  const short = new Map() // the agent's name → the one sent
  const names = new Map() // the one sent → the agent's name
  // In a fixed order, so the same names are cut alike on every request.
  const long = [...new Set(slots.map((s) => s.obj[s.key]).filter((n) => n.length > TOOL_NAME_LIMIT))].sort()
  for (const name of long) {
    let cut = cutToolName(name, 0)
    for (let salt = 1; taken.has(cut) || names.has(cut); salt += 1) cut = cutToolName(name, salt)
    short.set(name, cut)
    names.set(cut, name)
  }
  // In place: the body is signedFetch's own parse of the request.
  for (const s of slots) {
    const cut = short.get(s.obj[s.key])
    if (cut) s.obj[s.key] = cut
  }
  return names
}

/** The agent's own names back in a whole completion's tool calls. */
function restoreToolNames(completion, names) {
  if (!names) return completion
  for (const choice of Array.isArray(completion?.choices) ? completion.choices : []) {
    const msg = choice?.message
    if (!msg || typeof msg !== "object") continue
    for (const c of Array.isArray(msg.tool_calls) ? msg.tool_calls : []) {
      const name = c?.function?.name
      if (typeof name === "string" && names.has(name)) c.function.name = names.get(name)
    }
    if (msg.function_call && names.has(msg.function_call.name)) msg.function_call.name = names.get(msg.function_call.name)
  }
  return completion
}

/**
 * A stream with the agent's own names back in its tool calls. A call's name
 * usually comes whole in one delta; should the gateway send it in pieces, the
 * pieces of a cut name past its first 55 characters (the part that differs
 * from the agent's) are held until the name is whole, then the rest of the
 * agent's name goes in their place. Events that name no cut tool pass as
 * they came, byte for byte.
 */
function restoreToolNamesInStream(stream, names) {
  if (!names) return stream
  const cuts = [...names.keys()]
  const calls = new Map() // `${choice}:${call}` → { got, sent }
  const enc = new TextEncoder()
  const dec = new TextDecoder()
  let pending = ""
  const named = (key, piece) => {
    const c = calls.get(key) ?? { got: "", sent: 0 }
    calls.set(key, c)
    // A whole cut name in one piece, the call's first or a gateway's repeat
    // of it in a later delta: the agent's name, whole.
    if (names.has(piece)) {
      const own = names.get(piece)
      c.got = own
      c.sent = own.length
      return own
    }
    c.got += piece
    let out
    if (names.has(c.got)) {
      const own = names.get(c.got)
      out = own.slice(c.sent)
      c.sent = own.length
      c.got = own // a whole name, matched once
    } else if (c.got.length < TOOL_NAME_LIMIT && cuts.some((cut) => cut.startsWith(c.got))) {
      const upTo = Math.min(c.got.length, TOOL_NAME_KEEP)
      out = upTo > c.sent ? c.got.slice(c.sent, upTo) : ""
      c.sent = Math.max(c.sent, upTo)
    } else {
      out = c.got.slice(c.sent)
      c.sent = c.got.length
    }
    return out
  }
  // what was held back of a name that never became whole
  const held = () => {
    const choices = []
    for (const [key, c] of calls) {
      if (c.sent >= c.got.length) continue
      const [ci, ti] = key.split(":").map(Number)
      choices.push({ index: ci, delta: { tool_calls: [{ index: ti, function: { name: c.got.slice(c.sent) } }] } })
      c.sent = c.got.length
    }
    return choices.length ? `data: ${JSON.stringify({ choices })}\n\n` : ""
  }
  const line = (l) => {
    const t = l.replace(/\r$/, "")
    if (!t.startsWith("data:")) return l
    const payload = t.slice(5).trim()
    if (payload === "[DONE]") return held() + l
    if (!payload.includes("tool_calls") && !payload.includes("function_call")) return l
    const ev = safeJson(payload)
    if (!ev || !Array.isArray(ev.choices)) return l
    let changed = false
    for (const [ci, choice] of ev.choices.entries()) {
      const delta = choice?.delta
      if (!delta || typeof delta !== "object") continue
      const index = Number.isInteger(choice.index) ? choice.index : ci
      for (const [k, call] of (Array.isArray(delta.tool_calls) ? delta.tool_calls : []).entries()) {
        const fn = call?.function
        if (!fn || typeof fn.name !== "string") continue
        const out = named(`${index}:${Number.isInteger(call.index) ? call.index : k}`, fn.name)
        if (out !== fn.name) {
          fn.name = out
          changed = true
        }
      }
      if (delta.function_call && typeof delta.function_call.name === "string") {
        const out = named(`${index}:fc`, delta.function_call.name)
        if (out !== delta.function_call.name) {
          delta.function_call.name = out
          changed = true
        }
      }
    }
    return changed ? `data: ${JSON.stringify(ev)}${l.endsWith("\r") ? "\r" : ""}` : l
  }
  const reader = stream.getReader()
  return new ReadableStream({
    async pull(controller) {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) {
          let rest = pending + dec.decode()
          pending = ""
          if (rest) rest = line(rest)
          rest += held()
          if (rest) controller.enqueue(enc.encode(rest))
          controller.close()
          return
        }
        pending += dec.decode(value, { stream: true })
        const cut = pending.lastIndexOf("\n")
        if (cut < 0) continue
        const whole = pending.slice(0, cut)
        pending = pending.slice(cut + 1)
        controller.enqueue(enc.encode(whole.split("\n").map(line).join("\n") + "\n"))
        return
      }
    },
    cancel(reason) {
      return reader.cancel(reason)
    },
  })
}

// ---- reading the gateway's answers -----------------------------------------

/** The JSON payloads of an SSE body, in arrival order, `[DONE]` skipped. */
function parseSseEvents(text) {
  const events = []
  for (const line of String(text).split(/\r?\n/)) {
    const s = line.trim()
    if (!s.startsWith("data:")) continue
    const payload = s.slice(5).trim()
    if (!payload || payload === "[DONE]") continue
    const parsed = safeJson(payload)
    if (parsed) events.push(parsed)
  }
  return events
}

/** The error code an answer carries (`TM.00001041`, `InferHub.4291.200`, …), or "". */
function errorCodeOf(text) {
  // Any number of named parts before the digits: `InferHub.ModelArts.81111.429`.
  const m = /"(?:error_code|code)"\s*:\s*"((?:[A-Za-z]+\.)*[A-Za-z]*[0-9][0-9A-Za-z.]*)"/.exec(String(text ?? ""))
  return m ? m[1] : ""
}

/** The vendor's own words for an error, so the agent can show them. */
function errorMessageOf(text) {
  const m = /"(?:error_msg|message)"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(String(text ?? ""))
  if (!m) return ""
  try {
    return JSON.parse(`"${m[1]}"`)
  } catch {
    return m[1]
  }
}

/** A 401/400 that only means the temporary AK/SK/security-token went stale. */
function isStaleCredential(text) {
  return /APIG\.0(301|307|602)|security token has expired|verify ak sk signature fail/i.test(String(text ?? ""))
}

/** Codes magpie should treat as "try another account later": quota or a rate limit. */
function isRateLimitCode(code) {
  return /4291|8111\d|(^|\.)429(\.|$)/.test(String(code ?? ""))
}

/**
 * The status for an error the gateway put inside a 200: 429 for a spent quota
 * or a rate limit (magpie moves to another account), 400 for a model or benefit
 * the account doesn't have (retrying can't help), 502 for the rest.
 */
function embeddedErrorStatus(code) {
  if (isRateLimitCode(code)) return 429
  if (/(^|\.)40[0-4](\.|$)|InferHub\.400[0-9]\./.test(String(code ?? ""))) return 400
  if (isNotMultimodal(code)) return 400
  return 502
}

/**
 * An image sent to a text-only model (`InferHub.001001020.406` "The request
 * model is not multimodal"): the request's content, which no retry and no
 * other account changes.
 */
function isNotMultimodal(codeOrText) {
  return /InferHub\.001001020\.406|not multimodal/i.test(String(codeOrText ?? ""))
}

/** Does this event carry part of an answer (not only a role or a keepalive)? */
function eventHasContent(event) {
  const choice = Array.isArray(event?.choices) ? event.choices[0] : undefined
  if (!choice) return false
  if (choice.finish_reason != null || choice.message) return true
  const delta = asRecord(choice.delta)
  if (typeof delta.content === "string" && delta.content) return true
  if (typeof delta.reasoning_content === "string" && delta.reasoning_content) return true
  return Array.isArray(delta.tool_calls) && delta.tool_calls.length > 0
}

/**
 * What the head of a 200 body is: "answer", an error code, or undefined (read
 * on). The gateway reports the session cap, a spent quota or an unknown model
 * as an error event inside a 200, sometimes after an empty role-only delta, and
 * a 200 never fails over — the caller just saw an empty reply.
 */
function classifyHead(text, done) {
  if (parseSseEvents(text).some(eventHasContent)) return "answer"
  if (done && Array.isArray(safeJson(text)?.choices)) return "answer"
  const code = errorCodeOf(text)
  // Wait for the error event's end, so its message is whole.
  if (code) return done || /\n/.test(text.slice(text.indexOf(code))) ? code : undefined
  // The stream's own end, never a "[DONE]" inside an event: the gateway's
  // rate-limit error carries `"text":"[DONE]"`.
  if (done || /^data:\s*\[DONE\]\s*$/m.test(text)) return "answer"
  return undefined
}

/** Read a 200's head until it is an answer or an error; keep what was read. */
async function peekAnswer(res) {
  const head = { code: "", text: "", chunks: [], reader: null, decoder: new TextDecoder() }
  if (!res.body) return head
  head.reader = res.body.getReader()
  let done = false
  for (;;) {
    const verdict = classifyHead(head.text, done)
    if (verdict) {
      if (verdict !== "answer") head.code = verdict
      break
    }
    if (head.text.length >= SSE_PEEK_LIMIT) break
    const r = await head.reader.read()
    if (r.done) {
      done = true
      continue
    }
    head.chunks.push(typed(r.value))
    head.text += head.decoder.decode(r.value, { stream: true })
  }
  // An error answer is dropped; not awaited, as Node's cancel can hang on a live body.
  if (head.code) void head.reader.cancel().catch(() => {})
  return head
}

/** Headers for a body handed over re-read: length/encoding no longer hold. */
function streamHeaders(headers) {
  const out = new Headers(headers)
  out.delete("content-encoding")
  out.delete("content-length")
  return out
}

/** The peeked bytes, then the rest of the stream; `release` once it ends. */
function replayBody(head, release) {
  let i = 0
  return new ReadableStream({
    async pull(controller) {
      try {
        if (i < head.chunks.length) {
          controller.enqueue(head.chunks[i++])
          return
        }
        const { done, value } = head.reader ? await head.reader.read() : { done: true }
        if (done) {
          release()
          controller.close()
          return
        }
        controller.enqueue(typed(value))
      } catch (e) {
        release()
        controller.error(e)
      }
    },
    cancel(reason) {
      release()
      void head.reader?.cancel(reason).catch(() => {})
    },
  })
}

/** Fold streamed `choices[].delta` chunks into one OpenAI completion object. */
function completionFromChunks(events) {
  const first = events[0] ?? {}
  const content = []
  const reasoning = []
  const toolCalls = []
  let finish = null
  let usage = null
  let model = first.model
  for (const ev of events) {
    if (ev.usage) usage = ev.usage
    if (typeof ev.model === "string" && ev.model) model = ev.model
    const choice = Array.isArray(ev.choices) ? ev.choices[0] : undefined
    if (!choice) continue
    if (choice.finish_reason != null) finish = choice.finish_reason
    const delta = asRecord(choice.delta)
    if (typeof delta.content === "string") content.push(delta.content)
    if (typeof delta.reasoning_content === "string") reasoning.push(delta.reasoning_content)
    for (const call of Array.isArray(delta.tool_calls) ? delta.tool_calls : []) {
      const slot = (toolCalls[num(call.index)] ??= { id: "", type: "function", function: { name: "", arguments: "" } })
      if (typeof call.id === "string" && call.id) slot.id = call.id
      if (typeof call.type === "string" && call.type) slot.type = call.type
      if (typeof call.function?.name === "string") slot.function.name += call.function.name
      if (typeof call.function?.arguments === "string") slot.function.arguments += call.function.arguments
    }
  }
  const message = { role: "assistant", content: content.join("") }
  if (reasoning.length > 0) message.reasoning_content = reasoning.join("")
  const calls = toolCalls.filter(Boolean)
  if (calls.length > 0) message.tool_calls = calls
  return {
    id: firstOf(first.id) || `chatcmpl-${randomHex(12)}`,
    object: "chat.completion",
    created: num(first.created) || Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, message, finish_reason: finish ?? (calls.length ? "tool_calls" : "stop") }],
    ...(usage ? { usage } : {}),
  }
}

/** Answer a caller that asked for JSON: read the whole stream, fold it. */
async function foldAnswer(res, head, names = null) {
  let text = head.text
  if (head.reader) {
    for (;;) {
      const { done, value } = await head.reader.read()
      if (done) break
      text += head.decoder.decode(value, { stream: true })
    }
    text += head.decoder.decode()
  }
  const headers = streamHeaders(res.headers)
  headers.set("content-type", "application/json")
  const events = parseSseEvents(text)
  if (events.some((ev) => Array.isArray(ev.choices) && ev.choices.length > 0)) {
    return new Response(JSON.stringify(restoreToolNames(completionFromChunks(events), names)), { status: res.status, statusText: res.statusText, headers })
  }
  // The gateway answered JSON after all, or nothing at all.
  const whole = safeJson(text)
  if (Array.isArray(whole?.choices)) {
    const body = names ? JSON.stringify(restoreToolNames(whole, names)) : text
    return new Response(body, { status: res.status, statusText: res.statusText, headers })
  }
  const code = errorCodeOf(text)
  return errorResponse(code ? embeddedErrorStatus(code) : 502, code, firstOf(errorMessageOf(text), "the gateway returned an empty answer"))
}

/** An OpenAI-shaped error carrying the vendor's code and words (magpie adds the provider name). */
function errorResponse(status, code, message, extraHeaders = {}) {
  return new Response(
    JSON.stringify({ error: { message: `${message}${code ? ` (${code})` : ""}`, type: status === 429 ? "rate_limit_exceeded" : "upstream_error", code: code || null } }),
    { status, headers: { "content-type": "application/json", ...extraHeaders } },
  )
}

/** A 401 magpie reads as "this sign-in is gone": it marks it and fails over. */
function signInExpiredResponse(text) {
  const body = text || JSON.stringify({ error: { message: "the sign-in expired; sign in again", type: "authentication_error" } })
  return new Response(body, { status: 401, headers: { "content-type": "application/json", "X-Magpie-Sign-In": "expired" } })
}

/**
 * A stale credential that couldn't be renewed: turned away for good, a 401
 * that marks the sign-in; or only for now (STS unreachable, a DPoP proof
 * refused), a 503 that keeps it, for magpie to try again or fail over.
 */
function unrenewedResponse(context, text) {
  if (context.signInDead?.()) return signInExpiredResponse(text)
  return errorResponse(503, errorCodeOf(text), "临时凭据已过期，续期暂时失败，请稍后再试", { "X-Magpie-Sign-In": "kept" })
}

/** Rebuild a response whose body was read, keeping the vendor's answer. */
function rebuildResponse(res, text, extraHeaders = {}) {
  const headers = streamHeaders(res.headers)
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v)
  return new Response(text, { status: res.status, statusText: res.statusText, headers })
}

// ---- the account's session budget ------------------------------------------

/**
 * Per-account gate for in-flight chats: a burst queues here rather than come
 * back as `TM.00001041`. `acquire` resolves to that permit's release (safe to
 * call twice); a permit is let go by itself after PERMIT_MAX_HOLD_MS.
 */
function createConcurrencyGate(limit) {
  let active = 0
  const waiters = []
  const grant = () => {
    active += 1
    let held = true
    const release = () => {
      if (!held) return
      held = false
      clearTimeout(timer)
      active -= 1
      while (active < limit && waiters.length > 0) waiters.shift().admit()
    }
    const timer = setTimeout(release, PERMIT_MAX_HOLD_MS)
    timer.unref?.()
    return release
  }
  return {
    get active() { return active },
    get waiting() { return waiters.length },
    acquire(signal) {
      if (signal?.aborted) return Promise.reject(abortError(signal))
      if (active < limit) return Promise.resolve(grant())
      return new Promise((resolve, reject) => {
        const onAbort = () => {
          const i = waiters.indexOf(waiter)
          if (i >= 0) waiters.splice(i, 1)
          reject(abortError(signal))
        }
        const waiter = {
          admit() {
            signal?.removeEventListener("abort", onAbort)
            resolve(grant())
          },
        }
        signal?.addEventListener("abort", onAbort, { once: true })
        waiters.push(waiter)
      })
    },
  }
}

function abortError(signal) {
  return signal?.reason instanceof Error ? signal.reason : new DOMException("The operation was aborted.", "AbortError")
}

/** Sleep, but give up as soon as the caller aborts the request. */
function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError(signal))
      return
    }
    const onAbort = () => {
      clearTimeout(timer)
      reject(abortError(signal))
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort)
      resolve()
    }, ms)
    signal?.addEventListener("abort", onAbort, { once: true })
  })
}

/** The wait before retry `attempt` (±20% so concurrent callers spread out). */
function retryDelayMs(attempt, delays = SESSION_RETRY_DELAYS_MS) {
  const base = delays[Math.min(attempt, delays.length - 1)] ?? 0
  return Math.round(base * (0.8 + Math.random() * 0.4))
}

/** The queue a 429 put the request in, from its headers; undefined when it is no queue. */
function queueInfoOf(headers) {
  if (String(headers?.get("queue-status") ?? "").toLowerCase() !== "queued") return undefined
  const traceId = headers.get("trace-id")
  if (!traceId) return undefined
  const after = Number(headers.get("retry-after") ?? 5)
  return { traceId, retryAfter: Number.isFinite(after) && after >= 0 ? after : 5 }
}

/** One signed call on a queued trace: GET is where it stands, DELETE takes it out. */
async function traceQueueCall(method, cred, traceId, context, signal) {
  const url = TRACE_QUEUE_URL(traceId)
  const headers = await signFor(cred, method, url, new Uint8Array())
  headers.set(SESSION_HEADER, context.sessionId)
  return context.fetcher(url, { method, headers, signal, redirect: "error" })
}

/** The caller's signal, bounded to `ms` from now: a call that hangs can't outlast the wait it is part of. */
function withinMs(signal, ms) {
  const timeout = AbortSignal.timeout(Math.max(0, Math.min(ms, REQUEST_TIMEOUT_MS)))
  return signal ? AbortSignal.any([signal, timeout]) : timeout
}

/**
 * Wait in the gateway's queue the way the CodeArts agent does: poll every
 * `retry-after` seconds until the trace is promoted (then the request is sent
 * again), and leave the queue when the caller gives up or the wait runs out.
 * Gives "promoted" or "gone"; throws the abort.
 */
async function waitInQueue(cred, queued, context, signal, deadline) {
  const leave = () => void traceQueueCall("DELETE", cred, queued.traceId, context, AbortSignal.timeout(REQUEST_TIMEOUT_MS)).catch(() => {})
  let retryAfter = queued.retryAfter
  let failures = 0
  try {
    for (;;) {
      if (Date.now() + retryAfter * 1000 > deadline) {
        leave()
        return "gone"
      }
      await delay(retryAfter * 1000, signal)
      let body = null
      try {
        // The poll and its answer are bounded by what is left of the wait.
        const res = await traceQueueCall("GET", cred, queued.traceId, context, withinMs(signal, deadline - Date.now()))
        body = safeJson(await res.text())
        if (!res.ok && !body?.status) throw new Error(`HTTP ${res.status}`)
      } catch (e) {
        if (signal?.aborted) throw e
        if (++failures >= 3) {
          leave()
          return "gone"
        }
        continue
      }
      const status = String(body?.status ?? "queued")
      if (status === "promoted") return "promoted"
      if (status === "not_found" || status === "error") return "gone"
      retryAfter = num(body?.retry_after) || retryAfter
    }
  } catch (e) {
    leave()
    throw e
  }
}

/** The host of a URL, "" when it isn't one. */
function hostOf(url) {
  try {
    return new URL(url).hostname
  } catch {
    return ""
  }
}

/** Is this an https URL on one of SIGNED_HOSTS (its default port), the only ones the credentials go to? */
function isSignedHostUrl(url) {
  try {
    const u = new URL(url)
    return u.protocol === "https:" && SIGNED_HOSTS.has(u.host)
  } catch {
    return false
  }
}

const refusalTo = (url) =>
  `refusing to sign a request to ${hostOf(url) || "an unknown host"}: only CodeArts' own hosts (${[...SIGNED_HOSTS].join(", ")}) get the account's credentials`

/**
 * The SDK-HMAC-SHA256 headers for one request (all but `host`, which fetch
 * sets), signed only for SIGNED_HOSTS: whichever route asks, now or added
 * later, the account's credentials sign nothing else. Every signed call also
 * goes with `redirect: "error"`: a redirect would forward the security token
 * to wherever it points.
 */
async function signFor(cred, method, url, body, extraSigned) {
  if (!isSignedHostUrl(url)) throw new Error(refusalTo(url))
  const signed = await signRequestHuawei(
    cred.access_key_id, cred.secret_access_key, cred.security_token,
    method, url, body, extraSigned,
  )
  const headers = new Headers()
  signed.forEach((value, key) => {
    if (key !== "host") headers.set(key, value)
  })
  return headers
}

/** Mark a 401/403 the way magpie reads a sign-in that is gone. */
function withSignInMark(res) {
  if (res.status !== 401 && res.status !== 403) return res
  const h = new Headers(res.headers)
  h.set("X-Magpie-Sign-In", "expired")
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h })
}

/**
 * The plugin's per-request fetch. A chat is reshaped (see prepareChatBody),
 * signed with the account's temporary credentials and sent under the account's
 * one Chat-Id/Session-Id, after taking one of its in-flight permits. Then:
 * - `TM.00001041` (a 400, or a 200's first event) is retried, re-signed, until
 *   a session frees or the budget runs out — then a 429, which magpie fails
 *   over on;
 * - a stale credential (401, `APIG.0602`) is renewed once and the request sent
 *   again; when STS turns the renewal away for good, a 401 marks the sign-in,
 *   and when it only fails for now, a 503 keeps it;
 * - `benefit not found` on a day not yet claimed claims it and sends again;
 *   otherwise the model goes as the account's builtin one, if it has it;
 * - a 200 carrying only an error (a spent quota, an unknown model) becomes a
 *   429/502 with the vendor's words instead of an empty reply.
 * The permit is held until the answer's body ends: the gateway counts the
 * session while it streams. Only SIGNED_HOSTS are signed for: a request
 * anywhere else (an overridden `api`, say) is refused before the access key or
 * security token leave.
 */
async function signedFetch(cred, input, init, context) {
  const req = typeof Request !== "undefined" && input instanceof Request ? input : null
  const url = req ? req.url : String(input)
  if (!isSignedHostUrl(url)) return errorResponse(400, "", refusalTo(url))
  const method = String(init?.method ?? req?.method ?? "GET").toUpperCase()
  const baseHeaders = new Headers(init?.headers ?? req?.headers)
  // magpie says another account, provider or group member follows this
  // request (X-Magpie-Fallback): a queued request isn't waited out then.
  // magpie's own header, never CodeArts'
  const fallback = baseHeaders.get(FALLBACK_HEADER) === "1"
  baseHeaders.delete(FALLBACK_HEADER)
  let body
  if (init?.body != null) body = await toBytes(init.body)
  else if (req) body = new Uint8Array(await req.clone().arrayBuffer())
  else body = new Uint8Array()
  // The body is part of the signature, so it is reshaped before signing.
  const parsed = body.length > 0 ? safeJson(new TextDecoder().decode(body)) : null
  const chat = prepareChatBody(parsed, context)
  if (chat) body = utf8(JSON.stringify(chat.body))
  const model = upstreamModelId(parsed?.model)
  let extra = isBenefitModel(model, context.state) ? { maas_type: "benefit" } : undefined
  const signal = init?.signal ?? req?.signal ?? undefined

  let active = cred
  const send = async () => {
    const signed = await signFor(active, method, url, body, extra)
    const headers = new Headers(baseHeaders)
    // The body may have been reshaped: the transport counts it again.
    headers.delete("content-length")
    signed.forEach((value, key) => headers.set(key, value))
    headers.set("Chat-Id", context.chatId)
    headers.set("Session-Id", context.sessionId)
    // The session headers the CodeArts agent sends: one session per account,
    // a fresh trace per request.
    headers.set(SESSION_HEADER, context.sessionId)
    headers.set("user-session-id", context.sessionId)
    headers.set("x-ot-parent-session-id", "")
    headers.set("x-ot-trace-id", randomHex(16))
    headers.set("x-ot-span-id", randomHex(8))
    headers.set("x-snap-traceid", randomHex(16))
    headers.set("lang", "en")
    return context.fetcher(url, {
      ...init,
      method,
      headers,
      ...(body.length > 0 ? { body } : {}),
      ...(signal ? { signal } : {}),
      // After the caller's init, so no caller turns it back on.
      redirect: "error",
    })
  }

  // A sign-in known to be beyond renewal never reaches the network again.
  if (context.signInDead?.()) return signInExpiredResponse()
  if (!chat) {
    const res = await send()
    if (res.status !== 401 || !context.renewCredential) return withSignInMark(res)
    const text = await res.text().catch(() => "")
    const next = await context.renewCredential(active)
    if (!next) return unrenewedResponse(context, text)
    active = next
    return withSignInMark(await send())
  }

  const release = await context.gate.acquire(signal)
  let handedOver = false
  try {
    const clock = context.now ?? Date.now
    const started = clock()
    let renewed = false
    let claimTried = false
    let queueDeadline = 0
    for (let attempt = 0; ; attempt += 1) {
      const res = await send()
      let text
      let code
      if (res.status === 429) {
        const queued = queueInfoOf(res.headers)
        if (queued) {
          void res.body?.cancel().catch(() => {})
          if (fallback) {
            // the next candidate is asked at once: this one leaves the
            // queue, and says why it gave way and when to ask it again
            void traceQueueCall("DELETE", active, queued.traceId, context, AbortSignal.timeout(REQUEST_TIMEOUT_MS)).catch(() => {})
            const wait = Math.max(1, Math.ceil(queued.retryAfter))
            return errorResponse(503, "", `CodeArts queued the request; try again in ${wait}s`, { "retry-after": String(wait) })
          }
          queueDeadline ||= Date.now() + (context.queueBudgetMs ?? QUEUE_BUDGET_MS)
          if ((await waitInQueue(active, queued, context, signal, queueDeadline)) === "promoted") continue
          return errorResponse(429, "", "排队等待超时或已被移出队列，请稍后再试")
        }
      }
      if (res.ok) {
        const head = await peekAnswer(res)
        if (!head.code) {
          if (chat.fold) return await foldAnswer(res, head, chat.names)
          handedOver = true
          const stream = restoreToolNamesInStream(replayBody(head, release), chat.names)
          return new Response(stream, { status: res.status, statusText: res.statusText, headers: streamHeaders(res.headers) })
        }
        text = head.text
        code = head.code
      } else {
        text = await res.text().catch(() => "")
        code = errorCodeOf(text)
      }

      if (res.status === 401 || isStaleCredential(text)) {
        if (!renewed && context.renewCredential) {
          renewed = true
          const next = await context.renewCredential(active)
          if (next) {
            active = next
            continue
          }
          return unrenewedResponse(context, text)
        }
        return signInExpiredResponse(text)
      }
      if (res.status === 403) return rebuildResponse(res, text, { "X-Magpie-Sign-In": "expired" })
      // The thinking parameter is the plugin's own: a model that refuses it
      // gets the request again as the caller wrote it.
      if (res.status === 400 && chat.injected && /thinking/i.test(text)) {
        chat.injected = false
        delete chat.body.thinking
        body = utf8(JSON.stringify(chat.body))
        continue
      }
      if (extra && /InferHub\.400[45]\.200|benefit not found/i.test(code || text)) {
        // A new Beijing day whose benefit isn't claimed yet: claim it, as the
        // agent does each day, and send it again as the free model.
        if (!claimTried && context.state && context.state.claim?.day !== beijingDay()) {
          claimTried = true
          if (await ensureBenefitClaimed(active, context.fetcher, context.state)) continue
        }
        // No free benefit for this model on this account (`4004`), or the
        // header isn't taken for it (`4005`): it is the account's plain
        // builtin model, till the next day's claim.
        if (isRegularModel(model, context.state)) {
          context.state?.noBenefit.add(model)
          extra = undefined
          continue
        }
      }
      if (code === SESSION_LIMIT_ERROR || text.includes(SESSION_LIMIT_ERROR)) {
        const wait = retryDelayMs(attempt, context.retryDelays)
        if (clock() - started + wait <= (context.retryBudgetMs ?? SESSION_RETRY_BUDGET_MS)) {
          await (context.sleep ?? delay)(wait, signal)
          continue
        }
        return errorResponse(429, SESSION_LIMIT_ERROR, firstOf(errorMessageOf(text), "并发会话数已达上限，请稍后再试"))
      }
      // an image the model can't take is the request's fault, whatever
      // status it came with
      if (!res.ok && isNotMultimodal(code || text)) return errorResponse(400, code, firstOf(errorMessageOf(text), "the model takes no images"))
      if (!res.ok) return rebuildResponse(res, text)
      return errorResponse(embeddedErrorStatus(code), code, firstOf(errorMessageOf(text), "the gateway answered with an error"))
    }
  } finally {
    if (!handedOver) release()
  }
}

/** A signed GET returning the response text, or undefined on any failure. */
async function signedGet(url, cred, fetcher, extraUnsignedHeaders) {
  try {
    const headers = await signFor(cred, "GET", url, new Uint8Array())
    for (const [k, v] of Object.entries(extraUnsignedHeaders ?? {})) headers.set(k, v)
    const res = await fetcher(url, { method: "GET", headers, redirect: "error", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
    if (!res.ok) return undefined
    return await res.text()
  } catch {
    return undefined
  }
}

/** A failed answer as one line: the gateway's own code and words, not just the status. */
function describeHttpFailure(status, text) {
  const raw = safeJson(text)
  const detail = raw
    ? [firstOf(raw.error_code, String(raw.code ?? "")), firstOf(raw.error_msg, raw.message, raw.msg)].filter(Boolean).join(" ")
    : String(text ?? "").trim().slice(0, 200)
  return detail ? `HTTP ${status}: ${detail}` : `HTTP ${status}`
}

/**
 * A signed snap-access call the way the IDE's ActivityWelfarePane makes it:
 * `{ code, message, data }` back, `code !== 0` being a refusal.
 * Gives `{ ok: true, data }` or `{ ok: false, message }`, never throws.
 */
async function snapRequest(method, url, cred, fetcher, payload) {
  const body = payload === undefined ? new Uint8Array() : utf8(JSON.stringify(payload))
  let res
  let text
  try {
    const headers = await signFor(cred, method, url, body)
    for (const [k, v] of Object.entries(SNAP_EXTRA_HEADERS)) headers.set(k, v)
    res = await fetcher(url, {
      method,
      headers,
      ...(payload === undefined ? {} : { body }),
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    text = await res.text()
  } catch (e) {
    return { ok: false, message: e?.message ?? String(e) }
  }
  if (!res.ok) return { ok: false, message: describeHttpFailure(res.status, text) }
  const raw = safeJson(text)
  if (!raw || Array.isArray(raw)) return { ok: false, message: "the answer could not be read" }
  if (raw.code !== undefined && Number(raw.code) !== 0) {
    return { ok: false, message: firstOf(raw.message, raw.msg, `code ${raw.code}`) }
  }
  return { ok: true, data: "data" in raw ? raw.data : raw }
}

// ---- daily check-in ----------------------------------------------------------

/** The account's 「每日领取」 campaign from the activity list, or a reason it can't be read. */
async function dailyCampaign(cred, fetcher) {
  const listed = await snapRequest("GET", OPS_DELIVERY_URL, cred, fetcher)
  if (!listed.ok) return { error: `活动列表读取失败：${listed.message}` }
  const items = asRecord(listed.data).items
  if (!Array.isArray(items)) return { error: "活动列表缺少 items" }
  return { item: items.find((it) => asRecord(it).type === DAILY_CHECKIN_TYPE) }
}

const isClaimedToday = (item) => !item?.claimable && CLAIMED_STATUSES.includes(item?.status)

// ---- credit batches and when they lapse ------------------------------------

const PACKAGE_TYPE_METRICS = {
  basic: "usageBasicPackageCredit",
  ondemand: "usageOnDemandPackageCredit",
  bonus: "usageBonusPackageCredit",
}

/**
 * Every credit batch the account holds, as `{ metric, amount, left, expiresAt }`
 * (`metric` the statistics bucket it counts in, `expiresAt` ms): the packages
 * from `package/credit/page`, and each campaign's grants from `ops/credit`.
 * Undefined when none of it could be read.
 */
async function fetchCreditBatches(cred, fetcher) {
  const batches = []
  let reached = false
  for (const query of PACKAGE_CREDIT_QUERIES) {
    const r = await snapRequest("POST", PACKAGE_CREDIT_PAGE_URL, cred, fetcher, query)
    const list = asRecord(r.data).list
    if (!r.ok || !Array.isArray(list)) continue
    reached = true
    for (const p of list) {
      const metric = PACKAGE_TYPE_METRICS[asRecord(p).packageType]
      if (!metric) continue
      const amount = num(p.creditAmount)
      batches.push({ metric, amount, left: Math.max(0, amount - num(p.creditUsed)), expiresAt: vendorDate(p.expiredTime) })
    }
  }
  const overview = await snapRequest("GET", OPS_CREDIT_OVERVIEW_URL, cred, fetcher)
  const campaigns = asRecord(overview.data).items
  if (overview.ok && Array.isArray(campaigns)) {
    reached = true
    for (const c of campaigns) {
      const left = num(c?.totalClaimed) - num(c?.totalConsumed) - num(c?.totalExpired)
      if (left <= 0 || c.campaignId === undefined || c.campaignId === null) continue
      const page = await snapRequest("GET", OPS_CREDIT_CAMPAIGN_URL(c.campaignId), cred, fetcher)
      for (const b of Array.isArray(asRecord(page.data).benefits) ? page.data.benefits : []) {
        const amount = num(b?.claimedAmount)
        batches.push({
          metric: PACKAGE_TYPE_METRICS.bonus,
          amount,
          left: Math.max(0, amount - num(b.consumedAmount) - num(b.expiredAmount)),
          expiresAt: vendorDate(b.expireAt),
        })
      }
    }
  }
  return reached ? batches : undefined
}

/**
 * When the soonest still-good batch lapses, and what lapses that Beijing day
 * (a sign-up grant and that day's check-in go a minute apart). Undefined when
 * nothing is left to lapse.
 */
function soonestLapse(batches, now = Date.now()) {
  const live = (batches ?? []).filter((b) => b.left > 0 && b.expiresAt > now)
  if (live.length === 0) return undefined
  const at = Math.min(...live.map((b) => b.expiresAt))
  const day = beijingDay(at)
  return { at, credit: live.filter((b) => beijingDay(b.expiresAt) === day).reduce((n, b) => n + b.left, 0) }
}

/** The plugin's own check-in ledger as batches, for when the vendor's can't be read. */
const grantBatches = (grants) =>
  (grants ?? []).map((g) => ({ metric: PACKAGE_TYPE_METRICS.bonus, amount: num(g.credit), left: num(g.credit), expiresAt: vendorDate(g.expiresAt) }))

// ---- the check-in ledger -----------------------------------------------------
//
// CodeArts tells how many credits a bucket holds, never when each given batch
// lapses; check-in credits are good for 30 days from their day. The plugin keeps
// the claims it made, per account, so the usage card can say when the soonest
// of them runs out. Best effort: a ledger that can't be read or written only
// leaves that line out.

const LEDGER_KEEP_DAYS = 40

const defaultLedgerPath = () =>
  process.env.MAGPIE_CODEARTS_LEDGER || path.join(os.homedir(), ".config", "magpie", "codearts-checkins.json")

function readLedger(file) {
  try {
    const raw = safeJson(fs.readFileSync(file, "utf8"))
    return raw && !Array.isArray(raw) ? raw : {}
  } catch {
    return {}
  }
}

/** The check-in credits the plugin claimed for `account`. */
function readGrants(file, account) {
  const list = readLedger(file)[account]
  return Array.isArray(list) ? list : []
}

function writeLedger(file, all) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.${process.pid}.tmp`
  fs.writeFileSync(tmp, JSON.stringify(all, null, 2))
  fs.renameSync(tmp, file)
}

/** Keep one claim (one a Beijing day), dropping what lapsed long ago. */
function recordGrant(file, account, grant) {
  try {
    const all = readLedger(file)
    const keep = Date.now() - LEDGER_KEEP_DAYS * 86_400_000
    const day = beijingDay(vendorDate(grant.at))
    const list = (Array.isArray(all[account]) ? all[account] : [])
      .filter((g) => (vendorDate(g.expiresAt) ?? 0) > keep && beijingDay(vendorDate(g.at) ?? 0) !== day)
    all[account] = [...list, grant]
    writeLedger(file, all)
  } catch {
    /* best effort */
  }
}

// The claim this plugin made today whose confirm failed, per account: the
// next check-in confirms it, whichever magpie (or OpenCode) on this machine
// runs it. A claim the IDE leaves unconfirmed (`id: null`) is never kept
// here, so it is never confirmed. Kept for its Beijing day only.
const UNCONFIRMED = "_unconfirmed"

/** Today's claim this plugin left unconfirmed for `account`, if any. */
function readUnconfirmed(file, account) {
  const left = asRecord(asRecord(readLedger(file)[UNCONFIRMED])[account])
  return left.day === beijingDay() ? left : undefined
}

/** Keep the claim left unconfirmed for `account`, or with null drop it; other days' go. */
function recordUnconfirmed(file, account, left) {
  try {
    const all = readLedger(file)
    const today = beijingDay()
    const kept = Object.fromEntries(
      Object.entries(asRecord(all[UNCONFIRMED])).filter(([k, v]) => k !== account && asRecord(v).day === today),
    )
    if (left) kept[account] = { ...left, day: today }
    all[UNCONFIRMED] = kept
    writeLedger(file, all)
  } catch {
    /* best effort */
  }
}

/** When a claimed benefit lapses: the vendor's date when the claim says one, else 30 days on. */
function grantExpiry(benefit, at) {
  for (const k of ["expire_time", "expireTime", "expired_time", "expiredTime", "expire_at", "expireAt", "valid_end_time", "end_time", "endTime"]) {
    const v = vendorDate(benefit?.[k])
    if (v) return v
  }
  return at + CHECKIN_CREDIT_DAYS * 86_400_000
}

/**
 * Press the daily check-in, exactly as the IDE's 「限时福利 → 每日领取」 does:
 * list the activities, claim the `USER_LOGIN` one with `{campaignId, channel}`,
 * and confirm it when the claim answers an id (`benefit.id !== null`), or the
 * credits stay pending. Answers magpie's check-in outcome; never throws.
 * `unconfirmed` is today's claim this plugin left unconfirmed (the ledger's);
 * an answer's own `unconfirmed` is one to keep there.
 */
async function dailyCheckin(cred, fetcher, { unconfirmed } = {}) {
  const first = await dailyCampaign(cred, fetcher)
  if (first.error) return { outcome: "failed", message: first.error }
  const item = first.item
  if (!item) return { outcome: "inactive", message: "当前没有每日领取活动" }
  const credit = num(item.benefitAmount)
  // Claimed here, but the confirm failed: confirm it now, or the credits stay
  // pending. Only that claim: one the IDE leaves unconfirmed is `CLAIMED` as
  // well, and the IDE never confirms it. When the confirm fails, only the
  // activity tells whether it was confirmed after all; still claimed, it is a
  // failure magpie tries again later that day.
  const campaign = item.campaignId !== undefined && item.campaignId !== null && item.campaignId !== ""
  const leftHere = unconfirmed && String(unconfirmed.campaignId) === String(item.campaignId)
  if (!item.claimable && item.status === "CLAIMED" && campaign && leftHere) {
    const confirmed = await snapRequest("POST", OPS_CONFIRM_URL, cred, fetcher, { campaignId: item.campaignId })
    if (confirmed.ok) return claimedOutcome(asRecord(unconfirmed.benefit), credit)
    const again = await dailyCampaign(cred, fetcher)
    if (isClaimedToday(again.item) && again.item.status !== "CLAIMED") return { outcome: "done", message: "今天已领取" }
    return { outcome: "failed", message: `领取确认失败：${confirmed.message}` }
  }
  if (isClaimedToday(item)) return { outcome: "done", message: "今天已领取" }
  if (!item.claimable) return { outcome: "ineligible", message: `当前不可领取（status=${item.status ?? "null"}）` }
  if (!campaign) return { outcome: "failed", message: "活动缺少 campaignId" }

  const claimed = await snapRequest("POST", OPS_CLAIM_URL, cred, fetcher, { campaignId: item.campaignId, channel: OPS_CHANNEL })
  if (!claimed.ok) {
    // Claimed elsewhere a moment ago (the IDE, another magpie): look again.
    const again = await dailyCampaign(cred, fetcher)
    if (isClaimedToday(again.item)) return { outcome: "done", message: "今天已领取" }
    return { outcome: "failed", message: `领取失败：${claimed.message}` }
  }
  const benefit = asRecord(claimed.data)
  if (claimed.data && benefit.id !== null) {
    const confirmed = await snapRequest("POST", OPS_CONFIRM_URL, cred, fetcher, { campaignId: item.campaignId })
    if (!confirmed.ok) {
      return { outcome: "failed", message: `领取确认失败：${confirmed.message}`, unconfirmed: { campaignId: item.campaignId, benefit } }
    }
  }
  return claimedOutcome(benefit, credit)
}

/** The outcome of a check-in that went through, with the grant the ledger keeps. */
function claimedOutcome(benefit, credit) {
  const got = num(benefit.benefitAmount) || credit
  const at = Date.now()
  const grant = { at: new Date(at).toISOString(), credit: got, expiresAt: new Date(grantExpiry(benefit, at)).toISOString() }
  return { outcome: "claimed", ...(got > 0 ? { credit: got } : {}), message: got > 0 ? `+${got} 积分` : "已领取", grant }
}

// ---- model list & account info ---------------------------------------------

/**
 * One gateway/builtin entry as a model row. The id is the one published, never
 * the date-stripped one (a dated id and its bare form are two models with
 * opposite billing), so dedupe is by exact id too.
 */
function parseModelInfo(m, seen) {
  const id = m?.model_id
  if (typeof id !== "string" || !id) return undefined
  const base = normalizeModelId(id)
  // Hide vision models: small context, no tool calls — not agent main models.
  // Case-insensitive: the gateway lists some lowercase (`kimi-k2.6-vl`).
  if (/-vl(-|$)/i.test(base)) return undefined
  if (seen.has(id)) return undefined
  seen.add(id)
  const rawName = m.model_name
  const name = typeof rawName === "string" && rawName ? normalizeModelId(rawName) : prettify(base)
  const info = { id, name, context: num(m.context_window) || CONTEXT_WINDOWS[base] }
  const output = num(m.max_tokens)
  if (output > 0) info.output = Math.min(output, MAX_OUTPUT_TOKENS)
  return info
}

function extractArray(text, path) {
  const root = safeJson(text)
  if (!root) return undefined
  let value = root
  for (const key of path) {
    if (typeof value !== "object" || value === null) return undefined
    value = value[key]
  }
  return Array.isArray(value) ? value : undefined
}

/**
 * Claim today's free benefit (`POST /api/v1/benefit/claim`, an empty JSON
 * body), as the CodeArts agent does before it offers the free models.
 * Gives `{ ok, code, message }`; `network: true` when the vendor wasn't reached.
 */
async function claimBenefit(cred, fetcher) {
  const body = utf8("{}")
  try {
    const headers = await signFor(cred, "POST", BENEFIT_CLAIM_URL, body)
    headers.set("x-snap-traceid", randomHex(16))
    const res = await fetcher(BENEFIT_CLAIM_URL, { method: "POST", headers, body, redirect: "error", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
    const data = safeJson(await res.text())
    const code = firstOf(String(data?.error_code ?? "")) || `HTTP ${res.status}`
    return { ok: code === BENEFIT_OK, code, message: firstOf(data?.error_msg, data?.message) }
  } catch (e) {
    return { ok: false, network: true, code: "", message: e?.message ?? String(e) }
  }
}

// A refused claim is asked again this long after, not on every listing.
const CLAIM_RETRY_MS = 60 * 60 * 1000

/**
 * Is today's free benefit the account's? Claimed once a Beijing day (one claim
 * at a time); a refusal is asked again an hour later, and a vendor that can't
 * be reached leaves the last answer standing. A claim that goes through starts
 * the day afresh: the models the last one had no benefit for are asked again.
 */
function ensureBenefitClaimed(cred, fetcher, state) {
  const day = beijingDay()
  const was = state.claim
  if (was?.day === day && (was.ok || Date.now() - was.at < CLAIM_RETRY_MS)) return Promise.resolve(was.ok)
  state.claiming ??= claimBenefit(cred, fetcher)
    .then((r) => {
      if (r.network) return was?.ok ?? false
      state.claim = { day, ok: r.ok, at: Date.now(), code: r.code, message: r.message }
      if (r.ok) state.noBenefit?.clear()
      return r.ok
    })
    .finally(() => { state.claiming = null })
  return state.claiming
}

/**
 * One model of the CodeAgent's detail: its id is `model_parameters.model_id`
 * (what a request names), with the credit rate and the parameters the agent
 * itself reads — `thinking_type` set means a reasoning model.
 */
function parseAgentModel(m) {
  const p = asRecord(m?.model_parameters)
  const id = firstOf(p.model_id, m?.model_id)
  if (!id) return undefined
  const output = num(p.max_tokens)
  return {
    id,
    name: firstOf(m.display_name, m.model_name),
    rate: creditRateOf(m.credit ?? p.credit),
    ...(p.thinking_type != null ? { reasoning: true } : {}),
    context: num(p.context_window),
    ...(output > 0 ? { output: Math.min(output, MAX_OUTPUT_TOKENS) } : {}),
    // Configured by a user or a tenant, not one of CodeArts' own.
    own: m.model_type === "third" || m.model_type === "custom" || m.is_custom_model === true,
    hidden: m.display_enabled === false || p.display_enabled === false,
  }
}

/**
 * The agents to ask for a model list, best first: the account's main agent
 * (`original_id` "build", else CodeAgent), the rest of its agents, then the
 * IDE's own id for the main agent.
 */
async function agentCandidates(cred, fetcher) {
  const root = safeJson(await signedGet(AGENT_LIST_URL, cred, fetcher, AGENT_CENTER_HEADERS) ?? "")
  const agents = (Array.isArray(root?.agents) ? root.agents : Array.isArray(root?.data?.agents) ? root.data.agents : [])
    .filter((a) => typeof a?.agent_id === "string" && a.agent_id)
  const rank = (a) => {
    const i = MAIN_AGENT_ORIGINAL_IDS.indexOf(firstOf(a.original_id) || a.agent_id)
    return i < 0 ? MAIN_AGENT_ORIGINAL_IDS.length : i
  }
  const ids = [...agents].sort((a, b) => rank(a) - rank(b)).map((a) => a.agent_id)
  return [...new Set([...ids, MAIN_AGENT_FALLBACK_ID])]
}

/**
 * The main agent's models (`agents/detail` → `gpts.models`), carrying each
 * model's credit rate. The agent that answered with a list is kept on `state`.
 */
async function fetchAgentModels(cred, fetcher, state) {
  const read = async (id) => {
    const root = safeJson(await signedGet(AGENT_DETAIL_URL(id), cred, fetcher, AGENT_CENTER_HEADERS) ?? "")
    const models = root?.gpts?.models ?? root?.data?.gpts?.models
    return Array.isArray(models) && models.length ? models.map(parseAgentModel).filter(Boolean) : undefined
  }
  if (state.agentId) {
    const known = await read(state.agentId)
    if (known) return known
    state.agentId = ""
  }
  for (const id of (await agentCandidates(cred, fetcher)).slice(0, AGENT_DETAIL_TRIES)) {
    const models = await read(id)
    if (models) {
      state.agentId = id
      return models
    }
  }
  return undefined
}

/**
 * Fetch the account's live model list and merge it:
 * - the free models gateway/config lists, but only once today's benefit is
 *   claimed for the account (else they are left out: they answer `benefit not
 *   found`, and the plain builtin model of the same id stays);
 * - the builtin models;
 * - the main agent's own list, which gives every model its credit rate and
 *   adds the ones the builtin list leaves out.
 * `state` is the account's own: its claim, agent id, free models
 * (`state.benefit`) and builtin ones (`state.regular`) are kept there and
 * nowhere else. Without one the free list is taken as it is published.
 */
async function fetchRemoteModels(cred, fetcher, state) {
  const models = []
  const seen = new Set()
  const benefitIds = []

  const gatewayText = await signedGet(OPENGW_GATEWAY_CONFIG_URL, cred, fetcher)
  const gateway = gatewayText === undefined ? undefined : extractArray(gatewayText, ["result", "models"])
  const claimed = gateway?.length ? (state ? await ensureBenefitClaimed(cred, fetcher, state) : true) : false
  for (const item of claimed ? gateway : []) {
    if (typeof item !== "object" || item === null) continue
    const mi = parseModelInfo(item, seen)
    if (!mi) continue
    mi.benefit = true
    benefitIds.push(mi.id)
    models.push(mi)
  }

  const snapText = await signedGet(SNAP_MODEL_BUILTIN_URL, cred, fetcher, {
    "Content-Type": "application/json",
    ...SNAP_EXTRA_HEADERS,
  })
  const builtin = snapText === undefined ? undefined : extractArray(snapText, ["builtinModels"])
  const regularIds = []
  for (const item of builtin ?? []) {
    if (typeof item !== "object" || item === null) continue
    if (typeof item.model_id === "string") regularIds.push(item.model_id)
    const mi = parseModelInfo(item, seen)
    if (mi) models.push(mi)
  }

  // Rates and parameters from the agent's own list; a model only it lists is
  // one more the account can call.
  const agent = await fetchAgentModels(cred, fetcher, state ?? {}).catch(() => undefined)
  for (const a of agent ?? []) {
    const mi = models.find((m) => m.id === a.id)
    if (mi) {
      if (a.rate > 0 && !mi.benefit) mi.rate = a.rate
      if (a.reasoning) mi.reasoning = true
      // The limits the agent itself runs the model with.
      if (a.context > 0) mi.context = a.context
      if (a.output) mi.output = a.output
    } else if (!a.own && !a.hidden && !/-vl(-|$)/i.test(normalizeModelId(a.id))) {
      models.push({
        id: a.id,
        name: a.name ? normalizeModelId(a.name) : prettify(normalizeModelId(a.id)),
        context: a.context || CONTEXT_WINDOWS[normalizeModelId(a.id)],
        ...(a.output ? { output: a.output } : {}),
        ...(a.rate > 0 ? { rate: a.rate } : {}),
        ...(a.reasoning ? { reasoning: true } : {}),
      })
      regularIds.push(a.id)
    }
  }

  // The account's own lists: an answered list is the truth, an empty one
  // included; a failed read keeps what was known.
  if (state) {
    if (gateway) state.benefit = new Set(benefitIds)
    if (builtin) state.regular = new Set(regularIds)
  }
  return models
}

/** Chinese labels for the credit metric buckets CodeArts reports. */
const CREDIT_METRIC_LABELS = {
  usageTotalPackageCredit: "总积分",
  usageBasicPackageCredit: "基础积分包",
  usageOnDemandPackageCredit: "按需积分包",
  usageBonusPackageCredit: "赠送积分包",
}
const TOTAL_CREDIT_METRIC = "usageTotalPackageCredit"

/** Compact credit counts for the display string (12345 → "1.2万"). */
function formatCredit(n) {
  const v = Math.max(0, Number.isFinite(n) ? n : 0)
  if (v >= 1e8) return `${(v / 1e8).toFixed(1)}亿`
  if (v >= 1e4) return `${(v / 1e4).toFixed(1)}万`
  return String(Math.round(v))
}

const BENEFIT_WINDOW_LABEL = "免费额度"

/**
 * A credit bucket as a usage window. magpie takes its routing cap from every
 * window it is given, so only the package total may pause the account: the
 * buckets are that same money broken down, and a spent 500-credit basic bucket
 * used to stop an account with 30 000 credits left elsewhere.
 */
function creditWindow(name, limit, remain, { resetsAt, expiring = 0 } = {}) {
  const used = Math.max(0, limit - remain)
  return {
    name,
    used: clamp(limit > 0 ? (used / limit) * 100 : 0),
    display: `${formatCredit(used)} / ${formatCredit(limit)}${expiring > 0 ? ` · ${formatCredit(expiring)} 即将过期` : ""}`,
    amount: used,
    limit,
    unit: "credits",
    ...(resetsAt ? { resetsAt } : {}),
    ...(name !== CREDIT_METRIC_LABELS[TOTAL_CREDIT_METRIC] ? { aside: true } : {}),
  }
}

// The buckets that are the month's allowance and come back at the period's
// end (the IDE's 「等待至 {resetDate} 额度重置」); bought and given credits run
// out on their own dates instead.
const MONTHLY_CREDIT_METRICS = ["usageTotalPackageCredit", "usageBasicPackageCredit"]

/**
 * The free daily token pool as a window, scoped to the models that draw on it.
 * `aside`: an empty free pool leaves the paid models usable.
 */
function benefitWindow(raw, ids = BENEFIT_MODEL_FALLBACK) {
  const rec = asRecord(asRecord(raw).result ?? asRecord(raw).data ?? raw)
  const limit = num(rec.daily_token_limit)
  if (limit <= 0) return undefined
  const used = Math.max(0, Math.min(num(rec.daily_tokens_used), limit))
  return {
    name: BENEFIT_WINDOW_LABEL,
    used: clamp((used / limit) * 100),
    display: `${formatCredit(used)} / ${formatCredit(limit)}`,
    amount: used,
    limit,
    unit: "tokens",
    // A daily pool: back at the next Beijing midnight.
    resetsAt: new Date(nextBeijingMidnight()).toISOString(),
    span: 86_400,
    aside: true,
    ...(ids.length ? { models: [...ids].sort() } : {}),
  }
}

/**
 * Map the account's `statistics/plugin` (+ free pool) answer to magpie's usage
 * shape. `batches` are its credit batches with their own expiry (see
 * fetchCreditBatches): the plan's batch gives the month's reset to the second,
 * and the soonest of the rest to lapse is each bucket's (and the total's)
 * `runsOutAt`/`runsOut`. Without them, `grants` (the check-ins the plugin
 * claimed, 30 days each) stand in, and the reset is `end_date`.
 */
function usageFromStatistics(raw, benefitRaw, { batches, grants, benefitIds } = {}) {
  let data = raw
  if (raw && typeof raw.code === "number") {
    if (raw.code !== 0) return { error: firstOf(raw.message, raw.msg, `CodeArts code ${raw.code}`), windows: [] }
    data = asRecord(raw.data)
  }
  if (!data || typeof data !== "object") return { error: "CodeArts could not be parsed", windows: [] }
  const pkg = asRecord(data.package)
  const plan = firstOf(pkg.package_name_cn, pkg.package_name_en, pkg.spec_code)
  const metrics = Array.isArray(data.metrics) ? data.metrics : []
  const now = Date.now()
  const known = batches ?? grantBatches(grants)
  // The plan's own batch ends when the month's allowance comes back.
  const planEnds = known.filter((b) => b.metric === PACKAGE_TYPE_METRICS.basic && b.expiresAt > now).map((b) => b.expiresAt)
  const reset = planEnds.length ? Math.min(...planEnds) : vendorDate(data.end_date)
  const resetsAt = reset ? new Date(reset).toISOString() : undefined

  const windows = []
  const metricOf = new Map()
  for (const item of metrics) {
    const rec = asRecord(item)
    const name = CREDIT_METRIC_LABELS[rec.name]
    if (!name) continue
    const limit = num(rec.package_credit_amount)
    const remain = num(rec.package_credit_remain)
    if (limit <= 0 && remain <= 0) continue // empty bucket, nothing to show
    const w = creditWindow(name, limit, remain, {
      resetsAt: MONTHLY_CREDIT_METRICS.includes(rec.name) ? resetsAt : undefined,
      expiring: num(rec.package_credit_expiring_amount),
    })
    metricOf.set(w, rec.name)
    windows.push(w)
  }

  // What lapses soonest, apart from the month's reset: a bucket's own
  // batches; for the total, every batch but the plan's.
  for (const w of windows) {
    const metric = metricOf.get(w)
    if (metric === PACKAGE_TYPE_METRICS.basic) continue
    const own = known.filter((b) => (metric === TOTAL_CREDIT_METRIC ? b.metric !== PACKAGE_TYPE_METRICS.basic : b.metric === metric))
    const lapse = soonestLapse(own, now)
    const left = Math.max(0, w.limit - w.amount)
    if (lapse && left > 0) {
      w.runsOutAt = new Date(lapse.at).toISOString()
      w.runsOut = Math.min(lapse.credit, left)
    }
  }

  // Keep the package total on top, then the per-bucket breakdown, then the
  // separate free pool.
  const totalLabel = CREDIT_METRIC_LABELS[TOTAL_CREDIT_METRIC]
  windows.sort((a, b) => (a.name === totalLabel ? -1 : b.name === totalLabel ? 1 : 0))

  const benefit = benefitRaw ? benefitWindow(benefitRaw, benefitIds) : undefined
  if (benefit) windows.push(benefit)

  if (windows.length > 0) return { plan: plan || undefined, signIn: "kept", windows }
  return { plan: plan || undefined, windows, error: "该账号无积分额度" }
}

// ---- the plugin -------------------------------------------------------------

export const CodeArtsAuthPlugin = async ({ client } = {}, options = {}) => {
  const fetcher = typeof options?.fetch === "function" ? options.fetch : fetch
  // Tunables (magpie: `magpie plugin options <name> '{…}'`). `maxInflight` can
  // only lower the gate: above 3 the account would pass the vendor's cap.
  const maxInflight = Number.isInteger(options?.maxInflight) && options.maxInflight > 0
    ? Math.min(options.maxInflight, ACCOUNT_MAX_INFLIGHT)
    : ACCOUNT_MAX_INFLIGHT
  const retryBudgetMs = Number.isFinite(options?.retryBudgetMs) ? Math.max(0, options.retryBudgetMs) : SESSION_RETRY_BUDGET_MS
  const retryDelays = Array.isArray(options?.retryDelays) && options.retryDelays.length ? options.retryDelays : SESSION_RETRY_DELAYS_MS
  const queueBudgetMs = Number.isFinite(options?.queueBudgetMs) ? Math.max(0, options.queueBudgetMs) : QUEUE_BUDGET_MS
  const thinking = options?.thinking !== false
  const ledgerPath = typeof options?.ledgerPath === "string" && options.ledgerPath ? options.ledgerPath : defaultLedgerPath()
  // Test hooks: the clock and the sleep the retry budget runs on.
  const now = typeof options?.now === "function" ? options.now : Date.now
  const sleep = typeof options?.sleep === "function" ? options.sleep : delay

  // Per account, shared by every loader this process runs for it and by
  // nothing else: the gate; its free models today (null until its
  // gateway/config was read; the fallback stands until then), its builtin
  // ones, and the ones the gateway said it has no benefit for; today's
  // benefit claim; its main agent's id; its credit batches; the renewal of its
  // credential under way, and the last one made; today's check-in claim whose
  // confirm failed.
  const accounts = new Map()
  const accountState = (key) => {
    if (!accounts.has(key)) {
      accounts.set(key, {
        gate: createConcurrencyGate(maxInflight), benefit: null, regular: null, noBenefit: new Set(),
        claim: null, claiming: null, agentId: "", batches: undefined, batchesAt: 0,
        renewing: null, renewed: null, unconfirmed: null,
      })
    }
    return accounts.get(key)
  }
  const stateOf = async (cred) => accountState((await accountSessionIds(cred)).sessionId)

  // One renewal per refresh token, whoever asks for it (each of the account's
  // loaders, magpie's auth.refresh): STS spends a refresh token once, so a
  // second use of it would turn the account away. Whoever comes later with
  // the same token gets what that renewal gave.
  const renewOnce = async (cred) => {
    const token = firstOf(cred.refresh_token)
    if (!token) return refreshCredential(cred, fetcher)
    const state = await stateOf(cred)
    if (state.renewed?.from === token) return state.renewed.next
    if (state.renewing?.from !== token) {
      const promise = renewSharedCredential(cred, () => refreshCredential(cred, fetcher))
        .then(async (next) => {
          state.renewed = { from: token, next }
          return next
        })
        .finally(() => {
          if (state.renewing?.promise === promise) state.renewing = null
        })
      state.renewing = { from: token, promise }
    }
    return state.renewing.promise
  }
  // The ledger's key: the signer, which outlives a sign-in; else the session.
  const ledgerKey = async (cred) => accountIdentityOf(cred).id || (await accountSessionIds(cred)).sessionId

  const configModel = (m) => ({
    name: m.name ?? m.id,
    // Declared so a caller never sends its own, larger default.
    limit: { context: m.context ?? 0, output: MAX_OUTPUT_TOKENS },
    tool_call: true,
    // Text only (TEXT_ONLY): said, not left out, so an agent sends no image.
    attachment: false,
    modalities: { input: ["text"], output: ["text"] },
  })

  const modelOf = (provider, live, state) => {
    const base = provider.models?.[live.id] ?? {}
    const capabilities = {
      temperature: true, toolcall: true, output: { text: true }, attachment: false,
      ...(base.capabilities ?? {}),
      ...(live.reasoning ? { reasoning: true } : {}),
      // what the user's own config says of a kind stands; the rest is text only
      input: { ...TEXT_ONLY.input, ...(base.capabilities?.input ?? {}) },
    }
    // magpie's own fields: `free` (from the free daily pool, the same answer
    // the signed `maas_type: benefit` header follows, so a model never shows
    // as free while billed as paid) and `rate` (the credits a request costs,
    // as a multiple: the IDE's 「消耗系数」).
    const free = live.benefit === true && !state?.noBenefit.has(live.id)
    return {
      ...base,
      id: live.id,
      name: live.name || base.name || live.id,
      limit: { context: live.context ?? base.limit?.context ?? 0, output: live.output ?? MAX_OUTPUT_TOKENS },
      capabilities,
      free,
      ...(!free && live.rate > 0 ? { rate: live.rate } : {}),
    }
  }

  return {
    // The provider and the models it has before anyone is signed in.
    config: async (config) => {
      config.provider ??= {}
      config.provider[PROVIDER] ??= {}
      const p = config.provider[PROVIDER]
      p.name ??= "CodeArts"
      p.npm ??= NPM
      p.api ??= CHAT_API_BASE
      p.models = { ...Object.fromEntries(CATALOG.map((m) => [m.id, configModel(m)])), ...(p.models ?? {}) }
    },

    // The account's own list when signed in and CodeArts answers.
    provider: {
      id: PROVIDER,
      async models(provider, { auth } = {}) {
        const cred = credentialOf(auth)
        if (!cred?.access_key_id) {
          // A models hook that runs with no auth is a provider with no accounts.
          noteProviderEmpty(PROVIDER)
          return provider.models
        }
        const identity = accountIdentityOf(cred).id
        if (identity) noteProviderAccount(PROVIDER, identity)
        try {
          const state = await stateOf(cred)
          const list = await fetchRemoteModels(cred, fetcher, state)
          if (!list.length) return provider.models
          return Object.fromEntries(list.map((m) => [m.id, modelOf(provider, m, state)]))
        } catch {
          return provider.models
        }
      },
    },

    auth: {
      provider: PROVIDER,
      refreshLead: REFRESH_LEAD_MS,
      // The gateway's own cap: more in flight only queues in the plugin.
      maxConcurrency: maxInflight,

      // magpie's own hook: renew the temporary credentials before they expire.
      async refresh(auth) {
        const cred = credentialOf(auth)
        if (!cred) return undefined
        const renewed = await renewOnce(cred)
        // A rotation rebuilds the credential: keep the phone, which only the
        // stored one knows (`renewOnce` carries `session_id` itself), and read
        // it once for an account signed in before it was being read at all.
        const next = {
          ...renewed,
          ...(cred.user_phone && !renewed.user_phone ? { user_phone: cred.user_phone } : {}),
        }
        const identified = next.user_phone ? next : { ...next, ...(await accountPhoneField(next, fetcher)) }
        const identity = accountIdentityOf(identified)
        // accountId is the account's identity in magpie (its user-set name,
        // proxy, model picks and a gateway key's list hang off it), so a
        // renewal never renames one. An account stored without an accountId at
        // all gets the URN, as main does — otherwise signing it in again would
        // add a second row.
        const accountId = auth.accountId ? "" : identity.id
        return {
          access: JSON.stringify(identified),
          refresh: identified.refresh_token,
          expires: expiresFromCredential(identified),
          ...(accountId ? { accountId } : {}),
          ...(identity.id ? { uid: identity.id } : {}),
        }
      },

      // Every request the account makes is signed here.
      async loader(getAuth) {
        let account = await getAuth()
        let cred = credentialOf(account)
        if (!cred?.access_key_id || !cred?.secret_access_key) return {}
        const identity = accountIdentityOf(cred).id
        if (identity) noteProviderAccount(PROVIDER, identity)

        // magpie renews ahead of expiry by itself; this covers hosts that
        // ignore `auth.refresh` (OpenCode) and a credential that went stale
        // anyway (a 401 / APIG.0602). One renewal at a time, shared with the
        // account's other loaders and auth.refresh; null when it fails.
        let refreshing = null
        let signInDead = false
        // Another renewal may have landed already (magpie's own, or another
        // process's): the stored one, when it is newer than `than`.
        const takeStored = async (than) => {
          const latest = await getAuth().catch(() => null)
          const stored = credentialOf(latest)
          if (!stored || !than(stored)) return { latest, stored: null }
          cred = stored
          account = latest
          return { latest, stored }
        }
        const renewCredential = (stale) => {
          if (signInDead) return Promise.resolve(null)
          refreshing ??= (async () => {
            const first = await takeStored((s) => s.access_key_id !== stale.access_key_id && !nearExpiry(s))
            if (first.stored) return first.stored
            const base = credentialOf(first.latest) ?? cred
            try {
              const next = await renewOnce(base)
              cred = next
              account = await persistCredential(client, first.latest ?? account, next)
              return next
            } catch (e) {
              if (!isPermanentRefreshFailure(e)) return null
              // The token was spent a moment ago by someone else: theirs stands.
              const after = await takeStored((s) => !!s.refresh_token && s.refresh_token !== base.refresh_token)
              if (after.stored) return after.stored
              signInDead = true
              return null
            }
          })()
            .catch(() => null)
            .finally(() => { refreshing = null })
          return refreshing
        }
        const current = async () => {
          if (signInDead || !nearExpiry(cred)) return cred
          return (await renewCredential(cred)) ?? cred
        }

        // One account = one upstream session and one in-flight budget.
        const ids = await accountSessionIds(cred)
        const state = accountState(ids.sessionId)
        const context = {
          ...ids,
          gate: state.gate,
          // The account's own model lists, read at each request (the models
          // hook keeps them current).
          state,
          now,
          sleep,
          fetcher,
          retryBudgetMs,
          retryDelays,
          queueBudgetMs,
          thinking,
          renewCredential,
          signInDead: () => signInDead,
        }
        return {
          baseURL: CHAT_API_BASE,
          async fetch(input, init = {}) {
            const c = await current()
            return signedFetch(c, input, init, context)
          },
        }
      },

      // magpie's own hook: how much of the plan is left.
      async usage(getAuth) {
        const auth = await getAuth()
        const cred = credentialOf(auth)
        if (!cred?.access_key_id) return { error: "not signed in", windows: [] }
        const identity = accountIdentityOf(cred).id
        if (identity) noteProviderAccount(PROVIDER, identity)
        try {
          const text = await signedGet(SNAP_STATISTICS_URL, cred, fetcher, SNAP_EXTRA_HEADERS)
          if (text === undefined) return { error: "CodeArts answered an error", windows: [] }
          const state = await stateOf(cred)
          // The free pool only once today's benefit is the account's; best
          // effort either way: a credit account without one is normal.
          const free = state.benefit === null || state.benefit.size > 0
          const benefitText = free ? await signedGet(BENEFIT_BALANCE_URL, cred, fetcher) : undefined
          // Each batch's own expiry, read again every ten minutes (and after a
          // check-in); a failed read keeps the last one, else the ledger stands in.
          if (!state.batchesAt || Date.now() - state.batchesAt > CREDIT_BATCHES_TTL_MS) {
            const read = await fetchCreditBatches(cred, fetcher).catch(() => undefined)
            if (read) state.batches = read
            state.batchesAt = Date.now()
          }
          const usage = usageFromStatistics(safeJson(text), benefitText === undefined ? undefined : safeJson(benefitText), {
            batches: state.batches,
            grants: readGrants(ledgerPath, await ledgerKey(cred)),
            benefitIds: state.benefit ? [...state.benefit] : BENEFIT_MODEL_FALLBACK,
          })
          // The card names the account by its phone, not by IAM's `hw…` id or
          // its URN — read once here for an account whose credential predates
          // that read (the next refresh stores it).
          const phone = firstOf(cred.user_phone) || (await fetchAccountPhone(cred, fetcher))
          const user = phone || accountIdentityOf(cred).name
          return user ? { ...usage, user } : usage
        } catch (e) {
          return { error: e?.message ?? String(e), windows: [] }
        }
      },

      // magpie's own hook: the daily 「每日领取」 check-in (OpenCode ignores it).
      // magpie renews the sign-in before asking, and asks once a Beijing day.
      async checkin(getAuth) {
        const cred = credentialOf(await getAuth())
        if (!cred?.access_key_id) return { outcome: "failed", message: "not signed in" }
        const key = await ledgerKey(cred)
        const state = await stateOf(cred)
        const today = beijingDay()
        // The account's own memory first: the ledger is written best effort,
        // and a write that failed mustn't lose the claim; the ledger carries it
        // to another process, or past a restart.
        const held = state.unconfirmed?.day === today ? state.unconfirmed : undefined
        const left = held ?? readUnconfirmed(ledgerPath, key)
        const { grant, unconfirmed, ...r } = await dailyCheckin(cred, fetcher, { unconfirmed: left })
        // A claim whose confirm failed is kept for the next check-in; one
        // confirmed now, or found done, is dropped.
        if (unconfirmed) {
          state.unconfirmed = { ...unconfirmed, day: today }
          recordUnconfirmed(ledgerPath, key, unconfirmed)
        } else if (left && r.outcome !== "failed") {
          state.unconfirmed = null
          recordUnconfirmed(ledgerPath, key, null)
        }
        if (r.outcome === "claimed") {
          // The new batch shows at the next usage read; the ledger keeps it in
          // case the vendor's batch list can't be read.
          state.batchesAt = 0
          if (grant) recordGrant(ledgerPath, key, grant)
        }
        return r
      },

      methods: [
        {
          type: "oauth",
          label: "Sign in with Huawei Cloud",
          async authorize() {
            const flow = await startOAuthFlow(fetcher)
            return {
              url: flow.loginUrl,
              instructions: "Sign in to Huawei Cloud in the browser. This signs in CodeArts only — the OfficeAce card has its own sign-in. This window closes itself when done.",
              method: "auto",
              async callback() {
                try {
                  const outcome = await flow.result
                  const cred = safeJson(outcome.access)
                  if (!cred?.access_key_id) return { type: "failed", error: "CodeArts did not return a credential" }
                  // The card's name is the phone (one read away, best effort:
                  // a failed read still signs in), shown through usage's
                  // `user`; the credential carries it as `user_phone`.
                  const identified = { ...cred, ...(await accountPhoneField(cred, fetcher)) }
                  // The MaaS pair OfficeAce needs is read once here (best effort:
                  // an account that never opened MaaS signs in all the same), and
                  // kept on this credential too, so a later rotation of this
                  // record hands the other one a credential that still has it.
                  const withMaas = await withOfficeAceMaas(identified, fetcher)
                  const identity = accountIdentityOf(withMaas)
                  // `accountId` is the account's identity — the URN, as main
                  // gives it — so a re-sign-in replaces the account instead of
                  // adding a `codearts#xxxxxx`; `uid` is that same URN.
                  const record = {
                    type: "success",
                    access: JSON.stringify(withMaas),
                    refresh: cred.refresh_token,
                    expires: outcome.expires,
                    accountId: identity.id,
                    ...(identity.id ? { uid: identity.id } : {}),
                  }
                  // This sign-in writes this card's record only. A Huawei Cloud
                  // refresh token is spent once, so two records holding one
                  // token would sign each other out; the other card has its own
                  // sign-in and its own token.
                  await writeProviderRecord(client, PROVIDER, withMaas, fetcher)
                  return record
                } catch (e) {
                  return { type: "failed", error: e?.message ?? String(e) }
                } finally {
                  await flow.close()
                }
              },
            }
          },
        },
      ],
    },
  }
}

/** Is the credential this close to its expiry (unknown expiry: no)? */
function nearExpiry(cred) {
  const at = Date.parse(cred?.expires_at || "")
  return Number.isFinite(at) && at - Date.now() <= INBAND_REFRESH_LEAD_MS
}

/**
 * Best-effort: store a freshly refreshed credential back on the account, and
 * give the record as stored. The host keeps what it is given whole (nothing is
 * merged), so the account's other fields — its accountId — go along.
 */
async function persistCredential(client, account, cred) {
  const identity = accountIdentityOf(cred)
  // `accountId` is the account's identity in magpie, so it stays what main
  // stores: the URN, and what the record already had first. The phone is in
  // the credential (`user_phone`) and shown by usage's `user`.
  const accountId = firstOf(account?.accountId, identity.id)
  const uid = firstOf(identity.id, account?.uid)
  const body = {
    ...asRecord(account),
    type: "oauth",
    access: JSON.stringify(cred),
    refresh: cred.refresh_token,
    expires: expiresFromCredential(cred),
    ...(accountId ? { accountId } : {}),
    ...(uid ? { uid } : {}),
  }
  try {
    await client?.auth?.set?.({ path: { id: PROVIDER }, body })
  } catch {
    /* best effort */
  }
  return body
}

// for tests (never a plugin: magpie only calls exported functions)
export const _internal = {
  PROVIDER, NPM, CATALOG, CONTEXT_WINDOWS, BENEFIT_MODEL_FALLBACK, MAX_OUTPUT_TOKENS,
  CHAT_API_BASE, SNAP_MODEL_BUILTIN_URL, SNAP_STATISTICS_URL, OPENGW_GATEWAY_CONFIG_URL, BENEFIT_BALANCE_URL,
  OPS_DELIVERY_URL, OPS_CLAIM_URL, OPS_CONFIRM_URL, SESSION_LIMIT_ERROR, ACCOUNT_MAX_INFLIGHT,
  PORTAL_AUTHORIZE_BASE, STS_TOKEN_ENDPOINT, CLIENT_ID, REDIRECT_PATH,
  firstOf, asRecord, safeJson, num, clamp, prettify, normalizeModelId, upstreamModelId, formatCredit,
  b64url, utf8, sha256Hex, hmacSha256Hex,
  generatePkcePair, generateDpopKeyPair, keyPairFromStoredJwk, signDpopJws,
  buildCanonicalRequest, signRequestHuawei,
  credentialFromTokenResponse, credentialOf, expiresFromCredential, accountIdentityOf, accountSessionIds,
  profileOf, looksLikeIdentifier, maskPhone, fetchAccountPhone, accountPhoneField, IAM_HOST, IAM_USER_URL,
  requestToken, exchangeAuthorizationCode, exchangeRefreshToken, refreshCredential,
  isDeadRefreshToken, isPermanentRefreshFailure, nearExpiry, persistCredential,
  buildOAuthLoginUrl, buildPortalLoginResultUrl,
  startOAuthCallbackServer, listenOnCallbackPort, startOAuthFlow, isSignedHostUrl, hostOf, SIGNED_HOSTS, signFor, traceQueueCall,
  BENEFIT_CLAIM_URL, AGENT_LIST_URL, AGENT_DETAIL_URL, CODE_AGENT_ID,
  canonicalQuery, beijingDay, nextBeijingMidnight, vendorDate, creditRateOf,
  claimBenefit, ensureBenefitClaimed, parseAgentModel, fetchAgentModels,
  readGrants, recordGrant, readUnconfirmed, recordUnconfirmed, grantExpiry, grantBatches, soonestLapse, fetchCreditBatches,
  PACKAGE_CREDIT_PAGE_URL, OPS_CREDIT_OVERVIEW_URL, OPS_CREDIT_CAMPAIGN_URL,
  toBytes, isBenefitModel, prepareChatBody, signedFetch, signedGet,
  TOOL_NAME_LIMIT, cutToolName, shortenToolNames, restoreToolNames, restoreToolNamesInStream,
  parseSseEvents, errorCodeOf, errorMessageOf, isStaleCredential, isRateLimitCode, embeddedErrorStatus, isNotMultimodal, classifyHead,
  peekAnswer, completionFromChunks, createConcurrencyGate, delay, retryDelayMs,
  isRegularModel, queueInfoOf, waitInQueue, TRACE_QUEUE_URL, SESSION_HEADER,
  snapRequest, dailyCheckin,
  parseModelInfo, extractArray, fetchRemoteModels, creditWindow, benefitWindow, usageFromStatistics,
}

// ═══════════════════════════════════════════════════════════════════════════
// OfficeAce — a second provider from the same Huawei Cloud sign-in
// ═══════════════════════════════════════════════════════════════════════════
//
// OfficeAce (华为云 AgentArts / MaaS) runs on the same Huawei Cloud IAM account
// as CodeArts. Measured with a real account on 2026-10-30, read-only:
//
//   * a CodeArts STS triple signs OfficeAce's subscription read
//     (V11-HMAC `GET …/v1/subscription`, HTTP 200, same `domain_id`) and passes
//     its CLAW permission check (`…/v1/claw/client-permission-validate`);
//   * an OfficeAce STS triple signs CodeArts' `snap-access` reads byte for byte
//     the same way the CodeArts triple does.
//
// So one credential signs both providers' APIs, but each card signs in on its
// own and keeps its own record: a Huawei Cloud refresh token is spent once, so
// one token written into two records would sign one of them out at the other's
// renewal (`STS5.1806`). The second provider keeps its record in the shape
// `officeace-auth` (the package this one absorbs) has always written — `access`
// is a JSON string carrying `modelAppKey` / `securityToken` / `dpopPrivateJwk`
// … — so the accounts signed in through that package keep working without
// signing in again. The account is stored under the same provider id it always
// had (`officeace`), so its records are exactly where magpie already keeps them.
//
// A renewal writes only the record being renewed. Nothing is ever written into
// another record, which is what kept resurrecting an account the user had
// removed, and a failed renewal never borrows a credential from another chain.

/** The OfficeAce provider id — the one the `officeace-auth` package used. */
const OFFICEACE_PROVIDER = "officeace"
const OFFICEACE_NPM = "@ai-sdk/openai-compatible"

// The three domains, never mixed (each measured; see the OfficeAce internals):
//   CLAW          sign-in permission check (the MaaS appKey lives behind it)
//   STS           token exchange — the same endpoint CodeArts uses
//   MaaS          model catalog and chat
//   subscription  usage, credit rates and the daily check-in
const OA_CLAW_BASE = "https://agentarts.cn-southwest-2.myhuaweicloud.com"
const OA_PERMISSION_PATH = "/v1/claw/client-permission-validate"
const OA_SUBSCRIPTION_BASE = "https://officeace.cn-southwest-2.huaweicloud-agentarts.com"
const OA_SUBSCRIPTION_PATH = "/v1/subscription"
const OA_TOKEN_RATES_PATH = "/v1/model-token-rates"
const OA_BONUS_CLAIM_PATH = "/v1/subscription/bonus/claim"
const OA_MAAS_MARKET_BASE = "https://api.modelarts-maas.com"
const OA_MODELS_PATH = "/v2/models"
const OA_CHAT_PATH = "/v2/chat/completions"
const OA_REGION = "cn-southwest-2"
const OA_SERVICE = "apic"
/** The OAuth client OfficeAce's own sign-in uses (its old package's refreshes). */
const OA_AGENTARTS_CLIENT_ID = "pdp5_for_agentarts"
const OA_RATES_TTL_MS = 20 * 60 * 1000
const OA_REFRESH_LEAD_MS = 10 * 60 * 1000
const OA_TOKEN_TIMEOUT_MS = 30_000

/** The models OfficeAce shows before anyone is signed in (its own desktop list). */
const OA_FALLBACK_MODELS = {
  "glm-5.3": { name: "GLM-5.3", context: 1_000_000, output: 128_000 },
  "glm-5.2": { name: "GLM-5.2", context: 1_000_000, output: 128_000 },
  "glm-5.1": { name: "GLM-5.1", context: 1_000_000, output: 128_000 },
  "deepseek-v4": { name: "DeepSeek-V4", context: 1_000_000, output: 128_000 },
  "deepseek-v4.1": { name: "DeepSeek-V4.1", context: 1_000_000, output: 128_000 },
  "qwen3-30b": { name: "Qwen3 30B", context: 1_000_000, output: 128_000 },
  "qwen3-32b": { name: "Qwen3 32B", context: 1_000_000, output: 128_000 },
  "kimi-k2.6": { name: "Kimi-K2.6", context: 1_000_000, output: 128_000 },
  "pangu-2.0-pro": { name: "盘古 2.0 Pro", context: 1_000_000, output: 128_000 },
  "pangu-2.0-flash": { name: "盘古 2.0 Flash", context: 1_000_000, output: 128_000 },
}

/**
 * Registry ids that answer `404 ModelArts.81009 Invalid model` on chat whatever
 * the headers (measured; `deepseek-v4.1-flash-1017` stays 404 even with
 * `maas_type: benefit`). Never listed, whatever the catalog says.
 */
const OA_UNAVAILABLE_IDS = new Set([
  "deepseek-v4.1-flash-1017",
  "deepseek-v4.1-flash-bnt",
  "deepseek-v4-pro",
])

/** OfficeAce's own icon (its `.ico` as a 128×128 PNG). */
const OFFICEACE_ICON = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAnk0lEQVR42u19ebgcVbXvb+1d1eMZMicSCYEEAkGSYBglTMokg1cJAUUvXBBQUGRSEBEhDteRp4AXfL53laeC90tkiBc/RJkCl0EgDAqJMoUhATKQ5Iw9VO293h9791zVXd3n9DknSH/fgZM+1dW191p7jb+1FmGIL14CiWXQRODie1/Yd6Iv+hcJxoEaGE+M2cyYBuJJYJokAKEZABjFT9n/M3PFv8FcduPSe2X/K/1SuF3VvbnZ76q4jhvct/L7g+8LcM33V98XYGYmYIAZ/WDeBuBlBr8E5ucVOysnT3jzZVoOVbH3y6GpdOemX9Qy4a+CEEuhi2u6eM8dlc8nEdFRYN6fGOMpLgHNgGLzfwaU5sDNDN6kYCJVbn7AZtYQJOS7AojNEYlfer8x8Svu22ANZIkiALgEuETIKEZO8QBBr2HQn6RPt49b+faT5YxQzhhtZQBmEK4G0VJoAPAu3OsIAX0eGMeIuExCacBnaMXQzD4AAtsfAsCglohRZ9PCidwCgUJOZ62UqbpvwHthEqX+GowkMGsGg6CZWToEihMhLgg9ntYC/JCv6GfXrdywbKk5XgSACIYubWGAck7ji/Y8HISvgekISAHkFRRr3xCYBANEDTYtTDQyD03kRxbDUaRJi0wVReSHrivgu5jB9qYagJMW5hx5zE9A8w+6Vm76XSvSgJol/sAX5uwQc51vO0RnQBJUThceShCD2qKDR1Pf12O0ckI3RfzW7Iiyw8GawcSMlCRBAAZ8vtMjdekOD25Zs2wJ5JKItkFDBmCAsGSJoOXLlfeFPY8WcfqZcMRMlVUMZk2ArNyvyg3hiLq+liDDI/JDxXBd8T7M3xWg/+t+VySJYpiE2dhh3Y4QWaXeySm6eOrDm35lVQIaMQE1JL69iX/B3MulFP8OAlRe+0Tk1BPNkYgfVQe3yyBrVd8HqJzRZmBmKJcgY0QYVLjupw9vusjaBqKeXUB1ic8AEZgvnHsD4s65Oqs0a4AIAlxHrI2kvg9hqoZieIRdvMiHpUUGBgDFYMHQ41ySPXl9az4fO236qrcGDRmDJYEIJf5VVxER2PvSnrcg7pyrMr7PDGpI/IIIY1T8cM17diEB7zHXunNh31Vr2IV/V8X3RSF+1Z5xzR5yRH3PEZiKI+xX9Z5x8fbMgDDCWm7Nab/bocUxN3/b+oXvS5VL84YSwBD/UElLV/rq/Lk3ipTzeTWofCI4tSIpRISNNX0fYFS2Xd8HSsUIBuswSUqt4U9w4fT4+tbn41s/edgUcFDQqFYCLFkiaOlK3z9/jytE0vm8yviG+JbNuIr7ShwbjfjMXHOugs5apacWTd9HJQhXPC8Hr6HiJNaRXiWxV5+BI35XY+JzURYxaiVVYecEsbM1z/44Ryyekxl/DS2HwhKI6kNP1dE9WgrtfekDRwoHd8NnzcyCrD0QiYtHUt9X68qoOnis6PshRybrG6wMsGCopIDTq/jT05/YessyQJ6MUpyAyokPANgye6IS8aeloOnK09ro/BEWlwGBkdb9+xbjBlEZuAkjcjSCYQxoF0Qa3MtC7TPlsd6XcVUpkluhAmgptObY92RcTle+9okgSlKdA0VNjZEUiSAcQd+XLTDQsOQIhmW1yI/GwE0ZrFEZOGC/agzL4ZSU9hpiiLxm3SGoW3nyGgJ4+erSwafyKF/+gj0OkSTvh9bMDGHCui34940SOU2Jy2FKELUjboBRiFE0YuAglWzeUilJcpDVJ6Y93nMHA5IAZSTAXDABIEXfEhKCTeaOqo09DjGKaonE9YlUZRSFG5bRRX59w7JSlTQTz28YoGq4hjrrqnJLI+n7RvcNCfwxTDKOWV795EK4MMEhErxsiaSl0Pr8PQ+XDh2ic1oDJJsSl2jBv69ZSBCjNWaqWmKEEyRIvQQSv+DfN2KqBqK5wr+vq+/DVVfQusKJHxi+MO6eIDGooDskzZ8hJ3ycAL7/UEiB5+eyiSLpi0gI6CLbV/mwgUERrskVt6bv64hLRsAGRdT3gcSvw8BokoGjGHsNA0nN6nsODobVmmlBrh6DwIpxAQN02EooYwOcM3eGivGLgiimNJjA1Jwr1oTh0qzbNVb0fagdM4I5iTB9j1DJDyIKCv9qzWrh1Cd6nhEAoFycJONOTGvtF4kfIJrrhnSjcnHI6eSw8HGQvg9KF4cERRjRYuzcDPGHpO+5Vso0CB8zGuj7JogPht/lkNDknAQA4ipAaOZjoNmgfTjcyo+qg5vV96EuXgR3Ek18V7gRWW01B0XaqhitZX0fbNiFr6F5fU9hxDd/pBwDAvpoBgTxF3af6Gl6xZXU5WvmGshWVBH2TwTZahzcCdbt9SOTTaSh6516WGBYeJaXHYAUeJDIX+D4TIukRFrpMlk+ElEqRDCStiPI1ogwcCsiv5ZBSAEcFzKV1/IQB6wPEI4rvazvEwoZv+0MshXyWwVTjQBkqyWmaua7hk78wm8qIeB4zB9wADHByiFCUfr/E0O2GjDVqIBdhiDyg65jhvABaObZjtY8G0oDbP4aSHw0SOG+B9kKZuAIKe926vuw64gATzMINMsRxNOgC5D9EYJshQRFmmGq7Q2y1RIDD1HkhzEJA0IxAMIUhzUmMQFs/f92o2uGtSQrEmRr5Eq9mj4sI6HvA66lkkfZ6TAwyVcatoLnnxuyFYKuqfGjtiN93+A616ECJiCIAyNAttqr79tfi9eWGEWYvg+NTLZX5NdzCZ0Rh2y1wFTvVsjWaBC/WjU4YAQ89HYC2WpgATSr70etfrGN+r7Rdc6o6/s6iJeSuUKVhG4H5nAkIFs18o5qbZ/26ftAJnFCU50R0DVhcYOmU7gVTyptOZIGlKrMvRtkg7mGtf3B2INsVf9GAEiYRCwzWPmVEHoiuy4BYl0bdm4T8UsqoB36PigxEshEZDdHA14enM+BvTzgxkCxJCAkQMLc18+DBwYALw+KJcBuHJAOoDVKrSqGSd8HBcOa1fckzD88D5zLgXNZwHFAiRTguPbvAHwPPNAP5HNAIgGKJ8zftQ5lBGpR5IcwwBBQOw1EY6gfTpbwfh6cGQA5LmjCVIhZCyB3XQAx5f0QU2eAkh2A64K1Bvq2Qr/9OvTrL8B/7jH4L/8N3LPVbKgbA7SKHGMfXn1fdlMisBCA8sADfQAIYvxkuAsOgjt/X8gdZkLuMBPUNQ7kuAAA3bsN+u3X4b/6Arxn/gJv9VPgbZuBeBKUSFYwwnCc+orrcmfuykP1uaOJy7KNE9Kc9swAaPwUOAsOhXPQ8ZDzFoE6x0eyeKEV1No18O6/Dfl7lkG//TqQ6jRMpVVzkK0oBmtoMqfsHyTBygf394I6xyG28GAkjjwRsQOPgJg8Ldq6GFCvvYDsn29HdsWv4b3yd4iOLpB0zLqGifiFv1D2jF25rZCtcryAEKazwUAvxMRpcA8/Gc5HT4N4386VT6d8qxqo2v4r3VjK0tub3kR2+Q3Irfi/YN8DJVJgpZpwxYbo4pGtl+3vBXV1I3HkYqROPgfO7gsC1lUgDAWkvtmotAKPb92EwVt+hswt/2Hu3dFp7KJhIn6JASKFSIfW4QMkwZkBQDpwj/wUYou/CJq6k73OijgSkYMYFZ8Thhn8Zx/G4DUXQb36d6CjG/D9FvR9uGcSSHwhwdkM2PeQ+MjHkT7na3B226t0jdbWwGuiIQtr8znLDP7zT6H3uxfCf/YvoK5xgUzQqitI2X+bzS27eJGIb7hd922D3GNfxM/4BuReBxXFeNNED+lcBdaAkNCb38bAt86Ct+oBo06U30TXjQj6vvgPY7nrnq2QM3dD54XfQfzD/2LXpQtY7KGvS2tASvBAH3q/cQ5yd98K6h5fwQRNE7+CAU6fzW3T90KAfR/I5+AedwZip3/dGHVaW/E+RMJXv5QPSAc80Iv+r33aMEFHt3mGFiFbgW4mUVHkJ45cjI5Lfwg5ZfrwEb5mXcqoPN9D79fPRubOWyC6JwDKH1IQCAAoc/psbkeXLQgJzmcB6SDx+e/BOeJTpVMvJNr2svfXWzeh7/xj4b/+krGkTcJrePS974PzOXSc9w2kz7qsgvnaty6jSjibQc8XT4T3+AOgzm6z3iZPfSUDnDabhzuFCyHBuQyoczziX74RzvxDhk/cN3Fi/DVPofeCE4wtUIglMLcM2TLE9wCS6LriOiSOP9VKM5R8+na+LBPoDeux7fTDod7ZCHLjtklb88Q3NQJRIdrV74VAtI1RNAjqmojk1f9liK98G9AZAeIXPATlw9njg0h+5mJwf68Vy9wYol3tBRXWTALa8wAh0f3D3xjiK1WM4I3ISwhAKYip05G+8DuAlw/d0wqRX2ffRctdN4JKsoQw0a7uiUhc+RuIWXu1XzSGrkwCWiNx8nmQe+4LPdhvCBUK2QrpusElsU9E6P7erxBfdIxdlxyFdZk4R/yYJYgdfgK4f1vNc0R1BU1L2pBatmDIFtfG2Av/JQI8D3BjSF7+C8hd548e8QvPwwxKJJE89UtGDTBVVfYEFWZUn3wCaw3O59D1zZ8jfsixo78uS+L0GZeYKKi1b6iFOICoaerQbJctLrUjZC+PxPk/htxjv9HdpKIqMMmX+GEnwNljITjTb0LQUatwATAJcH8vOi74NhJHnTQ21iUEwBrOvP0QW3Q0MNAHKpcCEYmPQvuXprtuVBtPROD+HsQ/fRmcQz5ujbBR3qTCcrUG3Djix5wCzufLUrAR8HpSgnu2ILn4TKRPv8jqfIkx8dKGSxPHnVpk9Eb6PsgoFEPrsmW4kft74Ox3JGInX1CKfI2Vl11o7OBjQeMnA74X2vCmAvdPAtzfD3f3vdH55R/YuAaNnCEbRQoQIXbgRyBn7mYyiSHGKNXxCERw7pnrY9u57M75HMSkHZA474fW0sfY2aSiuGTI6TvD3Wt/E44uGINhxZggE2SJxdH59etAHV2lUPVYYmytgWQKsX0PBWcHAw9eDeGraCM4oMKXuUErlyLTGKs/dtoVoKkzSr7+WHvZYIk7/wCw5xdbHwV23YCNYPb1InX6RXDnH2Dd2DG4Luv/u/scDATEAyLGAdBCly27SQO9kAs/AvfDJ9uAyBjcpHIA5NyFoFSnIWhYizcS4MEBOLsvMHrf5hjG5Ms+l5z7QVBnl1lXIcYfgfiECkh4FIg2F0UkKwUk0kiccWXpdIwl0V+xUvN8zq4fAKU7i+nmwPZ3DLDW6Pji1aB0R8m4GsMvOXW6yUX4HogoMvFLkcCGtWxV4Al7+t3DF5tgz4gYfjYzpvzSj1aRsHPFA9M5DmLyNBPLNy2zKj0eIcH9vYh/6AjEDzvOSrUROP3MxsMoXxvryJINbswYgp5XIm0dj6AqDhC9dVvxV88DdU1E7BPnYggDq5rU4RY4KZ3STyG83CAhUggKwXEhd9gZ7HkV9VEFScdaAY6D9L9dXPpMOw9/Ie9PZKJ55WsjUcI7RLBv5ORpJtglmnAFy+sCojUpKpySHsQ+djbE+3dtb3avDHQBAP4/noH//BPQ72wE3DicnXeHu9+HQcmU2ax6NogV5TRuoj1hVegnEuC+HsQPPQ6x/Q8395Ptz1qCAL3xTXhPPQy17hXA9yGm7AB330Mhd9yl4tlD4wECoEnTiqnqSG3hKwpDIsGm7X+UD0p2wv3ov5aAEe0ivn3I/CN3I3PLtfCfX2WAll4eTASKJSB2nI30565E/IgTG6gisyBKd4G1BoEqM5/WzUsuPrO0sbKdWT0JtX4tBm/6CfL3/R56y0aTR2FAuDFQ93gkTvg0Ul+8CpSqY4sUJH5HFyCcQIkRRnzDAA26bFX8JiTQ3wO5/zGQs+YVvYF2EZ8zgxi47nJkV/zCMHc8BeocV3okzVDrXkHvpaei49IfI/nJc8MlgT0pItVhRmuUr4sEODMId/f5iC86qhRGbmNKN3f379D/w0uh314HSneCUh2gdJehjWbA95C56X9Brf0HOn90MyiZrm9ox+I2Ihid+EU3kKN02bKbyCC4R55c4Ye2hfh929D31U8hu/xGULLDuG+AgXj5JSOQ4klQuhP9P/4qvKcfLqGCQ44BF5+5LP8hCOzlkDj2FFAsbuFW1CaxL5D59fXovew0A2kfNxGQEqQ1SPk2aWWYhCa/D7mVf8Dgf3yzMp0dsDByXEtcjkx8GwiqR/xyL8lsEk2dAWfvwyvcq2ElPmuwl0PfN89G/uG7QOOnFK3/yl5+9sGUAoQD9jwM/Of3G0fslK0d0GVRP9+H6J6I+OHHt8+dtWI/e8ev0P/Dr5gTHYuVYhLVRGIGvDzEuEnI3nET1IvPWebWwYW2+VzRoKQIEcCyOABHgk2zFZPO3oeAOrpL1utwM4CQyPzy+8jft8IQ3/MaBqhY+aBkCt4zj8J/6flSmDTgpHAuW5Mx5MwgYnvtC2enXduj1qzY99c8g/7vfxmUStu8vm6cwpUS3NuD3J9urV9Fms8CSoGqz33jOADCWiGiAhegNeDE4Ox7RHvEf2GTVq9C5ubrQF0TrDhs0Ei58Acpoft6kH/6kUpkbnlOAIDeutmmTksJDdIK8YOPieZSthqJ9D30X/NVcKa/WPYVKWDDGhSLw//bEyUIfJBr2NdbqiuMSPwKRFD9jt1mAaJ7Apy5+7UH+WqfavCmH4Azg7aIREeDbBUanPgKat3agMWXLGi99R3j3hVKrbQP6uiG+8EPtUf8K1PNk7t3hQFydnSBlIoM2QIzyHGg1q0F5zKhwSC16a1KdzxE5FOQDcA1PXqrbAAQOJ8DzZxrxDKGOTNm8wj+mlXwHrsPlOosQbkjQLbYzlIlIcB922o3oPAh34fa+GbRvychAM+DmDYdzqy57bFrrKjPLPs5SEpQkL5vlMIVEsgOAtkgBjBr0ZvfBhynLvERYBeI2vbjXNtijQicz8LZY582iUnzZbl7bwcP9JZcsAiQrZpcRZ2glNq6CXrDOpATMxsiJDiXhfuBfQ10nIfZrrG1fN7fn4H//FMGvhWhJiJUcFdLXRupZC8PvW4t4LqBNkK9FYmGOEBmU5nrxCF33K2uHdIy8YUElIL35EogFgcrHRmyVfojgZUGdU+otVHs7+rVF4HMoLEBCpunFJxd5gTbDcMUyfQeux/o77Eh3iard+yBo85uIJ4M/pqNb4E3vWVcQeZIJ78mHRyKA7R6jBJp0I6zhl//F8aeblwHf91awImFFJ1wbWSy/Jk1A44DZ8edQwnhv7waPNhXCvEqDUok4czctdlh6k2la9U//hopXB5oFNpaBLHjLqZvQPkMUMuwau0ag3ouMxApehygAQ4QlgMTqbIqXhp2UINe/yqQy9okSOPBiNWtZNj3QelOuHvuU6vLLcP6f33c3qR0skQyDTljtr2Ohj+UrRTUW6+Z/gV1mj2EegTWg3B2n19k2ur9959/CsgMAEIGEz6oJKwWD4DgwQlsLdmuiRCFcOTwq3/ovh7TGYSqg1B1AlSFfxKBcxk4s/YsGXOiLKBCAshlkH/uyZKuL/wtFoOYNK09EgAA+3lwX48xOBvp5yDbQCtQMo3YgUcEo54B+M88CrjxSgMzgjtYZQOED0rSvg8aN8n4r2hf/gdclgFtNCipvIyNCJzPI3H0YlsVVBbKtWLSW/MM1FuvGxVjp6mzVqCObpNsQRuRySGb1jAOIASQHYSzxwI48/YrxjtK6yLoDeugXnwOIp6ojc0EMBTVxAEYAVZ2uQ1AgGaIzvGlHPlwcoC9legabxisZgRt2GDEYiAfnM3AmTEbyRNOrRXl9tfcg3eZTKKURSg7lIIcN6HYqqUt5HdjoK4JBmtQ3rA9SsCGTJg6cfLnSr2QqlSn9+i94C0b7d5xwzhAYG0g14jcajWgSj5mm/B6cqddTem48oP1PaqnZHEJnZQZRPrMSyDGT64CploPw/eR+5+77SmpMpLc2PDq/mrUrhCQO802dXxC1Nf3Fe69QSe5+x2G2FEn1mY5CxiJh+4qdvpvlvgojIatOxix8Ea7Cj2s0ScmToMzZ76JdpEIkEgBg5IcF7ztHSQ+8jGkTjqzFpiqjD7JP/Uw/JdWGzeqeIpsFq2AvmmHarOnNLZwkQk5gxsmaEoBqjwo3YXUJd8vScZiosjEEvSG9aZrSDI8vtDIKBSRByPWdIAY5jwAAYnjP2OydUW8HgdPECsQv2crnDnz0H31jSUfu9qCJkJ2xa9NEqhwAit6D3HbUbuxw44z6J5stljQEXoerA3D+RzSV1wLOWevYhq5Yr8A+E8+BL1lc8k2ixoAqo0D1BmMqM0H9EBfUOwIw1nDlzjyE3AXHQNd0GmFCRcV0TBZbADh7j4f466/1Vjx1VE8rQFBUOtfQ+7BuyBTHaDyDKbFAeiBvtoOIsOqBhSoewJSZ19mijdIBBdwkAA5jsmDKB/pb9yA2DFLgiF3VmL5Tz0MaL9xQUh9QEhItq3CyhbAQF8ZSJLbYyk7Lrq/cQNi8/aH3rwB8FWp8tjW+fFAL7i/F8njT8X4n98JZ8ddQmoSjLGaue2X0Fs2mNx71d+JjJ5tSwawKhcQ//hpSJ59KbjnHXA2UwztkpVKyGfBWzZD7rgLOq6/FfF/+ddg4hfS1fks/GcfK4WXI+j7iqkh9sdpmG3TDBLSADG9vIEecRv0pfUwxNT3Y9yNd2Lgxm8jc/fvwD1bTT2fdECpDsQ/eBCSp3wOiQ+fUJFGDkouqQ3rkL39JgMD0xwoebi/D9y3DRSfhra5gcKsLfWlb0HOmovM//sJ9BuvANmc2cp4AmLGbMSOPQWJkz4L6hpfBJCEBZjUqy9Cb1xv7QPd1KmnClRw6MiWMmdbOlBbNkJv2wwxZXqba/o1xLiJ6Lz8x0h/9ivw1jwN3bMVoqMLcvaecGbMqkIMi5BZ2QKZW26A3rAeNG5CbWs1tpm07CDUuletGmljEYhl8Phxn0LsyBOhVj8F/ebrgCCI6TtDzpln4GiN+ijZdatX1pjoX6qjFlsQkfjFbuEN+/ITmY1av9YwALexYMJ6BWCGmLID4lN2CO+aVQ9xu/YfyN52k0HLBiZ52LhaA73Q69cCCw6wJ0m0uaBTgWJxOAsOBBYcWLsuIRrkDWxw7q03wLksRLqrGNhqlvgBgaBaeBjDbCgP9kG9+DdE7WQ95I2yVb2lihlVinTJOqfDPlv/9VdBb3vHeAdhzytMnN1/4W8jV9pWSNho2w1dqVIvYBmlj5I1jHu3gcKwCyH6PujlRGoLSyaB4q9+ssK9wUgUdTZTnGGbKmb/dCty9/4+tI0alTNMPAGvHG41UusaIrMRuOVTHxAHqBqTXN0STtmNeu5xA9gohoTH0MsSX29Yj4FrLge5sdDByiVxzCA3Dv+l1VDr17YHE9Cu7Nm4ibXeWJPED28TV90PkBXgxqHWv2pAGwURNmb2pBTE6PvuRVBvvgbE69TLFzfA1Avy1s3IP/jHkVFvw+QyO3PmA4lUKf7RAvEp0AYIbRNnEhO5+1e0p83rUKFXUmLgP3+E3L0rAhsqUz3RKyVyD/x3+yqdhrsHIgBn7w9BzpprYgplapKaIH5RBVTWyAUghAp56VQH8g/dBfXaCyHY+1F42a5duT/fjoGfLjX1/2XPRY2GLNh1+U8/Am/VQ+ZipcY2E2gNxBNInHdl0ZgsBpSaIH6pTRy4/mBEZtPnX7rQWzcjs/znNWVIo0l875lH0Xv150vlUczNddEWAsjnkP3tz0pzCsbyy0YX3UVHI3nRd0yU1vOCMYcBHkFoixgj8quIX44Q8hUo3YXsnb8xrpPtxjkqL98S/7kn0XPRJ02yx3WbJ749UdTRjdzKP8B79N5iN85Rs2eaCTGf+gUkr7oRSKXBPVtKbWKqXEpqHAeI0kXbxgT6etB//ddR2099BInvOPCfexI9F54M3bPFACbLS60iQK8pIFI3cO2VRq+OhqdTSFY1yQSxj30GHb+4B7HFZ5qyvXwO3NdTPZwu2KS4bGbH1dzM4ATNQCIJ9eJqUDIFd++DatOV7eyowWaSRv7Bu9BzyanQvdtsQkQNaXACmEHxuIkK5jKIHXRUMaPY3jYhZV6MEOCeLWY9hQxdI3VkbTEaNwHuIR9F7OiTIOftDzFrD+jnnqzMgAZ8Vl66c/pqoPmpGeS48B69B+4ee0POnGPbk4j2toC3I+QGf3sj+paeZ0AT8URrxA+SEMwQiST8Jx+CnPZ+OHP3LoVn29opxGAEvAfuxMCFS0yn8wUHFmFrDb0um0MBM6ijC3LmbpBz5iG//P8Y2yDo+Ss6hXK9TmEMru6fb7mKhYOer38W+af+x0DGqkudh0ss2nYtessm9F5xFvq/e5HRcbFYZOJHbaQMZlAyjYHvXYz8vXcYw0qp4V9XcZ6QmaCWveGbGPzq6dDb3kHm+qsxeOXZ0BvWl3R5IWQcGgEURZUApUwWtYFHQADkpTsVJECTgxEtTIyzg8jfcwecmbvBmbVH6WGHemoK8XF7OnL334neK86E98ifi6PliDmyvm+qkbKtHMrf998QE6caSVBc1xBVQkGN2XX5zz6GwSvPQf4PvwUlUyDXBcXiUKtXwXvgTiOmd9rVqIUCLqLAkBWAY6qwDXiwH97tvzSp9PI2flV9BGnzoZO5menajNrpIPDyYKWQPusrSJ91WSmt2cygiCIETFfgD/3VT2Pgl9cg9+fbDYAimbJ18E0OUGyyi3ax00gug/gpn0fq3K+b3EJxXSJ4/FvIAOvS9DAqFsLkbv4p8r//jZmuku6qHCsnJZDLAblByJlz4B61GM7Bx0DOmV8nGWYnqBKgN7yJgdMPAzKDgCMrBEcFfnSTZYDoxK8dvUp21i/39cLd+0B0nHM54oceW6vDAwZBlxofV2LevGf/gsxtv0DunhXg/h5j3RJKue92TNUOqsqBaVfjzJmH5FmXInbEJ6rweaoElacqCRoA/1IvrYZ3583I37UMetObhvBCBg6FpEJWNJsBZzOgzi7IXfeC/OBBkHPmQcyaCzFtOiierElkce829J+00FQV24xo0C7QpkMmc/Q2cSHYfC6lcHmg33SxXrgIyeM/hdhBR0FObQwi4Xwe6rUXkH98JfL33A7v+VVmsmiq02LiVfMzc5s59fXg1FIWsXruvP3gfvQUxBYdDbHDjMbl5FpDb1gH74kH4T14F9STDxpLv9giRjVO5BQYQZkJbJzLAfEEKNUB0dkNmvw+iAmTgXSnYYZ4Ahjsh3ffCjsviULlFG06eDI3HhpZJ12MKrtE2E5Vg/0G3TNxKpzd9oKz+zzI982AmDAZ5LhgLw/ODkK/vQ7qzdfg//2vUOteMf5rYcCylLYWjod+mod6nRBGGmQGAOVDjJ8EOXtPyDnzIafvBJo4GRQ3yRkeHIDeshF6/VqoF56DWvsCeNtmY4gm08ZgLtg4UTH81VPGtTaHwuIluICXKBumSR2dFo5eZ782LZrELU0Nr4OqNqLLiiTfTgTP5wwnuvHSOBflm/4+0gFicZPCdZyabOOoE7+aALZjCudzoLwtaI3FQHbNrJXt3092XfFS9VG5Jd8s8cOmhxdskYIxWAjTl3ciqcsAAfqd641arwMMpiA9WjCqrN6g4nQLUXpYXd2PfmgjUVsV+ZFVQ/W6CqBTKjMibY+fCqTVEPP3DetXgrqF1+ugHtnYQwTiB21ocfG6kkFMe6/GRB1Bfd/MddXrqqg3KH9/mAg6bNfZa6kMEsZkx2k1re8bEb+JViXDar2PASahMUz8cgdVEPSAQHC30MCSrKAIW1TiRwCSDEtIt0niUxNEHRHiN0jhtswkZU0k7bWeYKYBe8q52vrnZvU9huG6YdT31OppbqK6ti3Ej4LuqdL3zdoF1vTqE2DeKqo7r3FEfT/cxG8mhTuC+n5IxG8Cot3saW5G5Ff3HZEggHijYOBlp6xFWE0J9hD0fVQjjtqp74eb+C2UYI+2vqeAxumuAMD0kkOaX3IFgRiawWJ7FfloVeQ3e5rbKPKHm0nCrhEETUSCiV92WOC5rGZosCSud0+KbsGPgr4fUyK/BSZp9TS3ch0zpGe81OccX8kHmdSgA6T82mYjw0787c7FGwLxx4rIr85NuoIop3nQZawU04/d/BJprIkZF0G3W9+PVeLTu1Tf166TdEwSiHh14rB1rwhaCs0Cf4yLyl6x/2z+Pcaof09N+vf1LyWAwEQEIvojLYUWpjhA/67HZ01k+gW0xcUbJsjWmPLvh1CSRSOk7wOKQZ2MrzWz/l1hbiBNeaLnWc38aFoSA6SGU9+3BbLVLhevTkvVlq8bWf++roRghkpKwRr8SPr+9X9lgMQDh0ISwDEhruUIGCeKKCHeLfp+zIV0y5I5LVxHGkyk+VoC2NIexABWLYQzXUx4Ii0xf1BBE9W2ytiu/Pt2WPljJIUbVeRTZfBHp6QQg0o9+4++qfsuXLXKLzSLZgBin1XwCFhKBkHCYyWkS++CkC6NpMgPIL7V/cxgCNBV+6xa5WGJob2wN1XLlkBOe2LL7f1Kr+hySGqGalnfbw8h3SHq+7Ho4pXre1SefpVyhcz4ekX6gTdWLFsCScsNfYv46yVzDUKtx1WX9Pt0aFyg22MTMtye8/fbdUg35DQ3cx0D2hUkskptcwRdwgBhbtko6OLnl0IvB8S4R3pf9onPjQsiAdLcoAZ8OP17atW/H0Mp3Hb490MgPhOgY4LIVzgvef8bLy9fAkFLSwG/ms+xFQ8b9hv/kwmuvGCLx34hPrA9Qbbe7SHdKBKCAT/tCieTVz9OPbDuYkvbivoyCmqxaA0EbH5j4s3dkk7Z4rEvypjgPcjW2ND3DWL+ftoVzoCvlqcPXvdJrAZhOXS1gU8hHyYAeOOA9ydSGLy1S4qPbrWS4L0U7uikcFshfsbTdyW1OBErX8vZe3PdsXFlD8oAMOOxdZlBpBb3evq/JrjkCNuB/z3IVvshW60QX5tsjkq70skqXra11z+JVr6WDSN+w+9kUwurAWDLAZN+FJd0SV4Dng62C97T96On7zVDxQTJmCBktb4ucd8bF1rwvaA6GHWK0JawUG/Cmw6YeKpLdG1SiEk9Smt7d/Gevh89fa/ZELfDFSKv+B2lcUHqgddvLqcbok4OracOli2BnPzYO7cM5PngXq1vSwkSHQ4JZmjTUNiqhvcg2k1DtFsgPjNDMUOnpaFD1td35BQtSj3w+s28BDIK8ZueksNlEaRNB078eIzoay5oXyJg0FRA+QwIECqGsrwH2Rq6yC+MdARBE+CkJNnGbfy4kuL7iXteu62aRmimCKeZSb929iZfBYgLPzT5EwScrxiLuh0h85qRM5zAZMLJolCgSnUQJu/p+7I9JoPOJAYTQTMgHQLFhRk+kfW0FoQHAf7f/37fumVLAX0VIK62c1XQwlTDpl/VnLbloMnzlcJJgnAMwLvHhOhIEuCx+VFUMYroPcLXQe0IAhwQHGE+62uGp7kfjDWK+M9xiNti97++KowWI8IA5UGj8i/nJZCbXp+0i5Q4FEx7MmM2CZrF4KkESgOIv5v8+zaI/BwzBoh4A0AvM/glaDwvgQcSU9atrd7roOBOM6//D3yh7zupDILjAAAAAElFTkSuQmCC"

// ---- one credential, two shapes -------------------------------------------

/**
 * A Huawei Cloud STS credential in this package's internal shape — the shape
 * CodeArts has always stored (`access_key_id`, `secret_access_key`,
 * `security_token`, `refresh_token`, `dpop_private_key_jwk` …) plus the MaaS
 * fields OfficeAce needs (`model_app_key`, `model_app_secret`, `maas_base_url`).
 *
 * OfficeAce's own package stored the same credential under different names
 * (`access`, `secret`, `securityToken`, `modelAppKey`, `dpopPrivateJwk` …).
 * `officeAceCredentialOf` reads either and gives this one; `officeAceRecordOf`
 * writes it back in OfficeAce's shape, so a record is readable by both.
 */
function officeAceCredentialOf(auth) {
  if (!auth) return null
  const raw = typeof auth.access === "string" ? safeJson(auth.access) : asRecord(auth.access)
  const flat = raw && typeof raw === "object" ? raw : asRecord(auth)
  const pick = (...vs) => firstOf(...vs)

  const access = pick(flat.access_key_id, flat.access)
  const secret = pick(flat.secret_access_key, flat.secret)
  const securityToken = pick(flat.security_token, flat.securityToken)
  // A record with only the STS triple is a sign-in too: usage and the check-in
  // are signed with it alone (the MaaS appKey only guards catalog and chat).
  if (!access || !secret || !securityToken) return null

  // Which OAuth client issued the refresh token. The CodeArts field names are
  // this package's own flow; OfficeAce's (`access` / `securityToken`) are the
  // old package's, whose refreshes were asked for as `pdp5_for_agentarts`.
  // `oauth_client` is written down when a record says it, so a derived record
  // is renewed the way it was made.
  const codeArtsShape = !!flat.access_key_id && !!flat.secret_access_key
  const profile = profileOf({ refresh_token: pick(flat.refresh_token, auth.refresh) }) || {}
  const domain = pick(flat.domain_id, flat.accountId, profile.account_id, profile.domain_id)
  return {
    access_key_id: access,
    secret_access_key: secret,
    security_token: securityToken,
    expires_at: pick(flat.expires_at, flat.expiresAt, typeof auth.expires === "number" ? new Date(auth.expires).toISOString() : ""),
    refresh_token: pick(auth.refresh, flat.refresh_token, flat.refreshToken),
    code_verifier: pick(flat.code_verifier, flat.codeVerifier),
    dpop_private_key_jwk: flat.dpop_private_key_jwk ?? flat.dpopPrivateJwk ?? null,
    session_id: pick(flat.session_id),
    user_phone: pick(flat.user_phone, auth.user_phone),
    domain_id: domain,
    model_app_key: pick(flat.model_app_key, flat.modelAppKey),
    model_app_secret: pick(flat.model_app_secret, flat.modelAppSecret),
    maas_base_url: pick(flat.maas_base_url, flat.maasBaseUrl),
    oauth_client: pick(flat.oauth_client, flat.oauthClient, codeArtsShape ? "codearts-agent" : OA_AGENTARTS_CLIENT_ID),
  }
}

/** Is this credential one this package's own CodeArts sign-in issued? */
const isCodeArtsClient = (cred) => cred?.oauth_client === "codearts-agent"

/** The credential as `officeace-auth` stores it (its historical shape). */
function officeAceCredentialRecord(cred) {
  const identity = accountIdentityOf(cred)
  const profile = profileOf(cred) || {}
  return {
    modelAppKey: firstOf(cred.model_app_key),
    modelAppSecret: firstOf(cred.model_app_secret),
    maasBaseUrl: firstOf(cred.maas_base_url),
    access: firstOf(cred.access_key_id),
    secret: firstOf(cred.secret_access_key),
    securityToken: firstOf(cred.security_token),
    projectId: "",
    expiresAt: firstOf(cred.expires_at),
    refreshToken: firstOf(cred.refresh_token),
    codeVerifier: firstOf(cred.code_verifier),
    dpopPrivateJwk: cred.dpop_private_key_jwk ?? null,
    session_id: firstOf(cred.session_id),
    accountId: firstOf(profile.account_id, profile.domain_id, cred.domain_id),
    user_phone: firstOf(cred.user_phone),
    // A record written from a credential with no marker of its own is one this
    // package's CodeArts sign-in (or a rotation of it) issued.
    oauth_client: firstOf(cred.oauth_client, "codearts-agent"),
    ...(identity.id ? { uid: identity.id } : {}),
  }
}

/**
 * What magpie shows for an OfficeAce account.
 *
 * `accountId` is the vendor's own stable id — the IAM domain id, as the record
 * `officeace-auth` wrote carried — and never the masked phone: the name,
 * proxy and gateway key a user gives an account hang off `accountId`, so a
 * phone there is both a display leak and a re-keying of that account (#483,
 * magpie#4416). The phone is only ever `usage().user`. `uid` is the same id.
 */
function officeAceIdentityOf(cred) {
  const profile = profileOf(cred) || {}
  const domain = firstOf(profile.account_id, profile.domain_id, cred?.domain_id)
  return { accountId: domain, uid: domain }
}

/** The `{type, refresh, access, expires, accountId, uid}` magpie keeps for OfficeAce. */
function officeAceRecordBody(cred) {
  const identity = officeAceIdentityOf(cred)
  return {
    type: "oauth",
    refresh: firstOf(cred.refresh_token),
    access: JSON.stringify(officeAceCredentialRecord(cred)),
    expires: expiresFromCredential(cred),
    ...(identity.accountId ? { accountId: identity.accountId } : {}),
    ...(identity.uid ? { uid: identity.uid } : {}),
  }
}

/** The same record in CodeArts' shape (for the sibling write). */
function codeArtsRecordBody(cred) {
  const identity = accountIdentityOf(cred)
  return {
    type: "oauth",
    refresh: firstOf(cred.refresh_token),
    access: JSON.stringify(cred),
    expires: expiresFromCredential(cred),
    ...(identity.id ? { accountId: identity.id, uid: identity.id } : {}),
  }
}

/** The MaaS base URL a credential names, or the official one (空串/裸域名 both handled). */
function officeAceMaasBase(cred) {
  const raw = cred?.maas_base_url
  if (typeof raw !== "string" || raw.length === 0) return OA_MAAS_MARKET_BASE
  const trimmed = raw.replace(/\/+$/, "")
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
}

// ---- V11-HMAC-SHA256: what the subscription API checks --------------------

/** `20261030T081500Z` — the X-Sdk-Date form both Huawei signers use. */
function oaSdkDate(now = new Date()) {
  return now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")
}

/**
 * Sign one OfficeAce subscription request (V11-HMAC-SHA256).
 *
 * The differences from the SDK-HMAC signer above are all load-bearing (each
 * was measured against the live gateway):
 *   * the key is derived: HMAC(HMAC(access, secret), scope + 0x01), first 32
 *     bytes hex, and that hex string is the signing key;
 *   * `X-Security-Token` and `x-subscription-type: v2` are mandatory;
 *   * the canonical URI is decoded and re-encoded segment by segment.
 */
function signOfficeAceV11(urlStr, cred, method = "GET", body, dateOverride) {
  const url = new URL(urlStr)
  const xdate = dateOverride ?? oaSdkDate()
  const path = url.pathname.split("/").map((s) => rfc3986(decodeURIComponent(s))).join("/")
  const canonicalUri = path.endsWith("/") ? path : `${path}/`

  const original = {
    "x-subscription-type": "v2",
    "X-Sdk-Date": xdate,
    "X-Security-Token": String(cred.security_token ?? "").trim(),
    Host: url.host,
  }
  if (method === "POST") original["Content-Type"] = "application/json;charset=utf8"
  if (cred.project_id) original["X-Project-ID"] = cred.project_id

  const lower = {}
  for (const [k, v] of Object.entries(original)) lower[k.toLowerCase()] = String(v).trim().replace(/\s+/g, " ")
  const signedHeaders = Object.keys(lower).sort()
  const canonicalHeaders = signedHeaders.map((h) => `${h}:${lower[h]}\n`).join("")

  const payloadHash = createHash("sha256").update(body ?? "", "utf8").digest("hex")
  const canonicalRequest = [
    method, canonicalUri, canonicalQuery(url), canonicalHeaders, signedHeaders.join(";"), payloadHash,
  ].join("\n")

  const scope = `${xdate.slice(0, 8)}/${OA_REGION}/${OA_SERVICE}`
  const stringToSign = [
    "V11-HMAC-SHA256", xdate, scope, createHash("sha256").update(canonicalRequest).digest("hex"),
  ].join("\n")

  const u1 = createHmac("sha256", cred.access_key_id).update(cred.secret_access_key).digest()
  const derivedKey = createHmac("sha256", u1)
    .update(Buffer.concat([Buffer.from(scope, "utf8"), Buffer.from([1])]))
    .digest()
    .subarray(0, 32)
    .toString("hex")
  const signature = createHmac("sha256", Buffer.from(derivedKey, "utf8")).update(stringToSign).digest("hex")

  return {
    ...original,
    Authorization: `V11-HMAC-SHA256 Credential=${cred.access_key_id}/${scope}, SignedHeaders=${signedHeaders.join(";")}, Signature=${signature}`,
  }
}

/** One signed OfficeAce request; a network error is `status: 0` with its reason. */
async function officeAceSigned(cred, urlStr, method = "GET", body, fetcher = fetch) {
  const headers = signOfficeAceV11(urlStr, cred, method, body)
  try {
    const res = await fetcher(urlStr, {
      method,
      headers,
      ...(body === undefined ? {} : { body }),
      signal: AbortSignal.timeout(OA_TOKEN_TIMEOUT_MS),
    })
    const text = await res.text().catch(() => "")
    return { ok: res.ok, status: res.status, text }
  } catch (e) {
    return { ok: false, status: 0, text: e instanceof Error ? e.message : String(e) }
  }
}

// ---- the MaaS appKey: the CLAW permission check --------------------------

/**
 * Read the account's MaaS Basic credentials and base URL from the CLAW
 * permission check — the same call OfficeAce's own sign-in ends with, signed
 * with the STS triple every Huawei Cloud sign-in yields. An account that has
 * not opened MaaS answers without `model_auth_info`: that is not a failure,
 * it only means catalog/chat have nothing to use yet.
 */
async function fetchOfficeAceMaasInfo(cred, fetcher = fetch) {
  const url = `${OA_CLAW_BASE}${OA_PERMISSION_PATH}`
  const extra = { "content-type": "application/json" }
  const signed = await signRequestHuawei(
    cred.access_key_id, cred.secret_access_key, cred.security_token, "GET", url, new Uint8Array(), extra,
  )
  const headers = new Headers()
  signed.forEach((value, key) => {
    if (key !== "host") headers.set(key, value)
  })
  const res = await fetcher(url, { method: "GET", headers, redirect: "error", signal: AbortSignal.timeout(OA_TOKEN_TIMEOUT_MS) })
  if (!res.ok) throw new Error(`OfficeAce permission check failed: HTTP ${res.status}`)
  const body = await res.json().catch(() => null)
  const info = body?.subscription?.model_info
  const auth = info?.model_auth_info
  return {
    model_app_key: typeof auth?.model_app_key === "string" ? auth.model_app_key : "",
    model_app_secret: typeof auth?.model_app_secret === "string" ? auth.model_app_secret : "",
    maas_base_url: typeof info?.model_api_url_base === "string" ? info.model_api_url_base : "",
  }
}

/** The MaaS fields of one account, read at most once per process (best effort). */
const oaMaasCache = new Map() // identity → { at, info }

async function officeAceMaasInfo(cred, fetcher = fetch) {
  const identity = accountIdentityOf(cred).id || cred.session_id || cred.access_key_id
  const hit = oaMaasCache.get(identity)
  if (hit && Date.now() - hit.at < 6 * 60 * 60 * 1000) return hit.info
  const info = await fetchOfficeAceMaasInfo(cred, fetcher).catch(() => null)
  if (info) oaMaasCache.set(identity, { at: Date.now(), info })
  return info
}

// ---- the OfficeAce API ---------------------------------------------------

/** Credit multipliers per account; a failed read keeps the last good table. */
const oaRatesCache = new Map() // identity → { at, map }

/**
 * `GET {SUB}/v1/model-token-rates` — the billable list. It is the whitelist the
 * catalog is cut down to: the catalog lists 26 registry entries, 19 of which
 * cannot be called; the rates list is what the OfficeAce desktop shows.
 *
 * A failure returns the last good table rather than an empty one: an empty
 * table would disable the whitelist downstream and put the uncallable ids back
 * in front of the user (measured defect, 2026-10-26).
 */
async function fetchOfficeAceTokenRates(cred, fetcher = fetch) {
  const identity = accountIdentityOf(cred).id || cred.session_id || cred.access_key_id
  const hit = oaRatesCache.get(identity)
  if (hit && hit.map.size > 0 && Date.now() - hit.at < OA_RATES_TTL_MS) return hit.map
  const keepStale = () => {
    if (hit) oaRatesCache.set(identity, { at: Date.now(), map: hit.map })
    return hit?.map ?? new Map()
  }

  const r = await officeAceSigned(cred, `${OA_SUBSCRIPTION_BASE}${OA_TOKEN_RATES_PATH}`, "GET", undefined, fetcher)
  if (!r.ok) return keepStale()
  let j
  try {
    j = JSON.parse(r.text)
  } catch {
    return keepStale()
  }
  const rows = Array.isArray(j) ? j : Array.isArray(j?.models) ? j.models : Array.isArray(j?.data) ? j.data : Array.isArray(j?.rates) ? j.rates : []
  const map = new Map()
  for (const row of rows) {
    const raw = row?.model_name ?? row?.modelName ?? row?.model ?? row?.name
    // the vendor's `model_name` carries a trailing newline ("kimi-k3\n")
    const name = typeof raw === "string" ? raw.trim() : ""
    const rate = Number(row?.cost_coefficient ?? row?.costCoefficient ?? row?.rate)
    if (name && Number.isFinite(rate)) map.set(name, rate)
  }
  if (map.size === 0) return keepStale()
  oaRatesCache.set(identity, { at: Date.now(), map })
  return map
}

/** `GET {maas}/v2/models`, names carrying the account's multiplier (`· x1.5`). */
async function fetchOfficeAceCatalog(cred, fetcher = fetch) {
  const r = await fetcher(`${officeAceMaasBase(cred)}${OA_MODELS_PATH}`, {
    headers: { Accept: "application/json", Authorization: basicAuthorization(cred) },
    signal: AbortSignal.timeout(OA_TOKEN_TIMEOUT_MS),
  })
  if (!r.ok) throw new Error(`OfficeAce catalog read failed: HTTP ${r.status}`)
  const body = await r.json().catch(() => null)
  const rows = Array.isArray(body) ? body : Array.isArray(body?.data) ? body.data : []
  const rates = await fetchOfficeAceTokenRates(cred, fetcher).catch(() => new Map())
  const out = []
  for (const row of rows) {
    const id = (typeof row === "string" ? row : typeof row?.id === "string" ? row.id : "").trim()
    if (!id) continue
    const base = typeof row?.name === "string" && row.name.trim() ? row.name.trim() : id
    const rate = rates.get(id)
    out.push({ id, name: rate !== undefined && rate !== 1 ? `${base} · x${rate}` : base })
  }
  return out
}

/** One OfficeAce model entry, as magpie wants it. */
function officeAceModelEntry({ id, name, baseUrl = OA_MAAS_MARKET_BASE, context = 1_000_000, output = 128_000 }) {
  return {
    id,
    name,
    api: { id, url: `${baseUrl}/v2`, npm: OFFICEACE_NPM },
    status: "active",
    headers: {},
    options: {},
    cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
    limit: { context, output },
    capabilities: {
      temperature: true,
      reasoning: true,
      attachment: false,
      toolcall: true,
      input: { text: true, image: false, audio: false, video: false, pdf: false },
      output: { text: true, image: false, audio: false, video: false, pdf: false },
      interleaved: false,
    },
    release_date: "",
    variants: {},
  }
}

/** The static table `config` hands magpie before a sign-in (never "0 models"). */
function officeAceStaticModels() {
  const out = {}
  for (const [id, def] of Object.entries(OA_FALLBACK_MODELS)) {
    out[id] = officeAceModelEntry({ id, name: def.name, context: def.context, output: def.output })
  }
  return out
}

/** The account's own catalog: catalog ∩ rates, minus the ids that always 404. */
function officeAceLiveModels(rows, baseUrl, rates) {
  const out = {}
  for (const row of rows) {
    const id = typeof row === "string" ? row : row?.id
    if (typeof id !== "string" || id.length === 0) continue
    if (OA_UNAVAILABLE_IDS.has(id)) continue
    if (rates && rates.size > 0 && !rates.has(id)) continue
    const known = OA_FALLBACK_MODELS[id]
    out[id] = officeAceModelEntry({
      id,
      name: typeof row?.name === "string" && row.name.length > 0 ? row.name : id,
      baseUrl,
      context: known?.context ?? 1_000_000,
      output: known?.output ?? 128_000,
    })
  }
  return out
}

/**
 * One usage window.
 *
 * An expired bucket is folded away (`aside`) and carries no amount/limit: its
 * own total would become the denominator and read as "100% left". It takes no
 * part in routing either, so the fold is all it needs to say.
 */
function officeAceWindow({ name, used, display, unit, resetsAt = "", expired = false, amount = 0, limit = 0 }) {
  return {
    name,
    used,
    display,
    unit,
    ...(resetsAt ? { resetsAt } : {}),
    ...(expired ? { aside: true } : { amount, limit, span: 0 }),
  }
}

/**
 * `GET {SUB}/v1/subscription` → magpie windows.
 *
 * Two kinds of bucket: `skus[].quotas[]` (`sku_attr_code === 'officeace_points'`)
 * and `bonus_skus[]`. A `.trial` sku carries no expiry (the trial never
 * expires — show it as it is, never guess a date); an expired bucket is marked
 * `aside` so the card folds it away instead of letting it hold the top slot.
 */
async function fetchOfficeAceUsage(cred, fetcher = fetch) {
  const r = await officeAceSigned(cred, `${OA_SUBSCRIPTION_BASE}${OA_SUBSCRIPTION_PATH}`, "GET", undefined, fetcher)
  if (!r.ok) {
    const detail = r.text.trim().slice(0, 200)
    throw new Error(`订阅查询失败：HTTP ${r.status}${detail === "" ? "" : `：${detail}`}`)
  }
  let j
  try {
    j = JSON.parse(r.text)
  } catch {
    throw new Error("订阅查询失败：响应不是 JSON")
  }

  const round = (n) => Math.round(n * 100) / 100
  const windows = []
  const nowMs = Date.now()
  let plan = ""

  for (const sku of Array.isArray(j?.skus) ? j.skus : []) {
    for (const q of Array.isArray(sku?.quotas) ? sku.quotas : []) {
      if (q?.sku_attr_code !== "officeace_points") continue
      const total = Number(q.sku_value)
      const used = Number(q.current_value)
      if (!Number.isFinite(total) || total <= 0) continue
      const isTrial = String(sku.sku_code ?? "").endsWith(".trial")
      const expiresAt = typeof q.expired_time === "string" && q.expired_time.length > 0 ? q.expired_time : null
      const remaining = Math.max(0, total - used)
      const expired = expiresAt !== null && !isTrial && new Date(expiresAt).getTime() <= nowMs
      if (!plan && typeof sku.sku_name === "string") plan = sku.sku_name
      windows.push(officeAceWindow({
        name: `${sku.sku_name ?? "套餐"} · 剩 ${round(remaining)}`,
        used: Math.min(100, Math.max(0, Math.round((used / total) * 100))),
        // a `.trial` sku carries no expiry: nothing to invent
        resetsAt: isTrial || expiresAt === null ? "" : new Date(expiresAt).toISOString(),
        display: `${round(remaining)} / ${round(total)}`,
        unit: "积分",
        expired,
        amount: used,
        limit: total,
      }))
    }
  }

  for (const bonus of Array.isArray(j?.bonus_skus) ? j.bonus_skus : []) {
    const points = Number(bonus?.points)
    if (!Number.isFinite(points) || points <= 0) continue
    const used = Number(bonus.current_value)
    const remaining = Math.max(0, points - (Number.isFinite(used) ? used : 0))
    const expiresAt = typeof bonus.expired_time === "string" ? bonus.expired_time : null
    const expired = expiresAt !== null && new Date(expiresAt).getTime() <= nowMs
    windows.push(officeAceWindow({
      name: `${bonus.activity_name ?? "活动奖励"} · 剩 ${round(remaining)}`,
      used: Math.min(100, Math.round(((points - remaining) / points) * 100)),
      resetsAt: expiresAt === null ? "" : new Date(expiresAt).toISOString(),
      display: `${round(remaining)} / ${round(points)}`,
      unit: "积分",
      expired,
      amount: points - remaining,
      limit: points,
    }))
  }

  return { plan, windows }
}

/**
 * `POST {SUB}/v1/subscription/bonus/claim` — the daily check-in.
 *
 * Claiming twice is idempotent: a 2xx with no `bonus_skus` is `done` (today's
 * already taken), not a failure. A 2xx that does not parse is `done` too (the
 * claim itself may have gone through).
 */
async function officeAceCheckin(cred, fetcher = fetch) {
  if (!cred?.access_key_id || !cred?.security_token) {
    return { outcome: "failed", message: "凭据缺失（access 或 securityToken），未发起签到" }
  }
  const r = await officeAceSigned(cred, `${OA_SUBSCRIPTION_BASE}${OA_BONUS_CLAIM_PATH}`, "POST", undefined, fetcher)
  if (!r.ok || r.status < 200 || r.status >= 300) {
    const detail = r.text.trim().slice(0, 200)
    return {
      outcome: "failed",
      message: `HTTP ${r.status === 0 ? "（未发出/无响应）" : r.status}${detail === "" ? "" : `：${detail}`}`,
    }
  }
  if (r.text.length === 0) return { outcome: "claimed", message: "已领取（响应为空）" }
  let j
  try {
    j = JSON.parse(r.text)
  } catch {
    return { outcome: "done", message: "已领取（响应无法解析）" }
  }
  const skus = (Array.isArray(j?.bonus_skus) ? j.bonus_skus : []).map((s) => ({
    name: typeof s?.activity_name === "string" ? s.activity_name : "活动奖励",
    points: Number(s?.points) || 0,
  }))
  const credit = skus.reduce((sum, s) => sum + s.points, 0)
  if (skus.length === 0) return { outcome: "done", message: "今日已无新增可领" }
  return {
    outcome: "claimed",
    ...(credit > 0 ? { credit } : {}),
    message: skus.map((s) => `${s.name} +${s.points}`).join("；"),
  }
}

/** `officeace/<id>` → `<id>`: magpie names the model with the provider prefix. */
function officeAceStripPrefix(body) {
  if (typeof body !== "string" || body.length === 0) return body
  try {
    const parsed = JSON.parse(body)
    if (typeof parsed?.model === "string" && parsed.model.startsWith("officeace/")) {
      parsed.model = parsed.model.slice("officeace/".length)
      return JSON.stringify(parsed)
    }
  } catch {
    // not JSON: pass it through
  }
  return body
}

/** `base64(appKey:appSecret)` — MaaS takes Basic, the AI SDK only sends Bearer. */
function basicAuthorization(cred) {
  return "Basic " + Buffer.from(`${cred.model_app_key}:${cred.model_app_secret}`).toString("base64")
}

const oaBasicFingerprint = (cred) => `${cred?.model_app_key ?? ""}:${cred?.model_app_secret ?? ""}:${cred?.maas_base_url ?? ""}`

/** Is this 4xx the gateway refusing the Basic pair itself? */
function isOfficeAceBasicRejection(status, text) {
  if (status === 401 || status === 403) return true
  if (status < 400 || status >= 500) return false
  return /APIG\.1009|invalid.*(app|key|secret)|appkey|app_key/i.test(text ?? "")
}

/**
 * One chat request to OfficeAce's MaaS: Bearer is rewritten to Basic, the
 * provider prefix stripped. A 401 (or the gateway naming the Basic pair)
 * renews the credential once and sends the request again — but only when the
 * renewal actually changed the pair; retrying the same pair would just be the
 * same refusal with more latency.
 */
async function officeAceChatFetch({ input, init, credential, renew, fetcher = fetch }) {
  const req = input instanceof Request ? input : null
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (req?.url ?? "")
  let body = init?.body
  if (body === undefined && req) body = await req.text()
  body = officeAceStripPrefix(body)
  const target = `${officeAceMaasBase(credential)}${OA_CHAT_PATH}`
  const signal = init?.signal ?? req?.signal ?? AbortSignal.timeout(OA_TOKEN_TIMEOUT_MS)

  const call = (cred) =>
    fetcher(target, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: basicAuthorization(cred) },
      body,
      signal,
    })

  const response = await call(credential)
  if (response.ok) return response

  const text = await response.text().catch(() => "")
  let status = response.status
  let said = text
  let renewal = "not-attempted"
  if (renew && (status === 401 || isOfficeAceBasicRejection(status, said))) {
    const before = oaBasicFingerprint(credential)
    let renewed
    try {
      renewed = await renew()
    } catch {
      renewed = undefined
    }
    if (!renewed) renewal = "unreadable"
    else if (oaBasicFingerprint(renewed) !== before) {
      renewal = "changed"
      const retry = await call(renewed)
      if (retry.ok) return retry
      status = retry.status
      said = await retry.text().catch(() => "")
    } else {
      renewal = "unchanged"
    }
  }

  return Response.json(
    {
      error: {
        type: "provider_error",
        message:
          `OfficeAce（华为 MaaS）返回 HTTP ${status}：${said.slice(0, 200)}（${officeAceDiagnose(status, renewal)}）`,
        provider_status: status,
        credential_rejected: isOfficeAceBasicRejection(status, said),
        renewal_outcome: renewal,
      },
    },
    { status: status >= 400 ? status : 502 },
  )
}

/** One sentence a person can act on. */
function officeAceDiagnose(status, renewal) {
  if (status === 401 || status === 403) {
    if (renewal === "changed") return "续期后仍然是 401，请重新登录"
    if (renewal === "unchanged") return "凭据没变，重试无意义，请重新登录"
    if (renewal === "unreadable") return "续期失败，请重新登录"
    return "凭据被拒，请重新登录"
  }
  if (status === 404) return "模型名不对，或该模型不在这个账号的套餐里"
  if (status === 429) return "被限流，稍后重试或换账号"
  if (status >= 500) return "上游服务错误"
  return "请求被拒"
}

// ---- the two records of one account --------------------------------------
//
// magpie keeps accounts per provider id, and a provider's hooks only ever see
// that provider's own account — there is no call to read another provider's
// record. So the two records of one Huawei Cloud account are written the one
// way the host offers: `client.auth.set` from inside a sign-in or a renewal.
//
// What is remembered here is in this module, shared by the package's two
// plugins (one process, one module): which accounts each provider has, which
// key this package wrote, and the renewal in flight for each refresh chain. A
// record is never written to a key another account may sit at, and a record
// that already holds the account is never written again.
//
// Each record holds its own refresh token: a sign-in writes this card's record
// only, so the two cards of one account are two chains — an `officeace-auth`
// record was issued to `pdp5_for_agentarts`, a CodeArts record to
// `codearts-agent`. Each is only ever renewed with its own token, a renewal
// writes no other record (the host's `auth.set` creates a record that is not
// there), and a failed renewal fails instead of borrowing another chain's.

/** provider id → the identities its accounts were seen as. */
const seenProviderAccounts = new Map()
/** refresh chain → { from, promise }: the renewal in flight. */
const renewalGates = new Map()
/** refresh token → the lineage it belongs to (a rotation keeps its parent's). */
const refreshLineages = new Map()
/** How long a spent token's renewal stands in for it. */
const CHAIN_LIVE_MS = 10 * 60 * 1000
/** How many token lineages are remembered: one per rotation, oldest dropped. */
const LINEAGE_CAP = 1024

/** A stable 8-hex suffix of the account's identity — a key no other account gets. */
function accountKeySuffix(identity) {
  return createHash("sha256").update(String(identity)).digest("hex").slice(0, 8)
}

/** The OAuth client a credential's refresh token was issued to. */
function refreshClientOf(cred) {
  // A canonical credential with no marker of its own is this package's own shape
  // (the CodeArts reader stamps it); only the old OfficeAce chain says pdp5.
  return firstOf(cred?.oauth_client) === OA_AGENTARTS_CLIENT_ID ? OA_AGENTARTS_CLIENT_ID : "codearts-agent"
}

/**
 * The lineage a refresh token belongs to. A token never seen is its own
 * lineage; a rotation answers a new token for the same chain, and
 * `linkRotation` writes that down — so a record still holding the spent token
 * is known to belong to the chain that replaced it.
 */
function lineageOf(token) {
  const held = refreshLineages.get(token)
  if (held) return held
  const fresh = createHash("sha256").update(`refresh-chain\n${token}`).digest("hex").slice(0, 16)
  rememberLineage(token, fresh)
  return fresh
}

function rememberLineage(token, lineage) {
  if (!token || !lineage) return
  if (!refreshLineages.has(token) && refreshLineages.size >= LINEAGE_CAP) {
    // Oldest first. Forgetting a lineage only means a chain is not recognised —
    // that record then spends its own token and fails; two chains never merge.
    const oldest = refreshLineages.keys().next().value
    if (oldest !== undefined) refreshLineages.delete(oldest)
  }
  refreshLineages.set(token, lineage)
}

/**
 * The refresh chain a credential's token belongs to: the OAuth client it was
 * issued to, plus the token's lineage. STS spends a refresh token once, so the
 * chain is the unit of coordination — and a token issued to one client must
 * never be sent to the other, which is why the client is in the key too.
 *
 * The token, not the account: two records of one Huawei Cloud account can sit
 * on two chains, and one must never be renewed with the other's credential.
 */
function refreshChainOf(cred, client = refreshClientOf(cred)) {
  const token = firstOf(cred?.refresh_token)
  if (!token) return { key: "", client, token, lineage: "" }
  const lineage = lineageOf(token)
  return { key: `${client}\n${lineage}`, client, token, lineage }
}

/** A rotation answers a new refresh token for the same chain: remember the parent. */
function linkRotation(cred, next) {
  const from = firstOf(cred?.refresh_token)
  const to = firstOf(next?.refresh_token)
  if (!from || !to || from === to) return
  rememberLineage(to, lineageOf(from))
}

function noteProviderAccount(provider, identity) {
  if (!provider || !identity) return
  const set = seenProviderAccounts.get(provider) ?? new Set()
  set.add(identity)
  seenProviderAccounts.set(provider, set)
}

/** The provider was listed with no account at all: it has none, as far as this process knows. */
function noteProviderEmpty(provider) {
  // No accounts: any identity this process saw before is gone from the provider
  // now, so the set is emptied (a stale identity is not an account).
  seenProviderAccounts.set(provider, new Set())
}

/**
 * Where a record for `identity` may be written under `provider`: the provider's
 * own key while it has no account at all, otherwise a key of its identity's
 * own that no account can be sitting at. `null` when that provider already has
 * this account (writing again would add a second record of one account).
 */
function recordKeyFor(provider, identity) {
  const known = seenProviderAccounts.get(provider)
  if (known?.has(identity)) return null
  if (known && known.size === 0) return provider
  return `${provider}#${accountKeySuffix(identity)}`
}

/** Give the credential the MaaS fields OfficeAce needs (one read per account). */
async function withOfficeAceMaas(cred, fetcher = fetch) {
  if (cred.model_app_key) return cred
  const info = await officeAceMaasInfo(cred, fetcher).catch(() => null)
  // An answer without a pair means "MaaS is not opened for this account": it is
  // not a reason to take a pair the credential already has away.
  if (!info?.model_app_key) return cred
  return { ...cred, ...info }
}

/**
 * Write one account's record under `target`, in that provider's own shape.
 * Used at a sign-in, so the card that signed in keeps its record where a later
 * renewal can find it again. Only ever called for the card's own provider:
 * writing one sign-in into two records is what `STS5.1806` was about.
 */
async function writeProviderRecord(client, target, cred, fetcher = fetch) {
  const identity = accountIdentityOf(cred).id
  if (!identity || !client?.auth?.set) return null
  const key = recordKeyFor(target, identity)
  if (!key) return null
  const body = target === OFFICEACE_PROVIDER
    ? officeAceRecordBody(await withOfficeAceMaas(cred, fetcher))
    : codeArtsRecordBody(cred)
  try {
    await client.auth.set({ path: { id: key }, body })
  } catch {
    return null
  }
  return { key, body }
}

/**
 * Renew one Huawei Cloud credential, once per refresh chain.
 *
 * One credential, renewed once: callers holding the same record (same chain, same
 * token) share a single in-flight renewal, so STS is asked once and everyone gets
 * that answer. Records on different chains (an `officeace-auth` record beside a
 * CodeArts one) never meet in here at all — each spends its own token, and a
 * renewal that fails is a failure, never another chain's credential.
 */
function renewSharedCredential(cred, run, client = refreshClientOf(cred)) {
  const token = firstOf(cred?.refresh_token)
  const chain = refreshChainOf(cred, client)
  if (!chain.key) return Promise.resolve().then(run)
  const held = renewalGates.get(chain.key)
  if (held && held.from === token) return held.promise
  const promise = Promise.resolve()
    .then(run)
    .then((next) => {
      // A rotation rebuilds only the STS half of a credential: what the account
      // carries besides it (its MaaS pair, its phone, its session) stays.
      for (const k of ["model_app_key", "model_app_secret", "maas_base_url", "user_phone", "domain_id", "oauth_client"]) {
        if (cred[k] && !next[k]) next[k] = cred[k]
      }
      // The new token belongs to the same chain: a record still holding the
      // spent one is known to be on it (the gate above). Nothing else is
      // remembered, so a credential a hook merely saw can never stand in for a
      // newer one.
      linkRotation(cred, next)
      return next
    })
    .finally(() => {
      if (renewalGates.get(chain.key)?.promise === promise) renewalGates.delete(chain.key)
    })
  renewalGates.set(chain.key, { from: token, promise })
  return promise
}

/**
 * Renew a credential through the OAuth client that issued its refresh token:
 * this package's CodeArts flow (verifier + DPoP key, no client change), or the
 * old OfficeAce flow (`pdp5_for_agentarts`, DPoP key only).
 */
async function renewOfficeAceCredential(cred, fetcher = fetch) {
  if (!cred.refresh_token) {
    throw Object.assign(new Error("OfficeAce 凭据无法续期（没有 refresh token），请重新登录"), { signIn: "expired" })
  }
  if (!cred.dpop_private_key_jwk) {
    throw Object.assign(new Error("OfficeAce 凭据无法续期（DPoP 私钥缺失），请重新登录"), { signIn: "expired" })
  }
  const keyPair = keyPairFromStoredJwk(cred.dpop_private_key_jwk)
  const client = refreshClientOf(cred)
  const token = client === "codearts-agent"
    ? await requestToken({
        client_id: CLIENT_ID,
        code_verifier: firstOf(cred.code_verifier),
        grant_type: GRANT_REFRESH_TOKEN,
        refresh_token: firstOf(cred.refresh_token),
      }, keyPair, fetcher, "OfficeAce")
    : await requestToken({
        client_id: OA_AGENTARTS_CLIENT_ID,
        grant_type: GRANT_REFRESH_TOKEN,
        refresh_token: firstOf(cred.refresh_token),
      }, keyPair, fetcher, "OfficeAce")
  const next = credentialFromTokenResponse(token, firstOf(cred.code_verifier), keyPair)
  // What a rotation does not rebuild: the account's one upstream session, its
  // identity, its phone and the MaaS credentials behind the preserved appKey.
  for (const k of ["session_id", "domain_id", "user_phone", "model_app_key", "model_app_secret", "maas_base_url", "oauth_client"]) {
    if (cred[k]) next[k] = cred[k]
  }
  if (!next.refresh_token) next.refresh_token = cred.refresh_token
  if (!next.oauth_client) next.oauth_client = client
  // The MaaS Basic pair is minted per permission check and can rotate with the
  // session: read it again when this account has one. Best effort — the stored
  // pair stands when the CLAW call is down.
  if (cred.model_app_key) {
    const info = await fetchOfficeAceMaasInfo(next, fetcher).catch(() => null)
    if (info?.model_app_key) {
      Object.assign(next, info)
      oaMaasCache.set(accountIdentityOf(next).id || next.access_key_id, { at: Date.now(), info })
    }
  }
  return next
}

/**
 * Is this credential close enough to its expiry to renew first?
 */
function nearOfficeAceExpiry(cred) {
  const at = Date.parse(firstOf(cred?.expires_at))
  return Number.isFinite(at) && at - Date.now() <= OA_REFRESH_LEAD_MS
}

/**
 * Store an OfficeAce record for the account this hook runs for (its own
 * scope's key), keeping the account's stored `accountId` / `uid`.
 *
 * magpie hangs a user's own name, proxy and gateway key for an account off
 * `accountId`; rewriting it (a phone, or a domain id over the phone an older
 * `officeace-auth` stored) would re-key the account. So a stored value stands,
 * and one computed from the credential is only filled in when there is none —
 * as CodeArts' own `persistCredential` does.
 */
async function persistOfficeAceRecord(client, cred, prev) {
  const body = officeAceRecordBody(cred)
  const accountId = firstOf(prev?.accountId, body.accountId)
  const uid = firstOf(prev?.uid, body.uid)
  const record = {
    ...body,
    ...(accountId ? { accountId } : {}),
    ...(uid ? { uid } : {}),
  }
  try {
    await client?.auth?.set?.({ path: { id: OFFICEACE_PROVIDER }, body: record })
  } catch {
    /* best effort: the next renewal writes it again */
  }
  return record
}

/**
 * OfficeAce — the second provider of this package, signed in on its own card
 * through Huawei Cloud OAuth like `codearts`, with a record and a refresh token
 * of its own.
 *
 * Provider id `officeace`: the id `officeace-auth` used, so the accounts signed
 * in through that package are read from where magpie already keeps them
 * (`officeace`, `officeace#xxxxxx`) and nobody signs in again.
 */
export const OfficeAceAuthPlugin = async ({ client } = {}, options = {}) => {
  const fetcher = typeof options?.fetch === "function" ? options.fetch : fetch
  const log = (message, level = "info") => {
    try {
      client?.app?.log?.({ service: "officeace", level, message })
    } catch {
      /* no log channel */
    }
  }
  /** This account's credential, as either shape declares it. */
  const credential = (auth) => officeAceCredentialOf(auth)
  const renewNow = (cred) => renewSharedCredential(cred, () => renewOfficeAceCredential(cred, fetcher))

  return {
    // The provider and the models it shows before anyone is signed in.
    config: async (config) => {
      config.provider ??= {}
      config.provider[OFFICEACE_PROVIDER] ??= {}
      const p = config.provider[OFFICEACE_PROVIDER]
      p.name ??= "OfficeAce"
      p.npm ??= OFFICEACE_NPM
      p.api ??= `${OA_MAAS_MARKET_BASE}/v2`
      p.models = { ...officeAceStaticModels(), ...(p.models ?? {}) }
    },

    // The account's own catalog: the billable list, minus the ids that always 404.
    provider: {
      id: OFFICEACE_PROVIDER,
      async models(provider, { auth } = {}) {
        let cred = credential(auth)
        if (!cred) {
          // No account of its own: nothing is adopted here. An OfficeAce record
          // is only ever written by this card's own sign-in — an account the
          // user signed out of must not come back on the next listing.
          noteProviderEmpty(OFFICEACE_PROVIDER)
          return provider.models
        }
        const identity = accountIdentityOf(cred).id
        if (identity) noteProviderAccount(OFFICEACE_PROVIDER, identity)

        if (!cred.model_app_key) {
          const healed = await withOfficeAceMaas(cred, fetcher)
          if (healed.model_app_key) cred = healed
        }
        // The catalog and chat are behind the MaaS appKey; without it the
        // static table is all there is (and it is honest: nobody knows yet).
        if (!cred.model_app_key) return provider.models

        const base = officeAceMaasBase(cred)
        try {
          const rows = await fetchOfficeAceCatalog(cred, fetcher)
          if (!rows.length) return provider.models
          let rates = null
          try {
            rates = await fetchOfficeAceTokenRates(cred, fetcher)
          } catch {
            rates = null
          }
          // An empty rates table means "never read", not "no model is billable":
          // fall back to the static table rather than the registry's 26 ids, 19
          // of which the user can select and then only fail at chat.
          if (!rates || rates.size === 0) {
            log("倍率表不可用（空表）—— 目录降级为静态表，不列出注册表占位 id", "warn")
            return provider.models
          }
          const live = officeAceLiveModels(rows, base, rates)
          if (Object.keys(live).length === 0) {
            log("倍率表与模型目录零交集 —— 退回静态表", "warn")
            return provider.models
          }
          return live
        } catch (e) {
          log(`目录拉取失败，回退静态表：${e?.message ?? e}`, "warn")
          if (/401|403|unauthorized|被拒/i.test(String(e?.message))) {
            throw Object.assign(new Error("OfficeAce 登录已失效，请重新登录"), { signIn: "expired" })
          }
          return provider.models
        }
      },
    },

    auth: {
      provider: OFFICEACE_PROVIDER,
      icon: OFFICEACE_ICON,
      maxConcurrency: 3,
      refreshLead: OA_REFRESH_LEAD_MS,

      methods: [
        {
          type: "oauth",
          label: "Sign in with Huawei Cloud",
          /**
           * A sign-in of this card's own, not the CodeArts card's: the STS
           * triple it yields signs both vendors' APIs (measured), but a Huawei
           * Cloud refresh token is spent once, so a second record holding this
           * one would sign this card out at its renewal (`STS5.1806`).
           *
           * `authorize()` returns at once; the waiting happens in `callback()`.
           */
          async authorize() {
            const flow = await startOAuthFlow(fetcher, "OfficeAce")
            return {
              url: flow.loginUrl,
              instructions:
                "Sign in to Huawei Cloud in the browser. This signs in OfficeAce only — the CodeArts card has its own sign-in. This window closes itself when done.",
              method: "auto",
              async callback() {
                try {
                  const outcome = await flow.result
                  const cred = safeJson(outcome.access)
                  if (!cred?.access_key_id) {
                    return { type: "failed", error: "Huawei Cloud did not return a credential" }
                  }
                  // The card's name (its phone), and OfficeAce's MaaS credentials.
                  const identified = { ...cred, ...(await accountPhoneField(cred, fetcher)) }
                  const withMaas = await withOfficeAceMaas(identified, fetcher)
                  // This sign-in writes this card's record only — the two cards
                  // never share a refresh token, which is spent once.
                  await writeProviderRecord(client, OFFICEACE_PROVIDER, withMaas, fetcher)
                  return { ...officeAceRecordBody(withMaas), type: "success" }
                } catch (e) {
                  return { type: "failed", error: e?.message ?? String(e) }
                } finally {
                  await flow.close()
                }
              },
            }
          },
        },
      ],

      /** Renew this account's credential — this card's record only. */
      async refresh(auth) {
        const cred = credential(auth)
        if (!cred) return undefined
        const next = await renewNow(cred)
        if (!next) return undefined
        const body = officeAceRecordBody(next)
        // magpie merges this into the stored record. `accountId` is what the
        // user's own name, proxy and gateway key for the account hang off, so a
        // renewal never renames one: a stored value stands (phone or domain id,
        // as `officeace-auth` wrote it), and one is only filled in when missing.
        return {
          access: body.access,
          refresh: body.refresh,
          expires: body.expires,
          ...(auth.accountId || !body.accountId ? {} : { accountId: body.accountId }),
          ...(auth.uid || !body.uid ? {} : { uid: body.uid }),
        }
      },

      /** Rewrite Bearer to Basic, strip the provider prefix, renew once on a 401. */
      async loader(getAuth) {
        const stored = await getAuth()
        let cred = credential(stored)
        if (!cred) return {}
        const identity = accountIdentityOf(cred).id
        if (identity) noteProviderAccount(OFFICEACE_PROVIDER, identity)

        if (!cred.model_app_key) {
          const healed = await withOfficeAceMaas(cred, fetcher)
          if (healed.model_app_key) {
            cred = healed
            await persistOfficeAceRecord(client, cred, stored)
          }
        }
        // Signed in, but MaaS was never opened for this account: say so instead
        // of sending an empty Basic header upstream (a 400 that reads like a
        // broken model). Usage and the check-in work off the STS triple alone.
        if (!cred.model_app_key) {
          return {
            async fetch() {
              return Response.json(
                {
                  error: {
                    message:
                      "OfficeAce 账号已登录，但还没有接入华为云 MaaS（凭据里没有 modelAppKey）。" +
                      "请在 OfficeAce 客户端完成「接入华为云 MaaS 模型」后重试；额度与签到不受影响，已经可以正常使用。",
                    type: "officeace_maas_not_linked",
                    code: "MaaSNotLinked",
                  },
                },
                { status: 400, headers: { "content-type": "application/json" } },
              )
            },
          }
        }

        return {
          // Empty: the URL is built from the credential's own MaaS base.
          baseURL: "",
          apiKey: "",
          async fetch(input, init) {
            const freshRecord = await getAuth().catch(() => null)
            const fresh = credential(freshRecord) ?? cred
            return officeAceChatFetch({
              input,
              init,
              credential: fresh,
              fetcher,
              renew: async () => {
                try {
                  const next = await renewNow(fresh)
                  if (next) {
                    await persistOfficeAceRecord(client, next, freshRecord ?? stored)
                  }
                  return next
                } catch (e) {
                  log(`续期失败：${e?.message ?? e}`, "warn")
                  return undefined
                }
              },
            })
          },
        }
      },

      /** The subscription's buckets: plan quotas and activity bonuses. */
      async usage(getAuth) {
        const cred = credential(await getAuth())
        if (!cred) return { error: "未登录", windows: [] }
        try {
          const u = await fetchOfficeAceUsage(cred, fetcher)
          // The phone is a display name, so it goes here only — never into the
          // record's `accountId` (see officeAceIdentityOf).
          const user = firstOf(cred.user_phone, officeAceIdentityOf(cred).accountId)
          return {
            plan: u.plan || "OfficeAce",
            ...(user ? { user } : {}),
            windows: u.windows,
          }
        } catch (e) {
          return { error: String(e?.message ?? e).slice(0, 300), windows: [] }
        }
      },

      /** The daily claim; claiming twice is idempotent (a 2xx with no skus is `done`). */
      async checkin(getAuth) {
        const stored = await getAuth()
        const cred = credential(stored)
        if (!cred) return { outcome: "failed", message: "未登录" }
        try {
          let use = cred
          if (nearOfficeAceExpiry(cred) && cred.refresh_token) {
            try {
              use = (await renewNow(cred)) ?? cred
              if (use !== cred) await persistOfficeAceRecord(client, use, stored)
            } catch {
              /* try with what is stored */
            }
          }
          const result = await officeAceCheckin(use, fetcher)
          if (result.outcome === "claimed") log(`签到：${result.message ?? "已领取"}`)
          return result
        } catch (e) {
          return { outcome: "failed", message: String(e?.message ?? e).slice(0, 300) }
        }
      },
    },

    /** Per-request header: the same conversation keeps one upstream session. */
    "chat.headers": async (input, output) => {
      const id = input?.model?.providerID ?? input?.provider?.info?.id
      if (id !== OFFICEACE_PROVIDER || !input?.sessionID) return
      output.headers["x-officeace-session"] = String(input.sessionID).slice(0, 128)
    },
  }
}

// for tests (never a plugin: magpie only calls exported functions)
export const _officeace = {
  OFFICEACE_PROVIDER, OA_FALLBACK_MODELS, OA_UNAVAILABLE_IDS, OA_MAAS_MARKET_BASE,
  OA_SUBSCRIPTION_BASE, OA_CLAW_BASE, OA_PERMISSION_PATH, OA_TOKEN_RATES_PATH,
  officeAceCredentialOf, officeAceCredentialRecord, officeAceRecordBody, codeArtsRecordBody,
  officeAceIdentityOf, officeAceMaasBase, officeAceModelEntry, officeAceStaticModels,
  officeAceLiveModels, fetchOfficeAceUsage, officeAceCheckin, officeAceStripPrefix,
  officeAceChatFetch, officeAceDiagnose, isOfficeAceBasicRejection, oaBasicFingerprint,
  fetchOfficeAceTokenRates, fetchOfficeAceCatalog, fetchOfficeAceMaasInfo, officeAceMaasInfo,
  signOfficeAceV11, oaSdkDate, officeAceSigned, basicAuthorization, isCodeArtsClient,
  renewOfficeAceCredential, renewSharedCredential, nearOfficeAceExpiry,
  accountKeySuffix, recordKeyFor, writeProviderRecord,
  refreshClientOf, refreshChainOf, refreshLineages, lineageOf, linkRotation, rememberLineage,
  noteProviderAccount, noteProviderEmpty, seenProviderAccounts,
  renewalGates, withOfficeAceMaas, persistOfficeAceRecord,
  OFFICEACE_ICON,
}


