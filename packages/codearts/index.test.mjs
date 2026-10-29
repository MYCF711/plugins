// Unit tests for the CodeArts OAuth plugin. Run with: bun test (node --test
// runs them too).
//
// These tests exercise the pieces magpie calls (_internal helpers) and the
// hooks the plugin returns, with the network stubbed out via `options.fetch`.

import test from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"
import http from "node:http"
import net from "node:net"
import os from "node:os"
import path from "node:path"

import { CodeArtsAuthPlugin, _internal as x } from "./index.mjs"

// Never the real ledger in ~/.config/magpie: every plugin made here keeps its
// check-ins in a scratch file of its own.
const ledgerDir = fs.mkdtempSync(path.join(os.tmpdir(), "codearts-ledger-"))
process.env.MAGPIE_CODEARTS_LEDGER = path.join(ledgerDir, "default.json")
test.after(() => fs.rmSync(ledgerDir, { recursive: true, force: true }))

const buf = (s) => new TextEncoder().encode(s)

// ---- crypto primitives -----------------------------------------------------

test("sha256Hex matches the known SHA-256 of the empty string", async () => {
  assert.equal(
    await x.sha256Hex(new Uint8Array()),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
})

test("hmacSha256Hex matches RFC 4231 test case 2", async () => {
  assert.equal(
    await x.hmacSha256Hex(buf("Jefe"), buf("what do ya want for nothing?")),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
})

test("generatePkcePair derives the S256 challenge from the verifier", async () => {
  const pkce = await x.generatePkcePair()
  assert.match(pkce.codeVerifier, /^[A-Za-z0-9_-]{64}$/)
  const expected = x.b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", buf(pkce.codeVerifier))))
  assert.equal(pkce.codeChallenge, expected)
})

test("signDpopJws produces a verifiable ES256 dpop+jwt", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const jws = await x.signDpopJws(keyPair, "POST", "https://sts.example.com/tokens")
  const [h, p, s] = jws.split(".")
  assert.equal(jws.split(".").length, 3)

  const header = JSON.parse(Buffer.from(h, "base64url").toString())
  assert.equal(header.alg, "ES256")
  assert.equal(header.typ, "dpop+jwt")
  assert.deepEqual(header.jwk, keyPair.publicKeyJwk)

  const payload = JSON.parse(Buffer.from(p, "base64url").toString())
  assert.equal(payload.htm, "POST")
  assert.equal(payload.htu, "https://sts.example.com/tokens")
  assert.equal(typeof payload.iat, "number")
  assert.equal(typeof payload.jti, "string")

  const key = await crypto.subtle.importKey(
    "jwk", keyPair.publicKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
  )
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(s, "base64url"), buf(`${h}.${p}`),
  )
  assert.ok(ok, "the DPoP signature must verify against the advertised public key")
})

// ---- SDK-HMAC-SHA256 signing -----------------------------------------------

test("buildCanonicalRequest lays out the canonical request exactly", () => {
  const headers = new Map([
    ["host", "example.com"],
    ["x-sdk-content-sha256", "H"],
    ["x-sdk-date", "D"],
    ["x-security-token", "ST"],
  ])
  const expected = [
    "GET",
    "/path/",
    "",
    "host:example.com",
    "x-sdk-content-sha256:H",
    "x-sdk-date:D",
    "x-security-token:ST",
    "",
    "host;x-sdk-content-sha256;x-sdk-date;x-security-token",
    "H",
  ].join("\n")
  assert.equal(x.buildCanonicalRequest("GET", "/path/", "", headers, "H"), expected)
})

test("signRequestHuawei signs a GET with the expected header set", async () => {
  const signed = await x.signRequestHuawei(
    "AK", "SK", "ST", "GET", "https://example.com/path", new Uint8Array(), undefined, "20260101T000000Z",
  )
  assert.equal(signed.get("x-sdk-date"), "20260101T000000Z")
  assert.equal(
    signed.get("x-sdk-content-sha256"),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert.equal(signed.get("x-security-token"), "ST")
  // GET carries no content-type.
  assert.equal(signed.has("content-type"), false)
  assert.match(
    signed.get("Authorization"),
    /^SDK-HMAC-SHA256 Access=AK,SignedHeaders=host;x-sdk-content-sha256;x-sdk-date;x-security-token,Signature=[0-9a-f]{64}$/,
  )
})

test("signRequestHuawei includes content-type and maas_type in a signed POST", async () => {
  const signed = await x.signRequestHuawei(
    "AK", "SK", "ST", "POST", "https://example.com/api/v2/chat/completions",
    buf('{"model":"glm-5.3-flash"}'), { maas_type: "benefit" }, "20260101T000000Z",
  )
  const auth = signed.get("Authorization")
  assert.match(auth, /SignedHeaders=content-type;host;maas_type;x-sdk-content-sha256;x-sdk-date;x-security-token,/)
  assert.equal(signed.get("content-type"), "application/json")
  assert.equal(signed.get("maas_type"), "benefit")
})

test("canonicalQuery sorts and RFC 3986-encodes the query the way the gateway checks it", () => {
  assert.equal(x.canonicalQuery(new URL("https://h/p?offset=0&limit=100")), "limit=100&offset=0")
  assert.equal(x.canonicalQuery(new URL("https://h/p?agent_id=a b&x=(1)*")), "agent_id=a%20b&x=%281%29%2A")
  assert.equal(x.canonicalQuery(new URL("https://h/p")), "")
})

test("vendorDate reads CodeArts' dates; a zone-less one is Beijing time", () => {
  assert.equal(x.vendorDate("2026-11-01"), Date.parse("2026-10-31T16:00:00Z"))
  assert.equal(x.vendorDate("2026-11-01 08:30:00"), Date.parse("2026-11-01T00:30:00Z"))
  assert.equal(x.vendorDate("2026-11-01T00:00:00Z"), Date.parse("2026-11-01T00:00:00Z"))
  assert.equal(x.vendorDate(1793462400), 1793462400000)
  assert.equal(x.vendorDate("1793462400000"), 1793462400000)
  assert.equal(x.vendorDate("soon"), undefined)
  assert.equal(x.vendorDate(""), undefined)
})

test("creditRateOf reads the 消耗系数 from one tier or a list of them", () => {
  assert.equal(x.creditRateOf({ ratio: 2, ratio_display: "1.5" }), 1.5)
  assert.equal(x.creditRateOf([{ ratio_display: 0.3 }, { ratio_display: 2 }]), 0.3)
  assert.equal(x.creditRateOf(undefined), 0)
  assert.equal(x.creditRateOf({ ratio_display: "0" }), 0)
})

test("signRequestHuawei is deterministic for a fixed date stamp", async () => {
  const args = ["AK", "SK", "ST", "POST", "https://example.com/x", buf("body"), undefined, "20260101T000000Z"]
  const a = await x.signRequestHuawei(...args)
  const b = await x.signRequestHuawei(...args)
  assert.equal(a.get("Authorization"), b.get("Authorization"))
})

test("signRequestHuawei matches an independent SDK-HMAC-SHA256 implementation", async () => {
  // A known answer, from an independent (Python) SDK-HMAC-SHA256: an unsorted
  // query, a signed extra header, a URI that needs its trailing slash. Signing
  // the wrong hash, dropping the slash or the query order all change it.
  const signed = await x.signRequestHuawei(
    "AK", "SK", "ST", "POST", "https://example.com/api/v2/chat/completions?b=2&a=1",
    buf('{"m":1}'), { maas_type: "benefit" }, "20260101T000000Z",
  )
  assert.equal(
    signed.get("Authorization"),
    "SDK-HMAC-SHA256 Access=AK,SignedHeaders=content-type;host;maas_type;x-sdk-content-sha256;x-sdk-date;x-security-token,"
      + "Signature=f33e9f9e8fa23cb4dbac42f858e310657f72cc67179a098e0b3a2fa9a693e161",
  )
})

// ---- helpers ---------------------------------------------------------------

test("normalizeModelId strips only a trailing 4-digit date", () => {
  assert.equal(x.normalizeModelId("deepseek-v4-flash-0731"), "deepseek-v4-flash")
  assert.equal(x.normalizeModelId("glm-5.3-flash"), "glm-5.3-flash")
  assert.equal(x.normalizeModelId("GLM-5.2"), "GLM-5.2")
})

test("upstreamModelId drops the host's provider prefix only", () => {
  assert.equal(x.upstreamModelId("codearts/deepseek-v4.1-flash"), "deepseek-v4.1-flash")
  assert.equal(x.upstreamModelId("GLM-5.2"), "GLM-5.2")
  assert.equal(x.upstreamModelId("other/GLM-5.2"), "other/GLM-5.2")
})

test("parseModelInfo drops vision models, dedupes, and fills context", () => {
  const seen = new Set()
  assert.equal(x.parseModelInfo({ model_id: "Qwen3-VL-235B", model_name: "Qwen3-VL-235B" }, seen), undefined)
  assert.equal(x.parseModelInfo({ model_id: "kimi-k2.6-vl" }, seen), undefined)
  const a = x.parseModelInfo({ model_id: "GLM-5.2", model_name: "GLM-5.2" }, seen)
  assert.deepEqual(a, { id: "GLM-5.2", name: "GLM-5.2", context: 202752 })
  assert.equal(x.parseModelInfo({ model_id: "GLM-5.2", model_name: "GLM-5.2" }, seen), undefined)
})

test("parseModelInfo keeps the dated id, and its bare form as another model", () => {
  const seen = new Set()
  const dated = x.parseModelInfo({ model_id: "deepseek-v4-flash-0731", model_name: "deepseek-v4-flash-0731", max_tokens: 131072 }, seen)
  assert.deepEqual(dated, { id: "deepseek-v4-flash-0731", name: "deepseek-v4-flash", context: 1048576, output: x.MAX_OUTPUT_TOKENS })
  assert.equal(x.parseModelInfo({ model_id: "deepseek-v4-flash" }, seen).id, "deepseek-v4-flash")
})

test("prepareChatBody reshapes a chat into what the gateway accepts and meters", () => {
  const out = x.prepareChatBody({ model: "codearts/GLM-5.2", messages: [], max_tokens: 128000 })
  assert.equal(out.fold, true)
  assert.deepEqual(out.body, { model: "GLM-5.2", messages: [], max_tokens: x.MAX_OUTPUT_TOKENS, thinking: { type: "enabled" }, stream: true })

  const streamed = x.prepareChatBody({ model: "GLM-5.2", messages: [], stream: true, thinking: { type: "disabled" } })
  assert.equal(streamed.fold, false)
  assert.deepEqual(streamed.body.thinking, { type: "disabled" })

  assert.equal(x.prepareChatBody({ model: "GLM-5.2", messages: [] }, { thinking: false }).body.thinking, undefined)
  assert.equal(x.prepareChatBody({ model: "GLM-5.2" }), null)
  assert.equal(x.prepareChatBody(null), null)
})

// The free model's TPM limit, word for word as the gateway sent it in a 200.
const tpmEvent = 'data:{"text":"[DONE]","error_code":"InferHub.ModelArts.81111.429","error_msg":"The model TPM limit has been significantly exceeded. Please reduce the request rate and retry later."}'

test("classifyHead tells an answer from an embedded error", () => {
  const role = `data: ${JSON.stringify({ choices: [{ delta: { role: "assistant" } }] })}\n\n`
  const content = `data: ${JSON.stringify({ choices: [{ delta: { content: "hi" } }] })}\n\n`
  const cap = `data: {"error_code":"TM.00001041","error_msg":"并发会话数已达上限(3个)"}\n\n`
  assert.equal(x.classifyHead(role, false), undefined) // a role-only delta decides nothing
  assert.equal(x.classifyHead(role + content, false), "answer")
  assert.equal(x.classifyHead(role + cap, false), "TM.00001041")
  assert.equal(x.classifyHead(`data: {"error_code":"TM.00001041"`, false), undefined) // not whole yet
  assert.equal(x.classifyHead("", true), "answer")
  assert.equal(x.classifyHead(JSON.stringify({ choices: [{ message: { content: "x" } }] }), true), "answer")
  // The free model's TPM limit, as the gateway sends it: no space after
  // `data:`, a code of several parts, and a "[DONE]" that is no end.
  assert.equal(x.classifyHead(`${tpmEvent}\n\n`, false), "InferHub.ModelArts.81111.429")
  assert.equal(x.classifyHead(`data: ${JSON.stringify({ text: "[DONE]" })}\n\n`, false), undefined)
  assert.equal(x.classifyHead(role + "data: [DONE]\n\n", false), "answer")
})

test("errorCodeOf / errorMessageOf / isRateLimitCode read the gateway's errors", () => {
  const text = '{"error_code":"InferHub.4291.200","error_msg":"insufficient \\"quota\\""}'
  assert.equal(x.errorCodeOf(text), "InferHub.4291.200")
  assert.equal(x.errorMessageOf(text), 'insufficient "quota"')
  for (const code of ["InferHub.ModelArts.81111.429", "TM.00001041", "APIG.0602", "81114.429", "STS5.1806"]) {
    assert.equal(x.errorCodeOf(`{"error_code":"${code}"}`), code)
  }
  assert.equal(x.errorCodeOf('{"code":"build"}'), "", "a word is no code")
  assert.equal(x.isRateLimitCode("InferHub.ModelArts.81111.429"), true)
  assert.equal(x.isRateLimitCode("InferHub.4291.200"), true)
  assert.equal(x.isRateLimitCode("81111.429"), true)
  assert.equal(x.isRateLimitCode("InferHub.002002009.404"), false)
  assert.equal(x.isStaleCredential('{"error_code":"APIG.0602"}'), true)
  assert.equal(x.isStaleCredential('{"error_code":"APIG.0301","error_msg":"verify ak sk signature fail"}'), true)
})

test("accountIdentityOf reads the signer from the refresh token's user_profile", () => {
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
  const profile = { principal_urn: "iam::d1:user:alice", user_name: "alice" }
  const asString = `h.${b64u({ user_profile: JSON.stringify(profile) })}.s`
  assert.deepEqual(x.accountIdentityOf({ refresh_token: asString }), { id: "iam::d1:user:alice", name: "alice" })
  const asB64 = `h.${b64u({ user_profile: b64u(profile) })}.s`
  assert.deepEqual(x.accountIdentityOf({ refresh_token: asB64 }), { id: "iam::d1:user:alice", name: "alice" })
  assert.deepEqual(x.accountIdentityOf({ refresh_token: "opaque", user_name: "bob" }), { id: "bob", name: "bob" })
})

// A credential whose refresh token carries the IAM claims a real one does.
function credWithProfile(claims) {
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
  return {
    access_key_id: "AK",
    secret_access_key: "SK",
    security_token: "ST",
    refresh_token: `h.${b64u({ user_profile: JSON.stringify(claims) })}.s`,
  }
}

test("maskPhone shows a number a person can tell apart, or nothing", () => {
  // Huawei Cloud IAM answers `0086-18970098051`; the other magpie cards show
  // `189****8051`.
  assert.equal(x.maskPhone("0086-18970098051"), "189****8051")
  assert.equal(x.maskPhone("+86 189 7009 8051"), "189****8051")
  assert.equal(x.maskPhone("18970098051"), "189****8051")
  // Too short to be a number: no name, so the caller falls back.
  assert.equal(x.maskPhone(""), "")
  assert.equal(x.maskPhone("12345"), "")
  assert.equal(x.maskPhone(undefined), "")
})

test("accountIdentityOf names an account by its phone, never by IAM's ids", () => {
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
  const profile = { principal_urn: "iam::d1:user:hw123", account_name: "hw123" }
  const token = `h.${b64u({ user_profile: JSON.stringify(profile) })}.s`
  // The phone read from IAM stands in front of `hw123` and of the URN.
  assert.deepEqual(x.accountIdentityOf({ refresh_token: token, user_phone: "189****8051" }), {
    id: "iam::d1:user:hw123",
    name: "189****8051",
  })
  // Without one, the account name — while `id` stays the URN magpie keys by.
  assert.deepEqual(x.accountIdentityOf({ refresh_token: token }), { id: "iam::d1:user:hw123", name: "hw123" })
})

test("fetchAccountPhone reads IAM with the account's own credentials, and only once", async () => {
  const seen = []
  const cred = credWithProfile({ principal_id: "uid-1" })
  const fetcher = async (url, init) => {
    seen.push([String(url), new Headers(init.headers).get("authorization")])
    return new Response(JSON.stringify({ user: { name: "hw123", phone: "0086-18970098051" } }), { status: 200 })
  }
  assert.equal(await x.fetchAccountPhone(cred, fetcher), "189****8051")
  assert.equal(seen.length, 1)
  assert.equal(seen[0][0], "https://iam.cn-north-4.myhuaweicloud.com/v3.0/OS-USER/users/uid-1")
  assert.ok(String(seen[0][1]).startsWith("SDK-HMAC-SHA256 "), "signed, like every other call of the account")
  // The number does not change: the second read is free.
  assert.equal(await x.fetchAccountPhone(cred, fetcher), "189****8051")
  assert.equal(seen.length, 1)
})

test('fetchAccountPhone is best effort — no claim, a refusal, or no number gives ""', async () => {
  // No `principal_id` in the token: IAM is never called.
  const unreadable = { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", refresh_token: "R" }
  assert.equal(await x.fetchAccountPhone(unreadable, async () => { throw new Error("must not be called") }), "")
  const cred = credWithProfile({ principal_id: "uid-2" })
  assert.equal(await x.fetchAccountPhone(cred, async () => new Response("{}", { status: 403 })), "")
  assert.equal(
    await x.fetchAccountPhone(cred, async () => new Response(JSON.stringify({ user: { name: "hw123" } }), { status: 200 })),
    "",
  )
})

test("usage names an account by the phone its credential carries", async () => {
  const cred = { ...(await makeCred()), user_phone: "189****8051" }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async () => new Response(JSON.stringify({ metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 500, package_credit_remain: 500 },
    ] }), { status: 200 }),
    ledgerPath: path.join(ledgerDir, "unused.json"),
  })
  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  assert.equal(usage.user, "189****8051")
  assert.equal(usage.windows.length > 0, true, "the phone must not replace the windows")
})

test("a refresh stores the phone as the account's name and the URN as its uid", async () => {
  const saved = []
  const client = { auth: { set: async ({ body }) => { saved.push(body) } } }
  const cred = {
    ...(await makeCred()),
    user_phone: "189****8051",
    refresh_token: credWithProfile({ principal_urn: "iam::d:user:hw1" }).refresh_token,
  }
  const account = await x.persistCredential(client, { accountId: "iam::d:user:hw1" }, cred)
  assert.equal(saved.length, 1)
  // What the card shows, and what tells two accounts apart.
  assert.equal(saved[0].accountId, "189****8051")
  assert.equal(saved[0].uid, "iam::d:user:hw1")
  assert.equal(account.accountId, "189****8051")
})

test("accountSessionIds is stable per account and differs between accounts", async () => {
  const a = await x.accountSessionIds({ session_id: "s1", access_key_id: "AK1" })
  assert.deepEqual(await x.accountSessionIds({ session_id: "s1", access_key_id: "AK2" }), a)
  assert.notDeepEqual(await x.accountSessionIds({ session_id: "s2", access_key_id: "AK1" }), a)
  assert.match(a.sessionId, /^[0-9a-f]{32}$/)
  assert.match(a.chatId, /^[0-9a-f]{32}$/)
})

test("createConcurrencyGate caps permits, admits in order, and honours abort", async () => {
  const gate = x.createConcurrencyGate(2)
  const r1 = await gate.acquire()
  const r2 = await gate.acquire()
  let third = false
  const p3 = gate.acquire().then((r) => { third = true; return r })
  const ctl = new AbortController()
  const p4 = gate.acquire(ctl.signal)
  await new Promise((r) => setTimeout(r, 5))
  assert.equal(third, false)
  assert.equal(gate.waiting, 2)
  ctl.abort()
  await assert.rejects(p4, { name: "AbortError" })
  r1()
  r1() // a second release is a no-op
  const r3 = await p3
  assert.equal(gate.active, 2)
  r2()
  r3()
  assert.equal(gate.active, 0)
})

test("credentialOf round-trips a credential stored in the access field", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const cred = x.credentialFromTokenResponse(
    { credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R" },
    "verifier",
    keyPair,
  )
  const auth = { type: "oauth", access: JSON.stringify(cred), refresh: "R" }
  const back = x.credentialOf(auth)
  assert.equal(back.access_key_id, "AK")
  assert.equal(back.refresh_token, "R")
  assert.equal(back.code_verifier, "verifier")
  assert.deepEqual(back.dpop_private_key_jwk, keyPair.privateKeyJwk)
  assert.equal(x.credentialOf({ type: "api", key: "k" }), null)
})

test("expiresFromCredential parses the STS expiration or falls back to +1d", () => {
  assert.equal(x.expiresFromCredential({ expires_at: "2030-01-01T00:00:00Z" }), Date.parse("2030-01-01T00:00:00Z"))
  const soon = x.expiresFromCredential({})
  assert.ok(soon > Date.now() + 86_000_000 && soon <= Date.now() + 86_400_000)
})

test("buildOAuthLoginUrl matches the real IDE parameters", () => {
  const url = new URL(x.buildOAuthLoginUrl(12345, { codeChallenge: "CH" }, "TICKET"))
  assert.equal(url.origin + url.pathname, "https://codearts.huaweicloud.com/portal/authorize")
  const q = url.searchParams
  assert.equal(q.get("client_id"), "codearts-agent")
  assert.equal(q.get("uri_scheme"), "codearts-agent")
  assert.equal(q.get("port"), "12345")
  assert.equal(q.get("code_challenge"), "CH")
  assert.equal(q.get("code_challenge_method"), "SHA-256")
  assert.equal(q.get("ticket_id"), "TICKET")
  assert.equal(q.get("plugin-name"), "snap_AIIDE")
  // The real plugin never sends auth_callback_url (portal derives it from port).
  assert.equal(q.has("auth_callback_url"), false)
})

test("usageFromStatistics maps credit metrics to windows with real numbers", () => {
  const usage = x.usageFromStatistics({
    package: { package_name_cn: "企业版" },
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 250, package_credit_used: 750 },
      { name: "usageBasicPackageCredit", package_credit_amount: 1000, package_credit_remain: 250, package_credit_used: 750 },
      { name: "usageOnDemandPackageCredit", package_credit_amount: 20000, package_credit_remain: 20000 },
    ],
  })
  assert.equal(usage.plan, "企业版")
  assert.equal(usage.signIn, "kept")
  // The package total is listed first, then the buckets, all with display
  // numbers; only the total may pause the account, the buckets are aside.
  assert.deepEqual(usage.windows, [
    { name: "总积分", used: 75, display: "750 / 1000", amount: 750, limit: 1000, unit: "credits" },
    { name: "基础积分包", used: 75, display: "750 / 1000", amount: 750, limit: 1000, unit: "credits", aside: true },
    { name: "按需积分包", used: 0, display: "0 / 2.0万", amount: 0, limit: 20000, unit: "credits", aside: true },
  ])
})

test("usageFromStatistics adds the free daily pool as an aside window for the free models", () => {
  const usage = x.usageFromStatistics(
    { metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 1000 }] },
    { result: { daily_token_limit: 10_000_000, daily_tokens_used: 2_500_000 } },
  )
  const free = usage.windows.find((w) => w.name === "免费额度")
  assert.equal(free.used, 25)
  assert.equal(free.display, "250.0万 / 1000.0万")
  assert.equal(free.unit, "tokens")
  assert.equal(free.aside, true)
  assert.ok(free.models.includes("glm-5.3-flash"))
  assert.equal(x.benefitWindow({ result: {} }), undefined)
})

test("usageFromStatistics: the monthly buckets reset at end_date, expiring credits are said", () => {
  const usage = x.usageFromStatistics({
    end_date: "2026-11-01",
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 6500, package_credit_remain: 6000 },
      { name: "usageBasicPackageCredit", package_credit_amount: 500, package_credit_remain: 0 },
      { name: "usageBonusPackageCredit", package_credit_amount: 6000, package_credit_remain: 6000, package_credit_expiring_amount: 1000 },
    ],
  })
  const [total, basic, bonus] = usage.windows
  const reset = new Date(Date.parse("2026-10-31T16:00:00Z")).toISOString()
  assert.equal(total.resetsAt, reset)
  assert.equal(basic.resetsAt, reset)
  assert.equal(bonus.resetsAt, undefined, "given credits don't come back at the month's end")
  assert.equal(bonus.display, "0 / 6000 · 1000 即将过期")
})

test("usageFromStatistics: the soonest check-in credits to lapse show on the bonus bucket", () => {
  const now = Date.now()
  const day = 86_400_000
  const grants = [
    { at: new Date(now - 40 * day).toISOString(), credit: 1000, expiresAt: new Date(now - 10 * day).toISOString() }, // gone
    { at: new Date(now - 25 * day).toISOString(), credit: 1000, expiresAt: new Date(now + 5 * day).toISOString() },
    { at: new Date(now - 2 * day).toISOString(), credit: 1000, expiresAt: new Date(now + 28 * day).toISOString() },
  ]
  const usage = x.usageFromStatistics({
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 7000, package_credit_remain: 6500 },
      { name: "usageBonusPackageCredit", package_credit_amount: 2000, package_credit_remain: 1500 },
    ],
  }, undefined, { grants })
  const bonus = usage.windows.find((w) => w.name === "赠送积分包")
  assert.equal(bonus.runsOutAt, grants[1].expiresAt)
  assert.equal(bonus.runsOut, 1000)
  // The total loses them too.
  assert.equal(usage.windows.find((w) => w.name === "总积分").runsOutAt, grants[1].expiresAt)
  assert.equal(x.soonestLapse(x.grantBatches([grants[0]])), undefined)
})

// Shaped as the console's own answers (personal-usage → 获取明细).
const day = 86_400_000
const iso = (ms) => new Date(ms).toISOString()
function creditFetcher(now = Date.now()) {
  const planEnd = now + 31 * day
  // Noon in Beijing, so the check-in a minute later is the same Beijing day
  // whatever the wall clock (#322).
  const signUp = Math.floor((now + 30 * day + 8 * 3600_000) / day) * day + 4 * 3600_000
  const checkin = signUp + 52_000
  const ok = (data) => new Response(JSON.stringify({ code: 0, message: "ok", data }), { status: 200 })
  const fetcher = async (url, init) => {
    const u = String(url)
    const body = init?.body ? JSON.parse(new TextDecoder().decode(init.body)) : undefined
    if (u === x.PACKAGE_CREDIT_PAGE_URL) {
      const list = body.packageTypes.includes("basic")
        ? [{ packageType: "basic", creditAmount: 500.0, creditUsed: 0.0, validityPeriod: "31", expiredTime: iso(planEnd).replace("Z", "+00:00"), status: 1 }]
        : []
      return new Response(JSON.stringify({ list, total: list.length, pageNum: 1, pageSize: 100 }), { status: 200 })
    }
    if (u === x.OPS_CREDIT_OVERVIEW_URL) {
      return ok({ items: [
        { campaignId: 4, campaignTitle: "新用户注册送 4000 积分", totalClaimed: 4000, totalConsumed: 0, totalExpired: 0 },
        { campaignId: 1, campaignTitle: "每日签到领1000积分", totalClaimed: 1000, totalConsumed: 0, totalExpired: 0 },
        { campaignId: 9, campaignTitle: "用完了", totalClaimed: 1000, totalConsumed: 1000, totalExpired: 0 },
      ] })
    }
    if (u === x.OPS_CREDIT_CAMPAIGN_URL(4)) {
      return ok({ campaignId: 4, benefits: [{ status: "CONFIRMED", claimedAmount: 4000, consumedAmount: 0, expiredAmount: 0, claimedAt: iso(signUp - 30 * day), expireAt: iso(signUp) }] })
    }
    if (u === x.OPS_CREDIT_CAMPAIGN_URL(1)) {
      return ok({ campaignId: 1, expirePolicy: { strategy: "DURATION", duration: 30, durationUnit: "DAYS" }, benefits: [{ status: "CONFIRMED", claimedAmount: 1000, consumedAmount: 0, expiredAmount: 0, claimedAt: iso(checkin - 30 * day), expireAt: iso(checkin) }] })
    }
    throw new Error(`unexpected ${u}`)
  }
  return { fetcher, planEnd, signUp, checkin }
}

test("the credit fixture's check-in is its sign-up's Beijing day at any hour (#322)", () => {
  const bj = (ms) => new Date(ms + 8 * 3600_000).toISOString().slice(0, 10)
  const midnight = Date.parse("2026-10-24T16:00:00Z") // 00:00 in Beijing
  for (const now of [midnight - 30_000, midnight - 1, midnight, midnight + 12 * 3600_000]) {
    const { signUp, checkin, planEnd } = creditFetcher(now)
    assert.equal(bj(checkin), bj(signUp))
    assert.ok(signUp > now && checkin < planEnd)
  }
})

test("fetchCreditBatches reads every batch with its own expiry, signed", async () => {
  const { fetcher, planEnd, signUp, checkin } = creditFetcher()
  const seen = []
  const batches = await x.fetchCreditBatches({ access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, async (url, init) => {
    seen.push([init.method, String(url), new Headers(init.headers).get("authorization")])
    return fetcher(url, init)
  })
  assert.deepEqual(batches, [
    { metric: "usageBasicPackageCredit", amount: 500, left: 500, expiresAt: planEnd },
    { metric: "usageBonusPackageCredit", amount: 4000, left: 4000, expiresAt: signUp },
    { metric: "usageBonusPackageCredit", amount: 1000, left: 1000, expiresAt: checkin },
  ])
  // A spent campaign is not asked for its grants.
  assert.equal(seen.some((s) => s[1] === x.OPS_CREDIT_CAMPAIGN_URL(9)), false)
  assert.ok(seen.every((s) => String(s[2]).startsWith("SDK-HMAC-SHA256 ")))
  // Nothing reached: no batches, so the caller falls back.
  assert.equal(await x.fetchCreditBatches({ access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, async () => new Response("", { status: 401 })), undefined)
})

test("usage with the vendor's batches: the plan's end is the reset, the grants' the lapse", async () => {
  const cred = await makeCred()
  const { fetcher: credit, planEnd, signUp } = creditFetcher()
  const fetcher = async (url, init) => {
    if (String(url).endsWith("/snap-manager/v1/statistics/plugin")) {
      return new Response(JSON.stringify({
        end_date: "2099-01-01",
        metrics: [
          { name: "usageTotalPackageCredit", package_credit_amount: 5500, package_credit_remain: 5500 },
          { name: "usageBasicPackageCredit", package_credit_amount: 500, package_credit_remain: 500 },
          { name: "usageBonusPackageCredit", package_credit_amount: 5000, package_credit_remain: 5000 },
        ],
      }), { status: 200 })
    }
    if (String(url) === x.BENEFIT_BALANCE_URL) return new Response("", { status: 404 })
    return credit(url, init)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ledgerPath: path.join(ledgerDir, "unused.json") })
  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  const [total, basic, bonus] = usage.windows
  // To the second, from the plan's batch, not end_date's day.
  assert.equal(total.resetsAt, iso(planEnd))
  assert.equal(basic.resetsAt, iso(planEnd))
  assert.equal(basic.runsOutAt, undefined, "the plan's credits come back, they don't lapse")
  // The sign-up grant and that day's check-in lapse together.
  assert.equal(bonus.runsOutAt, iso(signUp))
  assert.equal(bonus.runsOut, 5000)
  assert.equal(total.runsOutAt, iso(signUp))
  assert.equal(total.runsOut, 5000)
})

test("the free pool window comes back at the next Beijing midnight", () => {
  const w = x.benefitWindow({ result: { daily_token_limit: 100, daily_tokens_used: 10 } })
  const at = Date.parse(w.resetsAt)
  assert.ok(at > Date.now() && at - Date.now() <= 86_400_000)
  assert.equal(new Date(at + 8 * 3600 * 1000).toISOString().slice(11, 19), "00:00:00")
})

test("usageFromStatistics reports no credit plan when every bucket is empty", () => {
  const usage = x.usageFromStatistics({
    metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 0, package_credit_remain: 0 }],
  })
  assert.deepEqual(usage.windows, [])
  assert.equal(usage.error, "该账号无积分额度")
})

test("usageFromStatistics surfaces a business error code", () => {
  const usage = x.usageFromStatistics({ code: 500, message: "boom" })
  assert.equal(usage.error, "boom")
})

test("toBytes normalizes strings and views", async () => {
  assert.deepEqual(await x.toBytes("hi"), buf("hi"))
  assert.deepEqual(await x.toBytes(buf("hi")), buf("hi"))
  assert.equal((await x.toBytes(null)).length, 0)
})

test("isBenefitModel honours the static fallback and the host's prefix", () => {
  assert.equal(x.isBenefitModel("glm-5.3-flash"), true)
  assert.equal(x.isBenefitModel("codearts/glm-5.3-flash"), true)
  assert.equal(x.isBenefitModel("deepseek-v4-flash-0731"), true)
  // The bare id is a different, paid model.
  assert.equal(x.isBenefitModel("deepseek-v4-flash"), false)
  assert.equal(x.isBenefitModel("GLM-5.2"), false)
})

test("isBenefitModel / isRegularModel read the account's own lists once it has them", () => {
  const state = { benefit: new Set(["glm-5.3-flash"]), regular: new Set(["GLM-5.2"]), noBenefit: new Set() }
  assert.equal(x.isBenefitModel("deepseek-v4.1-flash", state), false, "the fallback no longer stands")
  assert.equal(x.isBenefitModel("glm-5.3-flash", state), true)
  state.noBenefit.add("glm-5.3-flash")
  assert.equal(x.isBenefitModel("glm-5.3-flash", state), false)
  assert.equal(x.isRegularModel("GLM-5.2", state), true)
  assert.equal(x.isRegularModel("glm-5.3-flash", state), false)
  assert.equal(x.isRegularModel("anything", { regular: null }), true, "not known yet")
})

// ---- remote model list -----------------------------------------------------

const gatewayBody = JSON.stringify({
  result: {
    models: [
      { model_id: "glm-5.3-flash", model_name: "glm-5.3-flash" },
      { model_id: "deepseek-v4-flash-0731", model_name: "deepseek-v4-flash-0731" },
      { model_id: "Qwen3-VL-235B", model_name: "Qwen3-VL-235B" },
    ],
  },
})
const builtinBody = JSON.stringify({ builtinModels: [{ model_id: "GLM-5.2", model_name: "GLM-5.2" }] })

function modelsFetcher(seen, { claim = "0000", agents, detail } = {}) {
  return async (url, init) => {
    const u = String(url)
    seen.push({ url: u, method: init?.method, auth: new Headers(init?.headers).get("authorization") })
    if (u === x.BENEFIT_CLAIM_URL) return new Response(JSON.stringify({ error_code: claim, error_msg: claim === "0000" ? "ok" : "权益不存在" }), { status: 200 })
    if (u === x.AGENT_LIST_URL) return new Response(JSON.stringify(agents ?? { total: 0, agents: [] }), { status: 200 })
    if (u.startsWith(`${x.AGENT_DETAIL_URL("")}`)) return new Response(JSON.stringify(detail ?? { gpts: { models: [] } }), { status: 200 })
    const body = u.includes("opengw") ? gatewayBody : builtinBody
    return new Response(body, { status: 200 })
  }
}

test("fetchRemoteModels merges both endpoints, filters VL, and keeps the published ids", async () => {
  const seen = []
  const models = await x.fetchRemoteModels(
    { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" },
    modelsFetcher(seen),
  )
  const ids = models.map((m) => m.id)
  assert.deepEqual(ids, ["glm-5.3-flash", "deepseek-v4-flash-0731", "GLM-5.2"])
  // Everything gateway/config publishes is a free model.
  assert.deepEqual(models.map((m) => m.benefit === true), [true, true, false])
  assert.ok(seen.every((s) => String(s.auth).startsWith("SDK-HMAC-SHA256")))
})

test("signedGet returns undefined on a non-2xx response", async () => {
  const fetcher = async () => new Response("nope", { status: 401 })
  const text = await x.signedGet(x.SNAP_MODEL_BUILTIN_URL, { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }, fetcher)
  assert.equal(text, undefined)
})

// ---- plugin hooks ----------------------------------------------------------

function makeAuth(cred) {
  return { type: "oauth", access: JSON.stringify(cred), refresh: cred.refresh_token, expires: x.expiresFromCredential(cred) }
}

async function makeCred() {
  const keyPair = await x.generateDpopKeyPair()
  return x.credentialFromTokenResponse(
    { credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R" },
    "verifier",
    keyPair,
  )
}

test("plugin exposes config, provider.models, and an oauth auth method", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  assert.equal(typeof plugin.config, "function")
  assert.equal(plugin.provider.id, "codearts")
  assert.equal(plugin.auth.provider, "codearts")
  assert.equal(plugin.auth.methods.length, 1)
  assert.equal(plugin.auth.methods[0].type, "oauth")
  assert.equal(typeof plugin.auth.checkin, "function")
  assert.equal(plugin.auth.maxConcurrency, x.ACCOUNT_MAX_INFLIGHT)

  const config = {}
  await plugin.config(config)
  const p = config.provider.codearts
  assert.equal(p.npm, "@ai-sdk/openai-compatible")
  assert.equal(p.api, x.CHAT_API_BASE)
  assert.ok(p.models["GLM-5.2"])
  assert.equal(p.models["GLM-5"], undefined)
  // The output budget is declared; nothing is called free before the
  // account's own list says so.
  assert.equal(p.models["GLM-5.2"].limit.output, x.MAX_OUTPUT_TOKENS)
  assert.equal(p.models["GLM-5.2"].free, undefined)
  assert.equal(p.models["glm-5.3-flash"].free, undefined)
})

const CHAT_URL = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions"
const sse = (...events) => events.map((e) => `data: ${typeof e === "string" ? e : JSON.stringify(e)}\n\n`).join("")
const sseResponse = (text) => new Response(text, { status: 200, headers: { "content-type": "text/event-stream" } })
const chatInit = (body) => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
const okStream = sse(
  { id: "c1", model: "GLM-5.2", choices: [{ index: 0, delta: { role: "assistant" } }] },
  { id: "c1", choices: [{ index: 0, delta: { content: "你好" } }] },
  { id: "c1", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] },
  "[DONE]",
)
const fastRetry = { retryDelays: [1], retryBudgetMs: 2_000 }

test("loader signs each chat request with SDK-HMAC-SHA256 and sends it metered", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push({ url: String(url), init })
    return sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  assert.equal(loaded.baseURL, x.CHAT_API_BASE)

  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "codearts/GLM-5.2", messages: [] }))

  const headers = new Headers(seen[0].init.headers)
  assert.match(headers.get("authorization"), /^SDK-HMAC-SHA256 Access=AK,/)
  assert.equal(headers.get("lang"), "en")
  assert.match(headers.get("chat-id"), /^[0-9a-f]{32}$/)
  assert.match(headers.get("session-id"), /^[0-9a-f]{32}$/)
  assert.equal(headers.has("maas_type"), false)
  // The body signed and sent: bare model, explicit thinking, streamed.
  assert.deepEqual(JSON.parse(new TextDecoder().decode(seen[0].init.body)), {
    model: "GLM-5.2", messages: [], thinking: { type: "enabled" }, stream: true,
  })
  // The caller asked for JSON, so the stream comes back folded.
  assert.equal(res.headers.get("content-type"), "application/json")
  const json = await res.json()
  assert.equal(json.object, "chat.completion")
  assert.deepEqual(json.choices[0].message, { role: "assistant", content: "你好" })
  assert.equal(json.choices[0].finish_reason, "stop")
})

test("one account keeps one Chat-Id/Session-Id across requests and loaders", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push(new Headers(init.headers))
    return sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const a = await plugin.auth.loader(async () => makeAuth(cred))
  const b = await plugin.auth.loader(async () => makeAuth(cred))
  await (await a.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  await (await a.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  await (await b.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  assert.equal(new Set(seen.map((h) => h.get("chat-id"))).size, 1)
  assert.equal(new Set(seen.map((h) => h.get("session-id"))).size, 1)
})

test("a streaming caller gets the upstream stream intact, peeked bytes included", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => sseResponse(okStream) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), okStream)
})

test("a folded answer keeps reasoning, tool calls and usage apart", async () => {
  const cred = await makeCred()
  const stream = sse(
    { id: "c2", model: "deepseek-v4.1-flash", choices: [{ delta: { reasoning_content: "想一想" } }] },
    { id: "c2", choices: [{ delta: { tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "read", arguments: '{"pa' } }] } }] },
    { id: "c2", choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: 'th":"a"}' } }] } }] },
    { id: "c2", choices: [{ delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 5, completion_tokens: 7, total_tokens: 12 } },
    "[DONE]",
  )
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => sseResponse(stream) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const json = await (await loaded.fetch(CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [] }))).json()
  const msg = json.choices[0].message
  assert.equal(msg.content, "")
  assert.equal(msg.reasoning_content, "想一想")
  assert.deepEqual(msg.tool_calls, [{ id: "call_1", type: "function", function: { name: "read", arguments: '{"path":"a"}' } }])
  assert.equal(json.choices[0].finish_reason, "tool_calls")
  assert.deepEqual(json.usage, { prompt_tokens: 5, completion_tokens: 7, total_tokens: 12 })
})

// ---- tool names over CodeArts' 64 characters (#432) -------------------------

// The reporter's tool, word for word: ZCode's android emulator MCP, 71 long.
const ANDROID_TOOL = "mcp__plugin_android-emulator_android-emulator__android_discover_project"
const toolOf = (name) => ({ type: "function", function: { name, description: "d", parameters: { type: "object", properties: {} } } })
const sentOf = (init) => JSON.parse(new TextDecoder().decode(init.body))

test("a tool name over 64 goes cut to 64: its first 55, _ and 8 hex of its SHA-256", async () => {
  assert.equal(ANDROID_TOOL.length, 71)
  const body = {
    model: "GLM-5.2",
    tools: [toolOf(ANDROID_TOOL), toolOf("read")],
    tool_choice: { type: "function", function: { name: ANDROID_TOOL } },
    messages: [
      { role: "user", content: "find the project" },
      { role: "assistant", content: "", tool_calls: [{ id: "c1", type: "function", function: { name: ANDROID_TOOL, arguments: "{}" } }] },
      { role: "tool", tool_call_id: "c1", name: ANDROID_TOOL, content: "ok" },
    ],
  }
  const { body: sent, names } = x.prepareChatBody(structuredClone(body))
  const hex = (await x.sha256Hex(new TextEncoder().encode(ANDROID_TOOL))).slice(0, 8)
  const cut = `${ANDROID_TOOL.slice(0, 55)}_${hex}`
  assert.equal(cut.length, 64)
  assert.equal(sent.tools[0].function.name, cut)
  assert.equal(sent.tools[1].function.name, "read")
  assert.equal(sent.tool_choice.function.name, cut)
  assert.equal(sent.messages[1].tool_calls[0].function.name, cut)
  assert.equal(sent.messages[2].name, cut)
  assert.deepEqual([...names], [[cut, ANDROID_TOOL]])
  // The same on the next request, so the history keeps matching its tool.
  assert.equal(x.prepareChatBody(structuredClone(body)).body.tools[0].function.name, cut)
  // Names that fit leave the body as it was, and nothing to put back.
  const fits = { model: "GLM-5.2", tools: [toolOf("read"), toolOf("x".repeat(64))], messages: [] }
  const plain = x.prepareChatBody(structuredClone(fits))
  assert.equal(plain.names, null)
  assert.deepEqual(plain.body.tools, fits.tools)
})

test("cut names never collide: alike for 55, or the cut of one being another tool's own name", () => {
  const a = `${ANDROID_TOOL}_a_long_tail`
  const b = `${ANDROID_TOOL}_b_long_tail`
  const taken = x.cutToolName(a, 0) // a tool the agent itself calls by a's cut
  const { body, names } = x.prepareChatBody({ model: "GLM-5.2", tools: [toolOf(a), toolOf(b), toolOf(taken)], messages: [] })
  const sent = body.tools.map((t) => t.function.name)
  assert.equal(new Set(sent).size, 3)
  for (const n of sent) assert.ok(n.length <= x.TOOL_NAME_LIMIT, n)
  // the agent's own short name goes as it is; a's is cut again, with a salt
  assert.equal(sent[2], taken)
  assert.notEqual(sent[0], taken)
  assert.equal(sent[0].slice(0, 55), a.slice(0, 55))
  assert.equal(names.get(sent[0]), a)
  assert.equal(names.get(sent[1]), b)
  assert.equal(names.has(taken), false)
})

test("a streamed tool call names the agent's tool again, whole or in pieces; other events pass byte for byte", async () => {
  const cred = await makeCred()
  const other = `${ANDROID_TOOL}_screenshot`
  const cutA = x.cutToolName(ANDROID_TOOL, 0)
  const cutB = x.cutToolName(other, 0)
  const sentBodies = []
  const head = sse({ id: "c3", model: "GLM-5.2", choices: [{ index: 0, delta: { role: "assistant", content: "" } }] })
  const stream = head + sse(
    // whole in one delta
    { id: "c3", choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "call_a", type: "function", function: { name: cutA, arguments: "" } }] } }] },
    { id: "c3", choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"p":1}' } }] } }] },
    // in three pieces, one across the 55th character
    { id: "c3", choices: [{ index: 0, delta: { tool_calls: [{ index: 1, id: "call_b", type: "function", function: { name: cutB.slice(0, 30) } }] } }] },
    { id: "c3", choices: [{ index: 0, delta: { tool_calls: [{ index: 1, function: { name: cutB.slice(30, 60) } }] } }] },
    { id: "c3", choices: [{ index: 0, delta: { tool_calls: [{ index: 1, function: { name: cutB.slice(60), arguments: "{}" } }] } }] },
    // a tool whose name fits
    { id: "c3", choices: [{ index: 0, delta: { tool_calls: [{ index: 2, id: "call_c", type: "function", function: { name: "read", arguments: "{}" } }] } }] },
    { id: "c3", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] },
    "[DONE]",
  )
  const fetcher = async (url, init) => {
    sentBodies.push(sentOf(init))
    return sseResponse(stream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({
    model: "GLM-5.2", stream: true, tools: [toolOf(ANDROID_TOOL), toolOf(other), toolOf("read")], messages: [{ role: "user", content: "hi" }],
  }))
  // CodeArts was sent names it takes
  assert.deepEqual(sentBodies[0].tools.map((t) => t.function.name), [cutA, cutB, "read"])
  for (const t of sentBodies[0].tools) assert.ok(t.function.name.length <= 64)
  const text = await res.text()
  // what the agent's stream folds to: its own names
  const folded = x.completionFromChunks(x.parseSseEvents(text)).choices[0].message.tool_calls
  assert.deepEqual(folded.map((c) => c.function.name), [ANDROID_TOOL, other, "read"])
  assert.deepEqual(folded.map((c) => c.function.arguments), ['{"p":1}', "{}", "{}"])
  // no cut name reaches the agent; events naming no cut tool are unchanged
  assert.equal(text.includes(cutA) || text.includes(cutB), false)
  assert.ok(text.startsWith(head))
  assert.ok(text.endsWith('data: {"id":"c3","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n\n'))
})

test("a gateway that repeats a cut name in each delta still gives the agent's name", async () => {
  const cut = x.cutToolName(ANDROID_TOOL, 0)
  const names = new Map([[cut, ANDROID_TOOL]])
  const text = sse(
    { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "c", function: { name: cut, arguments: "" } }] } }] },
    { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { name: cut, arguments: "{}" } }] } }] },
    "[DONE]",
  )
  const out = await new Response(x.restoreToolNamesInStream(new Response(text).body, names)).text()
  const evs = x.parseSseEvents(out)
  assert.deepEqual(evs.map((e) => e.choices[0].delta.tool_calls[0].function.name), [ANDROID_TOOL, ANDROID_TOOL])
})

test("a folded tool call names the agent's tool again", async () => {
  const cred = await makeCred()
  const cut = x.cutToolName(ANDROID_TOOL, 0)
  const stream = sse(
    { id: "c4", model: "GLM-5.2", choices: [{ delta: { tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: cut, arguments: "{}" } }] } }] },
    { id: "c4", choices: [{ delta: {}, finish_reason: "tool_calls" }] },
    "[DONE]",
  )
  let sent
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async (url, init) => { sent = sentOf(init); return sseResponse(stream) } })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const json = await (await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", tools: [toolOf(ANDROID_TOOL)], messages: [] }))).json()
  assert.equal(sent.tools[0].function.name, cut)
  assert.deepEqual(json.choices[0].message.tool_calls, [{ id: "call_1", type: "function", function: { name: ANDROID_TOOL, arguments: "{}" } }])
})

const capBody = JSON.stringify({ error_code: "TM.00001041", error_msg: "并发会话数已达上限(3个)，请关闭部分会话后重试。" })

test("TM.00001041 as a 400 is retried, re-signed, until a session frees", async () => {
  const cred = await makeCred()
  let calls = 0
  const fetcher = async () => {
    calls += 1
    return calls <= 2 ? new Response(capBody, { status: 400 }) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ...fastRetry })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(calls, 3)
  assert.equal(res.status, 200)
  assert.equal(await res.text(), okStream)
})

test("TM.00001041 inside a 200 stream is retried too", async () => {
  const cred = await makeCred()
  let calls = 0
  const fetcher = async () => {
    calls += 1
    return calls === 1 ? sseResponse(sse({ choices: [{ delta: { role: "assistant" } }] }, JSON.parse(capBody))) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ...fastRetry })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const json = await (await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).json()
  assert.equal(calls, 2)
  assert.equal(json.choices[0].message.content, "你好")
})

test("a session cap that outlasts the budget comes back as a 429 magpie fails over on", async () => {
  const cred = await makeCred()
  let calls = 0
  const fetcher = async () => {
    calls += 1
    return new Response(capBody, { status: 400 })
  }
  // A virtual clock that moves only when the plugin sleeps: however slow the
  // signing is, the budget is spent by the waits alone.
  let t = 0
  const now = () => t
  const sleep = async (ms) => { t += ms }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, retryDelays: [10], retryBudgetMs: 13, now, sleep })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 429)
  // A wait is 10 ms ±20%: one (8–12) always fits the 13 ms budget, two (≥ 16)
  // never do. So exactly one retry, whatever the jitter.
  assert.equal(calls, 2)
  const body = await res.json()
  assert.equal(body.error.code, "TM.00001041")
  assert.match(body.error.message, /并发会话数已达上限/)
})

test("an abort while waiting for a session stops the retries", async () => {
  const cred = await makeCred()
  const fetcher = async () => new Response(capBody, { status: 400 })
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, retryDelays: [10_000], retryBudgetMs: 60_000 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const ctl = new AbortController()
  setTimeout(() => ctl.abort(), 20)
  await assert.rejects(
    loaded.fetch(CHAT_URL, { ...chatInit({ model: "GLM-5.2", messages: [] }), signal: ctl.signal }),
    { name: "AbortError" },
  )
})

test("an error inside a 200 becomes a status magpie acts on, with the vendor's words", async () => {
  const cred = await makeCred()
  const quota = sse({ error_code: "InferHub.4291.200", error_msg: "insufficient quota" })
  const unknown = sse({ error_code: "InferHub.002002009.404", error_msg: "model is not registered" })
  let next = quota
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => sseResponse(next) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))

  const a = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(a.status, 429)
  assert.match((await a.json()).error.message, /insufficient quota \(InferHub\.4291\.200\)/)

  // A model the account doesn't have: retrying can't help, so a 400.
  next = unknown
  const b = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(b.status, 400)
  const body = await b.json()
  assert.equal(body.error.code, "InferHub.002002009.404")
  assert.equal(body.error.message.startsWith("CodeArts"), false, "magpie adds the provider name itself")
})

test("the free model's TPM limit inside a 200 is a 429 magpie fails over on, not an empty reply", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => sseResponse(`${tpmEvent}\n\n`) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  for (const stream of [true, false]) {
    const res = await loaded.fetch(CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [{ role: "user", content: "你好" }], stream }))
    assert.equal(res.status, 429)
    const body = await res.json()
    assert.equal(body.error.code, "InferHub.ModelArts.81111.429")
    assert.match(body.error.message, /TPM limit/)
  }
})

// star21321321124 (Discord, 10-28): an agent sent DeepSeek V4.1 Flash an
// image, and the "502: you can retry" had it ask again and again.
const notMultimodal = { error_code: "InferHub.001001020.406", error_msg: "The request model is not multimodal" }

test("an image a text-only model turns away is a 400, not a 502 to retry, on every path", async () => {
  const cred = await makeCred()
  let answer = () => sseResponse(sse(notMultimodal))
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => answer() })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const ask = (stream) => loaded.fetch(CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [{ role: "user", content: "看图" }], stream }))
  const cases = [
    ["inside a 200", () => sseResponse(sse(notMultimodal))],
    ["as a 502", () => new Response(JSON.stringify(notMultimodal), { status: 502, headers: { "content-type": "application/json" } })],
    ["as a 406", () => new Response(JSON.stringify(notMultimodal), { status: 406, headers: { "content-type": "application/json" } })],
  ]
  for (const [how, make] of cases) {
    answer = make
    for (const stream of [true, false]) {
      const res = await ask(stream)
      assert.equal(res.status, 400, `${how}, stream ${stream}`)
      const body = await res.json()
      assert.equal(body.error.code, "InferHub.001001020.406", how)
      assert.match(body.error.message, /not multimodal/, how)
    }
  }
})

test("every model says it takes text alone, so an agent sends it no image", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  const config = {}
  await plugin.config(config)
  for (const [id, m] of Object.entries(config.provider.codearts.models)) {
    assert.deepEqual(m.modalities, { input: ["text"], output: ["text"] }, id)
    assert.equal(m.attachment, false, id)
  }

  const cred = await makeCred()
  const listed = await CodeArtsAuthPlugin({ client: {} }, { fetch: modelsFetcher([], { agents: agentList, detail: agentDetail }) })
  // the host's entry for a config model, and one the user said sees
  const provider = {
    models: {
      "GLM-5.2": { capabilities: { input: { text: true, image: false } } },
      "glm-5.3-flash": { capabilities: { input: { text: true, image: true } } },
    },
  }
  const models = await listed.provider.models(provider, { auth: makeAuth(cred) })
  // glm-5.3 only the agent lists, deepseek-v4-flash-0731 has no entry of its own
  for (const id of ["GLM-5.2", "glm-5.3", "deepseek-v4-flash-0731"]) {
    assert.equal(models[id].capabilities.input.image, false, id)
    assert.equal(models[id].capabilities.input.text, true, id)
    assert.equal(models[id].capabilities.attachment, false, id)
  }
  // what the user's own config says stands
  assert.equal(models["glm-5.3-flash"].capabilities.input.image, true)
})

test("embeddedErrorStatus sorts the gateway's codes into what magpie acts on", () => {
  assert.equal(x.embeddedErrorStatus("InferHub.4291.200"), 429)
  assert.equal(x.embeddedErrorStatus("81114.429"), 429)
  assert.equal(x.embeddedErrorStatus("InferHub.4004.200"), 400)
  assert.equal(x.embeddedErrorStatus("ModelArts.81009.404"), 400)
  assert.equal(x.embeddedErrorStatus("InferHub.001001005.400"), 400)
  assert.equal(x.embeddedErrorStatus("InferHub.5000.500"), 502)
  assert.equal(x.embeddedErrorStatus("InferHub.001001020.406"), 400)
})

test("every chat carries the agent's session headers: one session, a fresh trace", async () => {
  const cred = await makeCred()
  const seen = []
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async (url, init) => {
      seen.push(new Headers(init.headers))
      return sseResponse(okStream)
    },
  })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await (await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  await (await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))).text()
  const [a, b] = seen
  assert.match(a.get("x-ot-session-id"), /^[0-9a-f]{32}$/)
  assert.equal(a.get("x-ot-session-id"), b.get("x-ot-session-id"))
  assert.equal(a.get("user-session-id"), a.get("x-ot-session-id"))
  assert.notEqual(a.get("x-ot-trace-id"), b.get("x-ot-trace-id"))
  assert.notEqual(a.get("x-snap-traceid"), b.get("x-snap-traceid"))
})

const signedCred = { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }

test("only the account's live free list decides the benefit header", async () => {
  const state = {}
  const fetcher = async (url) => String(url).includes("opengw")
    ? new Response(JSON.stringify({ result: { models: [{ model_id: "glm-5.3-flash" }] } }), { status: 200 })
    : new Response(JSON.stringify({ builtinModels: [{ model_id: "deepseek-v4.1-flash", model_name: "DeepSeek-V4.1-Flash" }] }), { status: 200 })
  // The claim answers with the gateway's own body here, so it is no 0000: read
  // the published list as it is (no state), then check the account's lists.
  const models = await x.fetchRemoteModels(signedCred, fetcher)
  assert.deepEqual(models.map((m) => [m.id, m.benefit === true]), [["glm-5.3-flash", true], ["deepseek-v4.1-flash", false]])
  const claimed = async (url, init) => (String(url) === x.BENEFIT_CLAIM_URL ? new Response('{"error_code":"0000"}', { status: 200 }) : fetcher(url, init))
  await x.fetchRemoteModels(signedCred, claimed, state)
  // In the fallback, but this account lists it as a plain builtin model.
  assert.equal(x.isBenefitModel("deepseek-v4.1-flash", state), false)
  assert.equal(x.isBenefitModel("glm-5.3-flash", state), true)
  assert.deepEqual([...state.regular], ["deepseek-v4.1-flash"])
  // A failed read keeps what was known.
  await x.fetchRemoteModels(signedCred, async () => new Response("", { status: 500 }), state)
  assert.equal(x.isBenefitModel("glm-5.3-flash", state), true)
})

test("one account's model lists never decide another's", async () => {
  // Two accounts in one plugin: A has the free model, B lists it only as builtin.
  const credA = await makeCred()
  const credB = { ...(await makeCred()), access_key_id: "AKB", session_id: "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0" }
  const listFor = (ak) => async (url, init) => {
    const u = String(url)
    if (u === x.BENEFIT_CLAIM_URL) return new Response(JSON.stringify({ error_code: ak === "AK" ? "0000" : "4004" }), { status: 200 })
    if (u.includes("opengw")) return new Response(JSON.stringify({ result: { models: [{ model_id: "deepseek-v4.1-flash" }] } }), { status: 200 })
    if (u === x.CHAT_API_BASE + "/chat/completions") {
      return new Headers(init.headers).get("maas_type") && ak !== "AK"
        ? sseResponse(sse({ error_code: "InferHub.4004.200", error_msg: "benefit not found" }))
        : sseResponse(okStream)
    }
    return new Response(JSON.stringify({ builtinModels: ak === "AK" ? [] : [{ model_id: "deepseek-v4.1-flash" }] }), { status: 200 })
  }
  const sent = []
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async (url, init) => {
      const ak = /Access=([^,]+),/.exec(new Headers(init.headers).get("authorization") ?? "")?.[1]
      if (String(url) === CHAT_URL) sent.push([ak, new Headers(init.headers).get("maas_type")])
      return listFor(ak)(url, init)
    },
  })
  const a = await plugin.provider.models({ models: {} }, { auth: makeAuth(credA) })
  const b = await plugin.provider.models({ models: {} }, { auth: makeAuth(credB) })
  assert.equal(a["deepseek-v4.1-flash"].free, true)
  assert.equal(b["deepseek-v4.1-flash"].free, false)
  const loadedA = await plugin.auth.loader(async () => makeAuth(credA))
  const loadedB = await plugin.auth.loader(async () => makeAuth(credB))
  await (await loadedB.fetch(CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [] }))).text()
  await (await loadedA.fetch(CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [] }))).text()
  // B bills it as its builtin model; A still sends it as its free one.
  assert.deepEqual(sent, [["AKB", null], ["AK", "benefit"]])
})

test("benefit not found sends the request again as the plain builtin model, and remembers it", async () => {
  const cred = await makeCred()
  const sent = []
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async (url, init) => {
      const u = String(url)
      // The free list and the builtin list both name the model, and today's
      // benefit is claimed.
      if (u === x.BENEFIT_CLAIM_URL) return new Response('{"error_code":"0000"}', { status: 200 })
      if (u.includes("opengw")) return new Response(JSON.stringify({ result: { models: [{ model_id: "deepseek-v4.1-flash" }] } }), { status: 200 })
      if (u !== CHAT_URL) return new Response(JSON.stringify({ builtinModels: [{ model_id: "deepseek-v4.1-flash" }] }), { status: 200 })
      const benefit = new Headers(init.headers).get("maas_type")
      sent.push(benefit)
      return benefit
        ? sseResponse(sse({ error_code: "InferHub.4004.200", error_msg: "benefit not found" }))
        : sseResponse(okStream)
    },
  })
  await plugin.provider.models({ models: {} }, { auth: makeAuth(cred) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const a = await loaded.fetch(CHAT_URL, chatInit({ model: "codearts/deepseek-v4.1-flash", messages: [] }))
  assert.equal(a.status, 200)
  assert.equal((await a.json()).choices[0].message.content, "你好")
  const b = await loaded.fetch(CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [] }))
  await b.text()
  assert.deepEqual(sent, ["benefit", null, null])
})

test("a 429 that queues the request is waited out the agent's way, then sent again", async () => {
  const cred = await makeCred()
  const calls = []
  let polls = 0
  const fetcher = async (url, init) => {
    calls.push([init.method, String(url), new Headers(init.headers).get("authorization")])
    if (String(url) === x.TRACE_QUEUE_URL("T1")) {
      polls += 1
      return new Response(JSON.stringify(polls < 2 ? { status: "queued", queue_length: 2, retry_after: 0 } : { status: "promoted" }), { status: 200 })
    }
    return calls.filter((c) => c[1] === CHAT_URL).length === 1
      ? new Response("{}", { status: 429, headers: { "queue-status": "queued", "trace-id": "T1", "retry-after": "0" } })
      : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), okStream)
  assert.deepEqual(calls.map((c) => [c[0], c[1]]), [
    ["POST", CHAT_URL],
    ["GET", x.TRACE_QUEUE_URL("T1")],
    ["GET", x.TRACE_QUEUE_URL("T1")],
    ["POST", CHAT_URL],
  ])
  assert.ok(calls.every((c) => String(c[2]).startsWith("SDK-HMAC-SHA256 ")))
})

// With another candidate after it (magpie's X-Magpie-Fallback), a queued
// request isn't waited out: it leaves the queue, and a 503 with the queue's
// retry-after goes back at once for magpie to ask the next (axuhere on X: a
// free model held in a queue while another provider could answer). The
// header never goes on to CodeArts.
test("told another candidate follows, a queued request leaves the queue and is answered at once", async () => {
  const cred = await makeCred()
  const calls = []
  let deleted
  const sawDelete = new Promise((r) => { deleted = r })
  const fetcher = async (url, init) => {
    calls.push([init.method, String(url), new Headers(init.headers).get("x-magpie-fallback")])
    if (init.method === "DELETE") deleted()
    if (String(url) === x.TRACE_QUEUE_URL("T9")) return new Response(JSON.stringify({ status: "queued", retry_after: 30 }), { status: 200 })
    return new Response("{}", { status: 429, headers: { "queue-status": "queued", "trace-id": "T9", "retry-after": "20" } })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const init = chatInit({ model: "GLM-5.2", messages: [] })
  const res = await loaded.fetch(CHAT_URL, { ...init, headers: { ...Object.fromEntries(new Headers(init.headers)), "x-magpie-fallback": "1" } })
  assert.equal(res.status, 503)
  assert.equal(res.headers.get("retry-after"), "20")
  assert.match((await res.json()).error.message, /CodeArts queued the request; try again in 20s/)
  await sawDelete
  assert.deepEqual(calls.map((c) => [c[0], c[1]]), [["POST", CHAT_URL], ["DELETE", x.TRACE_QUEUE_URL("T9")]])
  assert.ok(calls.every((c) => c[2] === null))
})

test("giving up in the queue takes the request out of it", async () => {
  const cred = await makeCred()
  const calls = []
  // The DELETE is sent in the background (it signs first): wait for the DELETE
  // itself, never for a fixed time.
  let deleted
  let sawDelete = new Promise((r) => { deleted = r })
  // The caller gives up once the request is queued, never before it is sent.
  const ctl = new AbortController()
  const fetcher = async (url, init) => {
    calls.push([init.method, String(url)])
    if (init.method === "DELETE") deleted()
    if (String(url) === x.TRACE_QUEUE_URL("T2")) return new Response(JSON.stringify({ status: "queued", retry_after: 30 }), { status: 200 })
    setTimeout(() => ctl.abort(), 0)
    return new Response("{}", { status: 429, headers: { "queue-status": "queued", "trace-id": "T2", "retry-after": "30" } })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await assert.rejects(loaded.fetch(CHAT_URL, { ...chatInit({ model: "GLM-5.2", messages: [] }), signal: ctl.signal }), { name: "AbortError" })
  await sawDelete
  assert.deepEqual(calls.at(-1), ["DELETE", x.TRACE_QUEUE_URL("T2")])

  // A queue the wait budget can't cover is left at once, and answered 429.
  calls.length = 0
  sawDelete = new Promise((r) => { deleted = r })
  const quick = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueBudgetMs: 1_000 })
  const res = await (await quick.auth.loader(async () => makeAuth(cred))).fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 429)
  await sawDelete
  assert.deepEqual(calls.map((c) => c[0]), ["POST", "DELETE"])
})

test("a queue poll that hangs can't outlast the wait: the request leaves the queue, a 429", async () => {
  const cred = await makeCred()
  const calls = []
  let deleted
  const sawDelete = new Promise((r) => { deleted = r })
  const fetcher = async (url, init) => {
    calls.push(init.method)
    if (init.method === "DELETE") {
      deleted()
      return new Response("{}", { status: 200 })
    }
    if (String(url) === x.TRACE_QUEUE_URL("T3")) {
      // The poll never answers: only its signal ends it (without one, never),
      // at once when it ended while the request was signed, as fetch does.
      // Its open socket is what keeps a real process alive meanwhile: an
      // AbortSignal.timeout alone doesn't, in node or bun.
      return new Promise((_, reject) => {
        if (init.signal?.aborted) return reject(init.signal.reason)
        const socket = setInterval(() => {}, 1_000)
        init.signal?.addEventListener("abort", () => {
          clearInterval(socket)
          reject(init.signal.reason)
        })
      })
    }
    return new Response("{}", { status: 429, headers: { "queue-status": "queued", "trace-id": "T3", "retry-after": "0" } })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueBudgetMs: 200 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 429)
  await sawDelete
  assert.equal(calls[0], "POST")
  assert.equal(calls.at(-1), "DELETE")
  assert.ok(calls.slice(1, -1).length >= 1 && calls.slice(1, -1).every((m) => m === "GET"))
})

test("three failed polls take the request out of the queue before the 429", async () => {
  const cred = await makeCred()
  const calls = []
  let deleted
  const sawDelete = new Promise((r) => { deleted = r })
  const fetcher = async (url, init) => {
    calls.push(init.method)
    if (init.method === "DELETE") {
      deleted()
      return new Response("{}", { status: 200 })
    }
    if (String(url) === x.TRACE_QUEUE_URL("T4")) return new Response("busy", { status: 503 })
    return new Response("{}", { status: 429, headers: { "queue-status": "queued", "trace-id": "T4", "retry-after": "0" } })
  }
  // A budget the polls can't run out: it is the failures that end the wait.
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, queueBudgetMs: 60_000 })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 429)
  // The DELETE is sent in the background, after it signs: wait for it, with a
  // bound so a missing one fails here rather than at the runner's timeout.
  await Promise.race([sawDelete, new Promise((r) => setTimeout(r, 2_000))])
  assert.deepEqual(calls, ["POST", "GET", "GET", "GET", "DELETE"])
})

test("a 429 that is no queue passes through for magpie to fail over", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => new Response('{"error_code":"81111.429"}', { status: 429 }) })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 429)
  assert.equal(await res.text(), '{"error_code":"81111.429"}')
})

test("a model that refuses the injected thinking parameter gets the caller's request", async () => {
  const cred = await makeCred()
  const bodies = []
  const fetcher = async (url, init) => {
    bodies.push(JSON.parse(new TextDecoder().decode(init.body)))
    return bodies.length === 1
      ? new Response('{"error_code":"InferHub.001001005.400","error_msg":"unknown field: thinking"}', { status: 400 })
      : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "openpangu-2.0-pro", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.deepEqual(bodies[0].thinking, { type: "enabled" })
  assert.equal("thinking" in bodies[1], false)
})

test("other upstream errors pass through untouched", async () => {
  const cred = await makeCred()
  const body = JSON.stringify({ error_code: "InferHub.001001005.400", error_msg: "RANGE_VALIDATOR" })
  let calls = 0
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async () => {
      calls += 1
      return new Response(body, { status: 400 })
    },
    ...fastRetry,
  })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(res.status, 400)
  assert.equal(await res.text(), body)
  assert.equal(calls, 1)
})

const stsBody = (ak, refresh) => JSON.stringify({
  credentials: { access_key_id: ak, secret_access_key: `SK-${ak}`, security_token: `ST-${ak}`, expiration: "2031-01-01T00:00:00Z" },
  refresh_token: refresh,
})

test("a stale credential is renewed once, the request sent again, and the renewal kept", async () => {
  const cred = await makeCred()
  const sets = []
  const chats = []
  const fetcher = async (url, init) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) return new Response(stsBody("AK2", "R2"), { status: 200 })
    chats.push(new Headers(init.headers).get("authorization"))
    return chats.length === 1
      ? new Response(JSON.stringify({ error_code: "APIG.0602", error_msg: "the security token has expired" }), { status: 400 })
      : sseResponse(okStream)
  }
  const client = { auth: { set: async (o) => { sets.push(o) } } }
  const plugin = await CodeArtsAuthPlugin({ client }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => ({ ...makeAuth(cred), accountId: "alice" }))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.match(chats[0], /Access=AK,/)
  assert.match(chats[1], /Access=AK2,/)
  assert.equal(sets.length, 1)
  const saved = sets[0].body
  assert.equal(saved.accountId, "alice") // the host keeps the record whole: nothing may be lost
  assert.equal(saved.refresh, "R2")
  const next = JSON.parse(saved.access)
  assert.equal(next.access_key_id, "AK2")
  assert.equal(next.session_id, cred.session_id)
})

test("a stale credential takes over a renewal already stored instead of refreshing again", async () => {
  const cred = await makeCred()
  const renewed = { ...cred, access_key_id: "AK9", secret_access_key: "SK9", security_token: "ST9" }
  let reads = 0
  const getAuth = async () => (reads++ === 0 ? makeAuth(cred) : makeAuth(renewed))
  const chats = []
  const fetcher = async (url, init) => {
    assert.notEqual(String(url), x.STS_TOKEN_ENDPOINT, "the stored renewal must be used, not a second refresh")
    chats.push(new Headers(init.headers).get("authorization"))
    return chats.length === 1 ? new Response('{"error_code":"APIG.0301"}', { status: 401 }) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(getAuth)
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.match(chats[1], /Access=AK9,/)
})

test("a spent refresh token marks the sign-in and stops calling the vendor", async () => {
  const cred = await makeCred()
  let chats = 0
  const fetcher = async (url) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) {
      return new Response(JSON.stringify({ error_code: "STS5.1806", error_msg: "refresh token has been used" }), { status: 400 })
    }
    chats += 1
    return new Response('{"error_code":"APIG.0602","error_msg":"the security token has expired"}', { status: 400 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const a = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(a.status, 401)
  assert.equal(a.headers.get("x-magpie-sign-in"), "expired")
  const b = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(b.status, 401)
  assert.equal(chats, 1)
})

test("a 403 is a sign-in the account no longer has, on chats and other requests alike", async () => {
  const cred = await makeCred()
  const denied = '{"error_code":"APIG.0305","error_msg":"access denied"}'
  let calls = 0
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async () => {
      calls += 1
      return new Response(denied, { status: 403 })
    },
  })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const chat = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(chat.status, 403)
  assert.equal(chat.headers.get("x-magpie-sign-in"), "expired")
  assert.equal(await chat.text(), denied)
  const other = await loaded.fetch("https://snap-access.cn-north-4.myhuaweicloud.com/api/v1/models", { method: "GET" })
  assert.equal(other.status, 403)
  assert.equal(other.headers.get("x-magpie-sign-in"), "expired")
  assert.equal(await other.text(), denied)
  assert.equal(calls, 2, "a 403 is not retried")
})

test("isSignedHostUrl takes only https URLs on the two hosts the plugin calls, by name", () => {
  assert.deepEqual([...x.SIGNED_HOSTS].sort(), ["opengw.developer.huaweicloud.com", "snap-access.cn-north-4.myhuaweicloud.com"])
  assert.equal(x.isSignedHostUrl(CHAT_URL), true)
  assert.equal(x.isSignedHostUrl(x.BENEFIT_CLAIM_URL), true)
  assert.equal(x.isSignedHostUrl("https://SNAP-ACCESS.cn-north-4.myhuaweicloud.com/api/v2/chat/completions"), true, "a hostname has no case")
  // Other Huawei Cloud hosts don't get the account's signature either.
  for (const other of ["https://codearts.huaweicloud.com/x", "https://iam.myhuaweicloud.cn/v3", "https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens", "https://snap-access.cn-south-1.myhuaweicloud.com/api"]) {
    assert.equal(x.isSignedHostUrl(other), false, other)
  }
  assert.equal(x.isSignedHostUrl("http://snap-access.cn-north-4.myhuaweicloud.com/api"), false, "not over plain http")
  assert.equal(x.isSignedHostUrl("https://snap-access.cn-north-4.myhuaweicloud.com:8443/api"), false, "not on another port")
  assert.equal(x.isSignedHostUrl("https://snap-access.cn-north-4.myhuaweicloud.com.example.com/"), false)
  assert.equal(x.isSignedHostUrl("https://example.com/?u=snap-access.cn-north-4.myhuaweicloud.com"), false)
  assert.equal(x.isSignedHostUrl("not a url"), false)
})

test("signFor signs only for the two hosts, whichever route asks", async () => {
  const signed = await x.signFor(signedCred, "GET", x.SNAP_MODEL_BUILTIN_URL, new Uint8Array())
  assert.match(signed.get("authorization"), /^SDK-HMAC-SHA256 Access=AK,/)
  assert.equal(signed.get("host"), null, "fetch sets the host")
  await assert.rejects(x.signFor(signedCred, "GET", "https://example.com/x", new Uint8Array()), /refusing to sign a request to example\.com/)
  // A route that signs for another host gets nothing out, and never calls.
  let called = false
  const never = async () => { called = true; return new Response("{}") }
  assert.equal(await x.signedGet("https://example.com/x", signedCred, never), undefined)
  assert.equal((await x.snapRequest("POST", "https://example.com/x", signedCred, never, {})).ok, false)
  assert.equal(called, false)
})

test("a 3xx is never followed: whatever the route, the credentials stay on the two hosts", async () => {
  // Where a redirect would send them, and a stand-in for CodeArts that sends
  // every request there.
  const reached = []
  const elsewhere = http.createServer((req, res) => {
    reached.push(req.headers)
    res.end("{}")
  })
  await new Promise((r) => elsewhere.listen(0, "127.0.0.1", r))
  const gateway = http.createServer((req, res) => {
    res.writeHead(307, { Location: `http://127.0.0.1:${elsewhere.address().port}/stolen` }).end()
  })
  await new Promise((r) => gateway.listen(0, "127.0.0.1", r))
  // The plugin's calls go to the stand-in through the real fetch, with the
  // init the plugin gave them.
  const calls = []
  const fetcher = (url, init) => {
    calls.push([String(url), init?.redirect])
    const u = new URL(url)
    return fetch(`http://127.0.0.1:${gateway.address().port}${u.pathname}${u.search}`, init)
  }
  try {
    const cred = await makeCred()
    const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ledgerPath: path.join(ledgerDir, "redirect.json") })
    const loaded = await plugin.auth.loader(async () => makeAuth(cred))
    // A chat, even one whose caller asks to follow, and a request that isn't one.
    await assert.rejects(loaded.fetch(CHAT_URL, { ...chatInit({ model: "GLM-5.2", messages: [] }), redirect: "follow" }))
    await assert.rejects(loaded.fetch(x.SNAP_MODEL_BUILTIN_URL, { method: "GET" }))
    // The model list, usage, the check-in, the benefit claim, a queue poll, a token request.
    await plugin.provider.models({ models: {} }, { auth: makeAuth(cred) })
    await plugin.auth.usage(async () => makeAuth(cred))
    await plugin.auth.checkin(async () => makeAuth(cred))
    assert.equal((await x.claimBenefit(cred, fetcher)).ok, false)
    await assert.rejects(x.traceQueueCall("GET", cred, "T", { sessionId: "s", fetcher }))
    await assert.rejects(x.refreshCredential(cred, fetcher))
    assert.equal(reached.length, 0, "nothing reached the host a redirect pointed at")
    for (const url of [CHAT_URL, x.SNAP_MODEL_BUILTIN_URL, x.OPENGW_GATEWAY_CONFIG_URL, x.SNAP_STATISTICS_URL, x.OPS_DELIVERY_URL, x.BENEFIT_CLAIM_URL, x.TRACE_QUEUE_URL("T"), x.STS_TOKEN_ENDPOINT]) {
      assert.ok(calls.some(([u]) => u === url), `${url} was called`)
    }
    assert.deepEqual(calls.filter(([, redirect]) => redirect !== "error"), [], "every call goes with redirect: error")
  } finally {
    for (const s of [gateway, elsewhere]) {
      s.closeAllConnections?.()
      await new Promise((r) => s.close(r))
    }
  }
})

test("a request to any other host is refused before the credentials leave", async () => {
  const cred = await makeCred()
  let calls = 0
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => { calls += 1; return sseResponse(okStream) } })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  for (const url of ["https://api.example.com/v1/chat/completions", "http://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions"]) {
    const res = await loaded.fetch(url, chatInit({ model: "GLM-5.2", messages: [] }))
    assert.equal(res.status, 400)
    assert.match((await res.json()).error.message, /refusing to sign a request to/)
  }
  assert.equal(calls, 0)
})

const staleBody = '{"error_code":"APIG.0602","error_msg":"the security token has expired"}'
const spentBody = JSON.stringify({ error_code: "STS5.1806", error_msg: "refresh token has been used" })

test("a renewal that fails only for now keeps the sign-in, and the next request renews again", async () => {
  const cred = await makeCred()
  let sts = 0
  const fetcher = async (url, init) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) {
      sts += 1
      return sts === 1 ? new Response("upstream unavailable", { status: 503 }) : new Response(stsBody("AK2", "R2"), { status: 200 })
    }
    return /Access=AK,/.test(new Headers(init.headers).get("authorization")) ? new Response(staleBody, { status: 401 }) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const a = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))
  assert.equal(a.status, 503)
  assert.equal(a.headers.get("x-magpie-sign-in"), "kept")
  const b = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(b.status, 200)
  await b.text()
  assert.equal(sts, 2)

  // A request that isn't a chat: the same.
  const other = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async (url) => (String(url) === x.STS_TOKEN_ENDPOINT ? new Response("", { status: 503 }) : new Response(staleBody, { status: 401 })),
  })
  const res = await (await other.auth.loader(async () => makeAuth(cred))).fetch("https://snap-access.cn-north-4.myhuaweicloud.com/v1/model/builtin", { method: "GET" })
  assert.equal(res.status, 503)
  assert.equal(res.headers.get("x-magpie-sign-in"), "kept")
})

test("two loaders of one account and magpie's own renewal spend its refresh token once", async () => {
  const cred = await makeCred()
  let sts = 0
  let release
  const held = new Promise((r) => { release = r })
  const fetcher = async (url, init) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) {
      sts += 1
      await held
      // STS takes a refresh token once.
      return sts === 1 ? new Response(stsBody("AK2", "R2"), { status: 200 }) : new Response(spentBody, { status: 400 })
    }
    return /Access=AK,/.test(new Headers(init.headers).get("authorization")) ? new Response(staleBody, { status: 401 }) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  // Nothing is stored meanwhile: every read gives the old record.
  const getAuth = async () => makeAuth(cred)
  const loaders = await Promise.all([plugin.auth.loader(getAuth), plugin.auth.loader(getAuth)])
  const answers = Promise.all(loaders.map((l) => l.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [] }))))
  const refreshed = plugin.auth.refresh(makeAuth(cred))
  while (sts < 1) await new Promise((r) => setTimeout(r, 5))
  await new Promise((r) => setTimeout(r, 20))
  release()
  for (const res of await answers) {
    assert.equal(res.status, 200)
    assert.equal(res.headers.get("x-magpie-sign-in"), null)
  }
  assert.equal(JSON.parse((await refreshed).access).access_key_id, "AK2")
  // One that comes later with the spent token gets what the renewal gave.
  assert.equal(JSON.parse((await plugin.auth.refresh(makeAuth(cred))).access).access_key_id, "AK2")
  assert.equal(sts, 1)
})

test("a refresh token spent a moment ago by someone else: their renewal is taken, the sign-in kept", async () => {
  const cred = await makeCred()
  const theirs = { ...cred, access_key_id: "AK3", secret_access_key: "SK3", security_token: "ST3", refresh_token: "R3" }
  let stored = cred
  const fetcher = async (url, init) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) {
      stored = theirs // another process won the race and saved its renewal
      return new Response(spentBody, { status: 400 })
    }
    return /Access=AK,/.test(new Headers(init.headers).get("authorization")) ? new Response(staleBody, { status: 401 }) : sseResponse(okStream)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(stored))
  const res = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), okStream)
  const next = await loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true }))
  assert.equal(next.status, 200, "the account isn't marked")
  await next.text()
})

test("a reshaped body goes without the caller's Content-Length", async () => {
  const cred = await makeCred()
  const seen = []
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {
    fetch: async (url, init) => {
      seen.push({ length: new Headers(init.headers).get("content-length"), bytes: init.body.length })
      return sseResponse(okStream)
    },
  })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const body = JSON.stringify({ model: "codearts/GLM-5.2", messages: [] })
  const headers = { "content-type": "application/json", "content-length": String(body.length) }
  await (await loaded.fetch(CHAT_URL, { method: "POST", headers, body })).text()
  assert.equal(seen[0].length, null)
  assert.notEqual(seen[0].bytes, body.length, "the body was reshaped")
})

test("requestToken reads a spent refresh token as a sign-in gone for good", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const fetcher = async () => new Response(JSON.stringify({ error_code: "STS5.1806", error_msg: "refresh token has been used" }), { status: 400 })
  await assert.rejects(x.requestToken({ grant_type: "refresh_token" }, keyPair, fetcher), (e) => e.signIn === "expired")
  const flaky = async () => new Response(JSON.stringify({ error_code: "STS.0001", error_msg: "dpop proof rejected" }), { status: 400 })
  await assert.rejects(x.requestToken({ grant_type: "refresh_token" }, keyPair, flaky), (e) => e.signIn === undefined)
})

test("in-flight chats per account are capped, and a permit comes back when the body ends", async () => {
  const cred = await makeCred()
  // Each upstream stream is kept under the request that opened it (its body
  // names it): requests reach the fetcher in no set order, as each one signs
  // with WebCrypto first, so `first[i]` is paired with stream `i` by name.
  const streams = new Map()
  const fetcher = async (url, init) => {
    const n = JSON.parse(new TextDecoder().decode(init.body)).messages[0].content
    let ctl
    const body = new ReadableStream({ start(c) { ctl = c } })
    ctl.enqueue(new TextEncoder().encode(sse({ choices: [{ delta: { content: "x" } }] })))
    streams.set(n, ctl)
    return sseResponse(body)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  const send = (n) => loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [{ role: "user", content: n }], stream: true }))
  const first = await Promise.all(["0", "1", "2"].map(send))
  const fourth = send("3")
  // Three streams are open, so the fourth holds; give it a chance to get past
  // the gate, which it must not.
  await new Promise((r) => setTimeout(r, 30))
  assert.deepEqual([...streams.keys()].sort(), ["0", "1", "2"], "the 4th waits for a permit")
  streams.get("0").close()
  await first[0].text()
  const res = await fourth
  assert.ok(streams.has("3"))
  for (const n of ["1", "2", "3"]) streams.get(n).close()
  await Promise.all([...first.slice(1), res].map((r) => r.text()))
})

test("maxInflight can lower the gate but never lift it past the vendor's 3 sessions", async () => {
  const cred = await makeCred()
  const open = (opts, cap) => async () => {
    const streams = []
    const plugin = await CodeArtsAuthPlugin({ client: {} }, {
      ...opts,
      fetch: async () => {
        let ctl
        const body = new ReadableStream({ start(c) { ctl = c } })
        ctl.enqueue(new TextEncoder().encode(sse({ choices: [{ delta: { content: "x" } }] })))
        streams.push(ctl)
        return sseResponse(body)
      },
    })
    const loaded = await plugin.auth.loader(async () => makeAuth(cred))
    // Each answer is read as it comes; a permit comes back when its body ends.
    const read = Array.from({ length: 5 }, () =>
      loaded.fetch(CHAT_URL, chatInit({ model: "GLM-5.2", messages: [], stream: true })).then((r) => r.text()))
    // Wait for the cap to fill, however slow the signing, then give one more
    // request the chance to slip past it.
    while (streams.length < cap) await new Promise((r) => setTimeout(r, 5))
    await new Promise((r) => setTimeout(r, 30))
    const inFlight = streams.length
    let finished = false
    const all = Promise.all(read).then(() => { finished = true })
    while (!finished) {
      for (const c of streams.splice(0)) c.close()
      await new Promise((r) => setTimeout(r, 10))
    }
    await all
    return { inFlight, maxConcurrency: plugin.auth.maxConcurrency }
  }
  assert.deepEqual(await open({ maxInflight: 10 }, 3)(), { inFlight: 3, maxConcurrency: 3 })
  assert.deepEqual(await open({ maxInflight: 1 }, 1)(), { inFlight: 1, maxConcurrency: 1 })
})

test("loader adds a signed maas_type header for benefit models", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    seen.push(init)
    return new Response("ok", { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await loaded.fetch("https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "glm-5.3-flash" }),
  })
  const headers = new Headers(seen[0].headers)
  assert.equal(headers.get("maas_type"), "benefit")
  assert.match(headers.get("authorization"), /SignedHeaders=[^,]*,/)
  assert.ok(headers.get("authorization").split("SignedHeaders=")[1].split(",")[0].includes("maas_type"))
})

test("loader returns nothing when not signed in", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  assert.deepEqual(await plugin.auth.loader(async () => ({ type: "api", key: "k" })), {})
})

test("auth.refresh exchanges the refresh token for fresh credentials", async () => {
  const cred = await makeCred()
  const fetcher = async (url, init) => {
    assert.equal(String(url), x.STS_TOKEN_ENDPOINT)
    assert.equal(init.method, "POST")
    assert.ok(new Headers(init.headers).get("dpop"))
    return new Response(JSON.stringify({
      credentials: { access_key_id: "AK2", secret_access_key: "SK2", security_token: "ST2", expiration: "2031-01-01T00:00:00Z" },
      refresh_token: "R2",
    }), { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const next = await plugin.auth.refresh(makeAuth(cred))
  const parsed = JSON.parse(next.access)
  assert.equal(parsed.access_key_id, "AK2")
  assert.equal(next.refresh, "R2")
  assert.equal(next.expires, Date.parse("2031-01-01T00:00:00Z"))
})

/** Check a token request's DPoP proof: it verifies against the stored key, for POST to the STS endpoint. */
async function assertDpopFor(proof, publicKeyJwk) {
  const [h, p, s] = proof.split(".")
  const header = JSON.parse(Buffer.from(h, "base64url").toString())
  const payload = JSON.parse(Buffer.from(p, "base64url").toString())
  assert.equal(header.typ, "dpop+jwt")
  assert.deepEqual(header.jwk, publicKeyJwk, "signed with the credential's own DPoP key")
  assert.equal(payload.htm, "POST")
  assert.equal(payload.htu, x.STS_TOKEN_ENDPOINT)
  const key = await crypto.subtle.importKey("jwk", header.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
  assert.ok(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(s, "base64url"), buf(`${h}.${p}`)))
}

test("token requests carry a DPoP proof for POST to the STS endpoint, signed with the credential's key", async () => {
  const cred = await makeCred()
  const { publicKeyJwk } = x.keyPairFromStoredJwk(cred.dpop_private_key_jwk)
  const proofs = []
  const bodies = []
  const fetcher = async (url, init) => {
    proofs.push(new Headers(init.headers).get("dpop"))
    bodies.push(new URLSearchParams(init.body))
    return new Response(JSON.stringify({
      credentials: { access_key_id: "AK2", secret_access_key: "SK2", security_token: "ST2", expiration: "2031-01-01T00:00:00Z" },
      refresh_token: "R2",
    }), { status: 200 })
  }
  // A refresh, and an authorization-code exchange.
  await x.refreshCredential(cred, fetcher)
  await x.exchangeAuthorizationCode("CODE", "verifier", 12345, x.keyPairFromStoredJwk(cred.dpop_private_key_jwk), fetcher)
  for (const proof of proofs) await assertDpopFor(proof, publicKeyJwk)
  assert.equal(bodies[0].get("grant_type"), "refresh_token")
  assert.equal(bodies[0].get("refresh_token"), "R")
  assert.equal(bodies[0].get("code_verifier"), "verifier")
  assert.equal(bodies[1].get("grant_type"), "authorization_code")
  assert.equal(bodies[1].get("code"), "CODE")
  assert.equal(bodies[1].get("redirect_uri"), "http://127.0.0.1:12345/oauth/callback")
})

test("a credential with nothing to renew it with is a sign-in gone for good", async () => {
  const cred = { ...(await makeCred()), refresh_token: undefined }
  await assert.rejects(x.refreshCredential(cred, async () => { throw new Error("no network expected") }), (e) => e.signIn === "expired")
})

test("provider.models returns the account's live list", async () => {
  const cred = await makeCred()
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: modelsFetcher([]) })
  const provider = { models: { "GLM-5.2": { name: "GLM-5.2", limit: { context: 0, output: 0 } } } }
  const models = await plugin.provider.models(provider, { auth: makeAuth(cred) })
  assert.deepEqual(Object.keys(models).sort(), ["GLM-5.2", "deepseek-v4-flash-0731", "glm-5.3-flash"])
  assert.equal(models["GLM-5.2"].limit.context, 202752)
  assert.equal(models["GLM-5.2"].limit.output, x.MAX_OUTPUT_TOKENS)
  assert.equal(models["GLM-5.2"].free, false)
  assert.equal(models["deepseek-v4-flash-0731"].free, true)
})

const agentList = { total: 2, agents: [{ agent_id: "a-other", original_id: "DT-Agent" }, { agent_id: "a-code-1", original_id: "CodeAgent" }] }
const agentDetail = {
  gpts: {
    models: [
      { model_name: "GLM-5.2", model_parameters: { model_id: "GLM-5.2", thinking_type: "enabled", context_window: 202752, max_tokens: 131072 }, credit: [{ ratio: 1, ratio_display: "1.50" }] },
      { model_name: "GLM-5.3", model_parameters: { model_id: "glm-5.3", context_window: 1048576 }, credit: { ratio_display: 0.8 } },
      { model_name: "My Own", model_type: "custom", model_parameters: { model_id: "my-own" } },
    ],
  },
}

test("provider.models: free models once claimed, rates and parameters from the CodeAgent", async () => {
  const cred = await makeCred()
  const seen = []
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: modelsFetcher(seen, { agents: agentList, detail: agentDetail }) })
  const provider = { models: {} }
  const models = await plugin.provider.models(provider, { auth: makeAuth(cred) })
  assert.deepEqual(Object.keys(models).sort(), ["GLM-5.2", "deepseek-v4-flash-0731", "glm-5.3", "glm-5.3-flash"])
  // Today's benefit claimed: the gateway's models are free and carry no rate.
  assert.equal(models["glm-5.3-flash"].free, true)
  assert.equal(models["glm-5.3-flash"].rate, undefined)
  // The rest bill credits at the agent's own rate.
  assert.equal(models["GLM-5.2"].free, false)
  assert.equal(models["GLM-5.2"].rate, 1.5)
  assert.equal(models["GLM-5.2"].capabilities.reasoning, true)
  assert.equal(models["GLM-5.2"].limit.output, x.MAX_OUTPUT_TOKENS)
  // Only the agent lists it: one more model; a user's own is left out.
  assert.equal(models["glm-5.3"].rate, 0.8)
  assert.equal(models["glm-5.3"].limit.context, 1048576)
  assert.equal(models["my-own"], undefined)
  // The claim went out signed, and the detail named the CodeAgent's own id.
  const claim = seen.find((s) => s.url === x.BENEFIT_CLAIM_URL)
  assert.equal(claim.method, "POST")
  assert.match(claim.auth, /^SDK-HMAC-SHA256 /)
  assert.ok(seen.some((s) => s.url === x.AGENT_DETAIL_URL("a-code-1")))
  // Listed again the same day: no second claim, no second agent list.
  await plugin.provider.models(provider, { auth: makeAuth(cred) })
  assert.equal(seen.filter((s) => s.url === x.BENEFIT_CLAIM_URL).length, 1)
  assert.equal(seen.filter((s) => s.url === x.AGENT_LIST_URL).length, 1)
})

test("the model list comes from the main agent: original_id build, then CodeAgent, then the IDE's id", async () => {
  const cred = { access_key_id: "AK", secret_access_key: "SK", security_token: "ST" }
  const detailOf = (models) => new Response(JSON.stringify({ gpts: { models } }), { status: 200 })
  const glm = [{ model_name: "GLM-5.2", model_parameters: { model_id: "GLM-5.2", context_window: 1048576 }, credit: [{ ratio: 0.05, ratio_display: 0.7 }] }]
  const run = async (agents, detail) => {
    const asked = []
    const state = {}
    const models = await x.fetchAgentModels(cred, async (url) => {
      const u = String(url)
      if (u === x.AGENT_LIST_URL) return agents ? new Response(JSON.stringify({ total: agents.length, agents }), { status: 200 }) : new Response("", { status: 500 })
      const id = new URL(u).searchParams.get("agent_id")
      asked.push(id)
      return detailOf(detail(id))
    }, state)
    return { models, asked, state }
  }
  // The account's own agents, as the IDE lists them: the main one is "build".
  const agents = [
    { agent_id: "9f0e5cb64a104dcfb4aa90dbedab7dcf", original_id: "team-leader" },
    { agent_id: "a8bcb36232554267a5142361cc25a393", original_id: "build" },
    { agent_id: "c0de", original_id: "CodeAgent" },
  ]
  let r = await run(agents, (id) => (id === "a8bcb36232554267a5142361cc25a393" ? glm : []))
  assert.deepEqual(r.asked, ["a8bcb36232554267a5142361cc25a393"])
  assert.equal(r.models[0].rate, 0.7)
  assert.equal(r.state.agentId, "a8bcb36232554267a5142361cc25a393")
  // An agent with an empty list: the next one is asked.
  r = await run(agents, (id) => (id === "c0de" ? glm : []))
  assert.deepEqual(r.asked, ["a8bcb36232554267a5142361cc25a393", "c0de"])
  // No agent list at all: the IDE's own id for the main agent.
  r = await run(undefined, (id) => (id === "a8bcb36232554267a5142361cc25a393" ? glm : []))
  assert.deepEqual(r.asked, ["a8bcb36232554267a5142361cc25a393"])
  assert.equal(r.models[0].context, 1048576)
})

test("a benefit the account can't claim: no free models, and no benefit header", async () => {
  const cred = await makeCred()
  const seen = []
  const list = modelsFetcher(seen, { claim: "4004" })
  const sent = []
  const fetcher = async (url, init) => {
    if (String(url) === CHAT_URL) {
      sent.push(new Headers(init.headers).get("maas_type"))
      return sseResponse(okStream)
    }
    return list(url, init)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const models = await plugin.provider.models({ models: {} }, { auth: makeAuth(cred) })
  // The gateway's free-only models can't be called without the benefit.
  assert.deepEqual(Object.keys(models), ["GLM-5.2"])
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  await (await loaded.fetch(CHAT_URL, chatInit({ model: "glm-5.3-flash", messages: [] }))).text()
  assert.deepEqual(sent, [null])
})

test("benefit not found on a day not yet claimed claims it, and sends the free model again", async () => {
  const state = {
    benefit: new Set(["deepseek-v4.1-flash"]), regular: new Set(["deepseek-v4.1-flash"]), noBenefit: new Set(),
    claim: { day: "2000-01-01", ok: true, at: 0 }, claiming: null,
  }
  const sent = []
  let claims = 0
  const fetcher = async (url, init) => {
    if (String(url) === x.BENEFIT_CLAIM_URL) {
      claims += 1
      return new Response('{"error_code":"0000"}', { status: 200 })
    }
    const benefit = new Headers(init.headers).get("maas_type")
    sent.push(benefit)
    // Yesterday's benefit is spent: only today's claim brings it back.
    return benefit && !claims ? sseResponse(sse({ error_code: "InferHub.4004.200", error_msg: "benefit not found" })) : sseResponse(okStream)
  }
  const context = { ...(await x.accountSessionIds(signedCred)), gate: x.createConcurrencyGate(3), state, fetcher }
  const res = await x.signedFetch(signedCred, CHAT_URL, chatInit({ model: "deepseek-v4.1-flash", messages: [] }), context)
  assert.equal(res.status, 200)
  assert.equal((await res.json()).choices[0].message.content, "你好")
  assert.deepEqual(sent, ["benefit", "benefit"])
  assert.equal(claims, 1)
  assert.equal(state.claim.day, x.beijingDay())
  assert.equal(state.noBenefit.size, 0)
})

test("a day's claim asks again about the models the last day had no benefit for", async () => {
  const state = { noBenefit: new Set(["deepseek-v4.1-flash"]), claim: { day: "2000-01-01", ok: true, at: 0 } }
  const claimed = async () => new Response('{"error_code":"0000"}', { status: 200 })
  assert.equal(await x.ensureBenefitClaimed(signedCred, claimed, state), true)
  assert.equal(state.noBenefit.size, 0)
  // A refused claim leaves them as they were.
  const refused = { noBenefit: new Set(["deepseek-v4.1-flash"]), claim: null }
  assert.equal(await x.ensureBenefitClaimed(signedCred, async () => new Response('{"error_code":"4004"}', { status: 200 }), refused), false)
  assert.equal(refused.noBenefit.size, 1)
})

test("ensureBenefitClaimed claims once a day and asks again only an hour after a refusal", async () => {
  const cred = await makeCred()
  let claims = 0
  let answer = "4006"
  const fetcher = async () => {
    claims += 1
    return new Response(JSON.stringify({ error_code: answer }), { status: 200 })
  }
  const state = {}
  assert.equal(await x.ensureBenefitClaimed(cred, fetcher, state), false)
  answer = "0000"
  assert.equal(await x.ensureBenefitClaimed(cred, fetcher, state), false) // within the hour
  assert.equal(claims, 1)
  state.claim.at -= 61 * 60 * 1000
  assert.equal(await x.ensureBenefitClaimed(cred, fetcher, state), true)
  assert.equal(await x.ensureBenefitClaimed(cred, fetcher, state), true)
  assert.equal(claims, 2)
  // Unreachable: the last answer stands, nothing is cached over it.
  const down = async () => { throw new Error("offline") }
  assert.equal(await x.ensureBenefitClaimed(cred, down, { claim: { day: "2000-01-01", ok: true, at: 0 } }), true)
})

test("provider.models falls back to the catalog when unsigned", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, {})
  const provider = { models: { "GLM-5.2": {} } }
  assert.deepEqual(await plugin.provider.models(provider, {}), provider.models)
})

test("auth.usage reports the plan's credit window (the free pool is best-effort)", async () => {
  const cred = await makeCred()
  const asked = []
  const fetcher = async (url) => {
    asked.push(String(url))
    if (String(url) === x.BENEFIT_BALANCE_URL) return new Response("nope", { status: 404 })
    // The batch reads fail here: the usage read goes on without them.
    if (String(url) === x.PACKAGE_CREDIT_PAGE_URL || String(url) === x.OPS_CREDIT_OVERVIEW_URL) return new Response("", { status: 500 })
    assert.ok(String(url).endsWith("/snap-manager/v1/statistics/plugin"))
    return new Response(JSON.stringify({
      package: { package_name_cn: "企业版" },
      metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 1000, package_credit_remain: 400 }],
    }), { status: 200 })
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  assert.equal(usage.plan, "企业版")
  assert.deepEqual(usage.windows, [
    { name: "总积分", used: 60, display: "600 / 1000", amount: 600, limit: 1000, unit: "credits" },
  ])
  assert.deepEqual(asked, [x.SNAP_STATISTICS_URL, x.BENEFIT_BALANCE_URL, x.PACKAGE_CREDIT_PAGE_URL, x.PACKAGE_CREDIT_PAGE_URL, x.OPS_CREDIT_OVERVIEW_URL])
  // Read again within ten minutes: the batches aren't.
  await plugin.auth.usage(async () => makeAuth(cred))
  assert.equal(asked.filter((u) => u === x.OPS_CREDIT_OVERVIEW_URL).length, 1)
})

// ---- daily check-in ----------------------------------------------------------

/** A stand-in for the three ops endpoints: `state` is the USER_LOGIN item. */
function opsFetcher(state, { claim, confirm } = {}) {
  const calls = []
  const ok = (data) => new Response(JSON.stringify({ code: 0, message: "ok", data }), { status: 200 })
  const fetcher = async (url, init) => {
    const u = String(url)
    const headers = new Headers(init.headers)
    const body = init.body ? JSON.parse(new TextDecoder().decode(init.body)) : undefined
    calls.push({ url: u, method: init.method, body, headers })
    if (u === x.OPS_DELIVERY_URL) {
      const items = [{ campaignId: 7, type: "INVITE_USER", claimable: false }]
      if (state.item) items.push(state.item)
      return state.listStatus ? new Response('{"error_code":"APIG.0301","error_msg":"verify ak sk signature fail"}', { status: state.listStatus }) : ok({ items })
    }
    if (u === x.OPS_CLAIM_URL) {
      if (claim) return claim(state)
      state.item = { ...state.item, claimable: false, status: "CLAIMED" }
      return ok({ id: 42, benefitAmount: 1000 })
    }
    if (u === x.OPS_CONFIRM_URL) {
      if (confirm) return confirm(state)
      state.item = { ...state.item, status: "CONFIRMED" }
      return ok(null)
    }
    throw new Error(`unexpected ${u}`)
  }
  return { fetcher, calls }
}

const daily = (extra) => ({ campaignId: 1, type: "USER_LOGIN", title: "每日领取", claimable: true, status: "ENTRY", benefitAmount: 1000, ...extra })

test("checkin claims and confirms the daily benefit the way the IDE does", async () => {
  const cred = await makeCred()
  const { fetcher, calls } = opsFetcher({ item: daily() })
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher })
  const r = await plugin.auth.checkin(async () => makeAuth(cred))
  assert.deepEqual(r, { outcome: "claimed", credit: 1000, message: "+1000 积分" })
  assert.deepEqual(calls.map((c) => [c.method, c.url]), [
    ["GET", x.OPS_DELIVERY_URL],
    ["POST", x.OPS_CLAIM_URL],
    ["POST", x.OPS_CONFIRM_URL],
  ])
  assert.deepEqual(calls[1].body, { campaignId: 1, channel: "IDE" })
  assert.deepEqual(calls[2].body, { campaignId: 1 })
  for (const c of calls) {
    const auth = c.headers.get("authorization")
    assert.match(auth, /^SDK-HMAC-SHA256 Access=AK,/)
    // Routing headers go along unsigned: signing them breaks the signature.
    assert.equal(c.headers.get("agent-type"), "PromptCenter")
    assert.equal(auth.split("SignedHeaders=")[1].split(",")[0].includes("agent-type"), false)
  }
  // Asked again the same day: in already, and nothing is claimed twice.
  const again = await plugin.auth.checkin(async () => makeAuth(cred))
  assert.equal(again.outcome, "done")
  assert.equal(calls.filter((c) => c.url === x.OPS_CLAIM_URL).length, 1)
})

test("a claimed check-in is kept, and the usage card says when those credits run out", async () => {
  const cred = await makeCred()
  const ledgerPath = path.join(ledgerDir, "integrated.json")
  const ops = opsFetcher({ item: daily() })
  const fetcher = async (url, init) => {
    if (String(url).endsWith("/snap-manager/v1/statistics/plugin")) {
      return new Response(JSON.stringify({
        metrics: [
          { name: "usageTotalPackageCredit", package_credit_amount: 6500, package_credit_remain: 6500 },
          { name: "usageBonusPackageCredit", package_credit_amount: 1000, package_credit_remain: 1000 },
        ],
      }), { status: 200 })
    }
    if (String(url) === x.BENEFIT_BALANCE_URL) return new Response("", { status: 404 })
    return ops.fetcher(url, init)
  }
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: fetcher, ledgerPath })
  const r = await plugin.auth.checkin(async () => makeAuth(cred))
  assert.equal(r.outcome, "claimed")
  assert.equal("grant" in r, false)
  const kept = JSON.parse(fs.readFileSync(ledgerPath, "utf8"))
  const [grant] = Object.values(kept)[0]
  assert.equal(grant.credit, 1000)
  assert.equal(Date.parse(grant.expiresAt) - Date.parse(grant.at), 30 * 86_400_000)

  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  const bonus = usage.windows.find((w) => w.name === "赠送积分包")
  assert.equal(bonus.runsOutAt, grant.expiresAt)
  assert.equal(bonus.runsOut, 1000)
})

test("grantExpiry takes the vendor's date when the claim gives one", () => {
  const at = Date.parse("2026-10-21T00:00:00Z")
  assert.equal(x.grantExpiry({}, at), at + 30 * 86_400_000)
  assert.equal(x.grantExpiry({ expire_time: "2026-11-15 00:00:00" }, at), Date.parse("2026-11-14T16:00:00Z"))
})

test("checkin skips the confirm when the claim answers no id", async () => {
  const cred = await makeCred()
  const ok = (data) => new Response(JSON.stringify({ code: 0, data }), { status: 200 })
  const { fetcher, calls } = opsFetcher({ item: daily() }, { claim: () => ok({ id: null }) })
  const { grant, ...r } = await x.dailyCheckin(cred, fetcher)
  assert.deepEqual(r, { outcome: "claimed", credit: 1000, message: "+1000 积分" })
  assert.equal(grant.credit, 1000)
  assert.equal(calls.some((c) => c.url === x.OPS_CONFIRM_URL), false)
})

test("checkin confirms the claim it left unconfirmed, and tries again later when the confirm fails", async () => {
  const cred = await makeCred()
  // The first try: the claim goes through, the confirm doesn't; the answer
  // says what to keep for the next check-in.
  const s = { item: daily() }
  const { unconfirmed, ...first } = await x.dailyCheckin(cred, opsFetcher(s, { confirm: () => new Response("", { status: 502 }) }).fetcher)
  assert.deepEqual(first, { outcome: "failed", message: "领取确认失败：HTTP 502" })
  assert.deepEqual(unconfirmed, { campaignId: 1, benefit: { id: 42, benefitAmount: 1000 } })
  assert.equal(s.item.status, "CLAIMED")
  // Later that day, told what it left: it is confirmed now, not taken as done.
  const { fetcher, calls } = opsFetcher(s)
  const { grant, ...again } = await x.dailyCheckin(cred, fetcher, { unconfirmed })
  assert.deepEqual(again, { outcome: "claimed", credit: 1000, message: "+1000 积分" })
  assert.equal(grant.credit, 1000)
  assert.deepEqual(calls.map((c) => [c.method, c.url]), [["GET", x.OPS_DELIVERY_URL], ["POST", x.OPS_CONFIRM_URL]])
  assert.deepEqual(calls[1].body, { campaignId: 1 })
  assert.equal((await x.dailyCheckin(cred, fetcher, { unconfirmed })).outcome, "done")
  // A claimed activity it didn't leave unconfirmed, or another campaign's, is
  // done, and nothing is confirmed: the IDE leaves `id: null` claims so.
  for (const left of [undefined, { campaignId: 9 }]) {
    const notOurs = opsFetcher({ item: daily({ claimable: false, status: "CLAIMED" }) })
    assert.equal((await x.dailyCheckin(cred, notOurs.fetcher, { unconfirmed: left })).outcome, "done")
    assert.deepEqual(notOurs.calls.map((c) => c.url), [x.OPS_DELIVERY_URL])
  }
  // A confirm the vendor turns down while the activity is still only claimed
  // (活动太火爆, a code in a 200, as much as a 503): a failure, tried again later.
  const busy = () => new Response(JSON.stringify({ code: 500, message: "活动太火爆" }), { status: 200 })
  for (const confirm of [busy, () => new Response("", { status: 503 })]) {
    const still = opsFetcher({ item: daily({ claimable: false, status: "CLAIMED" }) }, { confirm })
    const r = await x.dailyCheckin(cred, still.fetcher, { unconfirmed })
    assert.equal(r.outcome, "failed")
    assert.match(r.message, /^领取确认失败：/)
    assert.deepEqual(still.calls.map((c) => c.method), ["GET", "POST", "GET"], "the activity is looked at again")
  }
  // Turned down because it was confirmed meanwhile (the IDE): done.
  const elsewhere = (st) => {
    st.item = { ...st.item, status: "CONFIRMED" }
    return new Response(JSON.stringify({ code: 1002, message: "already confirmed" }), { status: 200 })
  }
  const meanwhile = opsFetcher({ item: daily({ claimable: false, status: "CLAIMED" }) }, { confirm: elsewhere })
  assert.equal((await x.dailyCheckin(cred, meanwhile.fetcher, { unconfirmed })).outcome, "done")
})

test("a failed confirm is still made by the next check-in when the ledger can't be written", async () => {
  const cred = await makeCred()
  // A ledger under a file, not a folder: every write to it fails.
  const blocker = path.join(ledgerDir, "not-a-folder")
  fs.writeFileSync(blocker, "")
  const ledgerPath = path.join(blocker, "ledger.json")
  let confirms = 0
  const ops = opsFetcher({ item: daily() }, {
    confirm: (st) => {
      confirms += 1
      if (confirms === 1) return new Response("", { status: 502 })
      st.item = { ...st.item, status: "CONFIRMED" }
      return new Response(JSON.stringify({ code: 0, data: null }), { status: 200 })
    },
  })
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: ops.fetcher, ledgerPath })
  assert.equal((await plugin.auth.checkin(async () => makeAuth(cred))).outcome, "failed")
  assert.equal(fs.existsSync(ledgerPath), false)
  assert.equal((await plugin.auth.checkin(async () => makeAuth(cred))).outcome, "claimed")
  assert.equal(confirms, 2)
  assert.equal((await plugin.auth.checkin(async () => makeAuth(cred))).outcome, "done")
  assert.equal(confirms, 2)
})

test("a claim answering no id is never confirmed, however many check-ins follow it", async () => {
  const cred = await makeCred()
  const ledgerPath = path.join(ledgerDir, "no-id.json")
  const ops = opsFetcher({ item: daily() }, {
    claim: (st) => {
      st.item = { ...st.item, claimable: false, status: "CLAIMED" } // as the IDE's id-less claim leaves it
      return new Response(JSON.stringify({ code: 0, data: { id: null, benefitAmount: 1000 } }), { status: 200 })
    },
  })
  const outcomes = []
  // A second magpie, a restart, OpenCode: each a plugin of its own.
  for (let i = 0; i < 3; i++) {
    const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: ops.fetcher, ledgerPath })
    outcomes.push((await plugin.auth.checkin(async () => makeAuth(cred))).outcome)
  }
  assert.deepEqual(outcomes, ["claimed", "done", "done"])
  assert.equal(ops.calls.filter((c) => c.url === x.OPS_CONFIRM_URL).length, 0, "no confirm the IDE wouldn't send")
  const [grants] = Object.entries(JSON.parse(fs.readFileSync(ledgerPath, "utf8"))).filter(([k]) => !k.startsWith("_")).map(([, v]) => v)
  assert.equal(grants.length, 1, "one grant, not one per check-in")
})

test("a confirm that failed is made by the next check-in, in another magpie too, and then forgotten", async () => {
  const cred = await makeCred()
  const ledgerPath = path.join(ledgerDir, "unconfirmed.json")
  let confirms = 0
  const ops = opsFetcher({ item: daily() }, {
    confirm: (st) => {
      confirms += 1
      if (confirms === 1) return new Response("", { status: 502 })
      st.item = { ...st.item, status: "CONFIRMED" }
      return new Response(JSON.stringify({ code: 0, data: null }), { status: 200 })
    },
  })
  const checkin = async () => {
    const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: ops.fetcher, ledgerPath })
    return plugin.auth.checkin(async () => makeAuth(cred))
  }
  assert.equal((await checkin()).outcome, "failed")
  const kept = JSON.parse(fs.readFileSync(ledgerPath, "utf8"))._unconfirmed
  assert.deepEqual(Object.values(kept).map((v) => [v.campaignId, v.day]), [[1, x.beijingDay()]])
  assert.deepEqual(await checkin(), { outcome: "claimed", credit: 1000, message: "+1000 积分" })
  assert.equal(confirms, 2)
  assert.deepEqual(JSON.parse(fs.readFileSync(ledgerPath, "utf8"))._unconfirmed, {}, "confirmed, so forgotten")
  assert.equal((await checkin()).outcome, "done")
  assert.equal(confirms, 2)
})

test("checkin tells done, inactive and ineligible apart", async () => {
  const cred = await makeCred()
  for (const status of ["CONFIRMED", "CONSUMED"]) {
    const { fetcher, calls } = opsFetcher({ item: daily({ claimable: false, status }) })
    assert.equal((await x.dailyCheckin(cred, fetcher)).outcome, "done")
    assert.equal(calls.length, 1)
  }
  assert.equal((await x.dailyCheckin(cred, opsFetcher({}).fetcher)).outcome, "inactive")
  const ineligible = await x.dailyCheckin(cred, opsFetcher({ item: daily({ claimable: false, status: null }) }).fetcher)
  assert.equal(ineligible.outcome, "ineligible")
})

test("checkin looks again after a refused claim, and reports a real failure", async () => {
  const cred = await makeCred()
  const refused = (s) => {
    s.item = { ...s.item, claimable: false, status: "CLAIMED" } // claimed elsewhere meanwhile
    return new Response(JSON.stringify({ code: 1001, message: "already claimed" }), { status: 200 })
  }
  assert.equal((await x.dailyCheckin(cred, opsFetcher({ item: daily() }, { claim: refused }).fetcher)).outcome, "done")

  const boom = () => new Response(JSON.stringify({ code: 500, message: "活动太火爆" }), { status: 200 })
  const failed = await x.dailyCheckin(cred, opsFetcher({ item: daily() }, { claim: boom }).fetcher)
  assert.deepEqual(failed, { outcome: "failed", message: "领取失败：活动太火爆" })

  const listFailed = await x.dailyCheckin(cred, opsFetcher({ item: daily(), listStatus: 401 }).fetcher)
  assert.equal(listFailed.outcome, "failed")
  assert.match(listFailed.message, /HTTP 401: APIG\.0301/)
})

test("checkin without a sign-in fails without calling the vendor", async () => {
  const plugin = await CodeArtsAuthPlugin({ client: {} }, { fetch: async () => { throw new Error("no network") } })
  assert.deepEqual(await plugin.auth.checkin(async () => ({ type: "api", key: "k" })), { outcome: "failed", message: "not signed in" })
})

// ---- OAuth callback server -------------------------------------------------

test("startOAuthFlow serves a callback server and a valid login URL", async () => {
  const flow = await x.startOAuthFlow(async () => new Response("", { status: 200 }))
  const url = new URL(flow.loginUrl)
  assert.equal(url.origin + url.pathname, "https://codearts.huaweicloud.com/portal/authorize")
  const port = Number(url.searchParams.get("port"))
  assert.ok(port >= 10000, "callback port must be >= 10000")

  // A callback without a code fails the flow at once (the browser is sent to
  // the portal's failure page, not followed there).
  const res = await fetch(`http://127.0.0.1:${port}/oauth/callback`, { redirect: "manual" })
  assert.equal(res.status, 307)
  await assert.rejects(flow.result, /without an authorization code/)

  await flow.close()
})

test("the callback port is one >= 10000, another while the one picked is taken", async () => {
  const { EventEmitter } = await import("node:events")
  // A stand-in server: the system gives a port below 10000, and the first
  // random picks are someone else's.
  const fakeServer = (taken, code = "EADDRINUSE") => {
    const tried = []
    const server = Object.assign(new EventEmitter(), {
      listen(port, host, cb) {
        tried.push(port)
        this.port = port === 0 ? 8080 : port
        if (port !== 0 && tried.length - 1 <= taken) {
          queueMicrotask(() => this.emit("error", Object.assign(new Error("listen failed"), { code })))
          return
        }
        queueMicrotask(cb)
      },
      address() { return { port: this.port } },
      close(cb) { queueMicrotask(cb) },
    })
    return { server, tried }
  }
  const busy = fakeServer(3)
  const port = await x.listenOnCallbackPort(busy.server)
  assert.equal(busy.tried[0], 0)
  assert.equal(busy.tried.length, 5)
  assert.ok(port >= 10000)
  assert.equal(port, busy.tried.at(-1))
  // Anything but a taken port is no reason to try another.
  const denied = fakeServer(1, "EACCES")
  await assert.rejects(x.listenOnCallbackPort(denied.server), { code: "EACCES" })
  assert.equal(denied.tried.length, 2)
})

/** Run a callback server for one test, its STS answered by `sts`. */
async function withCallbackServer(sts, run) {
  const pkce = await x.generatePkcePair()
  const keyPair = await x.generateDpopKeyPair()
  const exchanges = []
  const fetcher = async (url, init) => {
    exchanges.push(new URLSearchParams(init.body))
    return sts()
  }
  const { port, server, result } = await x.startOAuthCallbackServer(pkce, keyPair, fetcher)
  result.catch(() => {})
  const call = (query = "", init = {}) =>
    fetch(`http://127.0.0.1:${port}${x.REDIRECT_PATH}${query}`, { redirect: "manual", ...init })
  try {
    await run({ port, call, result, exchanges, pkce })
  } finally {
    server.closeAllConnections?.()
    await new Promise((resolve) => server.close(() => resolve()))
  }
}

/**
 * A GET with its path sent as written, over a bare socket: fetch, and bun's
 * http.request, normalise `/oauth/./callback` before it leaves. Gives the
 * status and the Location.
 */
const rawGet = (port, rawPath) => new Promise((resolve, reject) => {
  const socket = net.connect(port, "127.0.0.1", () => {
    socket.write(`GET ${rawPath} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`)
  })
  let answer = ""
  socket.on("data", (d) => { answer += d })
  socket.on("end", () => resolve({
    status: Number(/^HTTP\/1\.1 (\d{3})/.exec(answer)?.[1]),
    location: /^location: *(.*?)\r?$/im.exec(answer.split("\r\n\r\n")[0])?.[1] ?? null,
  }))
  socket.on("error", reject)
})

test("the callback server takes only a GET to the exact path with a code, and never a redirect it is handed", async () => {
  await withCallbackServer(() => new Response(stsBody("AK", "R"), { status: 200 }), async ({ port, call, result, exchanges }) => {
    const post = await call("?code=C", { method: "POST" })
    assert.equal(post.status, 405)
    assert.equal(post.headers.get("allow"), "GET")
    // Only the path exactly as sent: none of these is it.
    const near = ["/other", "/oauth/./callback", "/oauth/%2e/callback", "/oauth/callback/", "/OAUTH/callback", "//oauth/callback"]
    for (const path of near.map((p) => `${p}?code=C`)) {
      assert.equal((await rawGet(port, path)).status, 404, path)
    }
    assert.equal(exchanges.length, 0)
    // The old login's parameters are no way in: no code is a sign-in that
    // failed, at once, and the browser goes to the portal's page, not theirs.
    // (Sent the raw way too, so the 404s above aren't the socket's doing.)
    const legacyRaw = await rawGet(port, `${x.REDIRECT_PATH}?secret=S&redirect=https%3A%2F%2Fevil.example%2F`)
    assert.deepEqual(legacyRaw, { status: 307, location: x.buildPortalLoginResultUrl(false) })
    await assert.rejects(result, /without an authorization code/)
    // Nothing after that is taken, nor exchanged.
    const legacy = await call(`?secret=${encodeURIComponent('{"access":"AK"}')}&redirect=${encodeURIComponent("https://evil.example/")}`)
    assert.equal(legacy.status, 409)
    assert.equal(legacy.headers.get("location"), null)
    assert.equal((await call("?code=C")).status, 409)
    assert.equal(exchanges.length, 0)
  })
})

test("a callback the portal sends back with an error ends the sign-in at once, in its words", async () => {
  await withCallbackServer(() => new Response(stsBody("AK", "R"), { status: 200 }), async ({ call, result }) => {
    const started = Date.now()
    const res = await call("?error=access_denied&error_description=user%20cancelled%20the%20sign-in")
    assert.equal(res.status, 307)
    assert.equal(res.headers.get("location"), x.buildPortalLoginResultUrl(false))
    await assert.rejects(result, /CodeArts sign-in failed: user cancelled the sign-in/)
    assert.ok(Date.now() - started < 5_000, "not left to the 180 s timeout")
  })
})

test("the callback server exchanges the code once, then sends the browser to the portal's result page", async () => {
  await withCallbackServer(() => new Response(stsBody("AK", "R"), { status: 200 }), async ({ port, call, result, exchanges, pkce }) => {
    const res = await call(`?code=C1&redirect=${encodeURIComponent("https://evil.example/")}`)
    assert.equal(res.status, 307)
    assert.equal(res.headers.get("location"), x.buildPortalLoginResultUrl(true))
    const signedIn = await result
    const cred = JSON.parse(signedIn.access)
    assert.equal(cred.access_key_id, "AK")
    assert.equal(cred.code_verifier, pkce.codeVerifier)
    assert.equal(exchanges.length, 1)
    assert.equal(exchanges[0].get("code"), "C1")
    assert.equal(exchanges[0].get("redirect_uri"), `http://127.0.0.1:${port}${x.REDIRECT_PATH}`)
    // A second callback for the same sign-in is refused, and not exchanged.
    const again = await call("?code=C2")
    assert.equal(again.status, 409)
    assert.equal(exchanges.length, 1)
  })
})

test("a code STS turns down sends the browser to the portal's failure page", async () => {
  await withCallbackServer(() => new Response('{"error":"invalid_grant"}', { status: 400 }), async ({ call, result }) => {
    const res = await call("?code=BAD")
    assert.equal(res.status, 307)
    assert.equal(res.headers.get("location"), x.buildPortalLoginResultUrl(false))
    await assert.rejects(result, /token request failed: 400/)
  })
})
