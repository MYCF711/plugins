// Qoder CN enterprise VPC accounts (yetone/magpie#312) against a local
// stand-in for an instance's hosts. The hosts and shapes are the ones
// AwadYoo reported from a real VPC account on @qodercn-ai/qoderclicn 1.1.64
// (values redacted there, made up here): the sign-in page on
// <instance>.vpc.qoder.com.cn, accounts on <instance>-openapi…, models and
// chat on <instance>-gateway…, the same paths as the public hosts. That CLI
// builds these hosts by swapping the public origin for the instance's
// (its VPC host map: base, gateway, openapi), the path kept.
import { afterAll, afterEach, beforeAll, expect, test } from "bun:test"
import { QoderAuthPlugin, QoderCNAuthPlugin, _internal } from "./index.mjs"

const CN_CLIENT = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
const WEB = "acme.vpc.qoder.com.cn"
const OPENAPI = "acme-openapi.vpc.qoder.com.cn"
const GATEWAY = "acme-gateway.vpc.qoder.com.cn"
const PUBLIC = ["qoder.cn", "openapi.qoder.com.cn", "gateway.qoder.com.cn", "openapi.qoder.sh", "api3.qoder.sh"]

let server
let route = () => new Response("", { status: 404 })
let seen = []
const real = globalThis.fetch

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    async fetch(req) {
      const u = new URL(req.url)
      const host = req.headers.get("x-qoder-host")
      const body = req.method === "GET" ? "" : await req.text()
      seen.push({ host, path: u.pathname, query: u.searchParams, method: req.method, headers: req.headers, body })
      return route(host + u.pathname, { req, url: u, body })
    },
  })
})
afterAll(() => server.stop(true))

const toServer = () => {
  globalThis.fetch = async (input, init = {}) => {
    const u = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url)
    const headers = new Headers(init.headers)
    headers.set("x-qoder-host", u.host)
    return real(`http://127.0.0.1:${server.port}${u.pathname}${u.search}`, { ...init, headers })
  }
}
afterEach(() => {
  globalThis.fetch = real
  route = () => new Response("", { status: 404 })
  seen = []
})

const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } })

function store(initial) {
  let auth = initial
  const saved = []
  return {
    client: { auth: { set: async ({ path, body }) => (saved.push(path.id), (auth = body)) } },
    get: async () => auth,
    auth: () => auth,
    saved,
  }
}

const hostsOf = () => [...new Set(seen.map((s) => s.host))]
const noPublic = () => expect(hostsOf().filter((h) => PUBLIC.includes(h))).toEqual([])

const vpcMethod = (hooks) => hooks.auth.methods.find((m) => m.prompts?.some((p) => p.key === "vpc"))

test("an instance is read from its name or any of its hosts, as Qoder CN's CLI reads its VPC endpoint", () => {
  const d = "vpc.qoder.com.cn"
  for (const v of ["acme", " ACME ", "acme.vpc.qoder.com.cn", "acme-openapi.vpc.qoder.com.cn", "acme-gateway.vpc.qoder.com.cn", "https://acme.vpc.qoder.com.cn", "https://acme.vpc.qoder.com.cn/"])
    expect([v, _internal.vpcInstance(v, d)]).toEqual([v, "acme"])
  expect(_internal.vpcInstance("my-corp-01", d)).toBe("my-corp-01")
  for (const v of ["", "  ", "http://acme.vpc.qoder.com.cn", "https://acme.vpc.qoder.com.cn/x", "https://acme.vpc.qoder.com.cn?a=1", "https://u:p@acme.vpc.qoder.com.cn", "https://acme.vpc.qoder.com.cn:8443", "10.0.0.1", "acme.example.com", "evil.com/acme.vpc.qoder.com.cn", "-acme", "acme-", "ac_me", "a.b.vpc.qoder.com.cn"])
    expect([v, _internal.vpcInstance(v, d)]).toEqual([v, undefined])
  // qoder.com has no VPC
  expect(_internal.vpcInstance("acme", undefined)).toBeUndefined()
})

test("the hosts of an instance are the CLI's: <i>.vpc, <i>-openapi.vpc, <i>-gateway.vpc", () => {
  const s = _internal.vpcSite(_internal.SITES["qoder-cn"], "acme")
  expect(s).toMatchObject({ id: "qoder-cn", web: "https://" + WEB, openapi: "https://" + OPENAPI, api: "https://" + GATEWAY, vpc: "acme", clientId: CN_CLIENT })
  expect(_internal.vpcSite(_internal.SITES.qoder, "acme")).toBeUndefined()
})

test("the public sign-in is unchanged: it is still the first method and asks nothing", async () => {
  const hooks = await QoderCNAuthPlugin({ client: store().client })
  expect(hooks.auth.methods[0].label).toBe("Sign in with Qoder CN")
  expect(hooks.auth.methods[0].prompts).toBeUndefined()
  const u = new URL((await hooks.auth.methods[0].authorize()).url)
  expect(u.origin + u.pathname).toBe("https://qoder.cn/device/selectAccounts")
  // qoder.com gains no VPC method, but has the PAT method
  expect((await QoderAuthPlugin({ client: store().client })).auth.methods.length).toBe(2)
})

test("the VPC method asks for the instance and checks it", async () => {
  const m = vpcMethod(await QoderCNAuthPlugin({ client: store().client }))
  expect(m.type).toBe("oauth")
  expect(m.label).toBe("Sign in with Qoder CN Enterprise (VPC)")
  const p = m.prompts[0]
  expect(p.type).toBe("text")
  expect(p.validate("acme")).toBeUndefined()
  expect(p.validate("http://acme.vpc.qoder.com.cn")).toContain("Not a VPC instance")
  expect(() => m.authorize({ vpc: "acme.example.com" })).toThrow("Not a VPC instance")
})

test("a VPC sign-in opens the instance's page and polls, trades and reads the user on its openapi host", async () => {
  toServer()
  let polls = 0
  route = (at, { url, body, req }) => {
    if (at === OPENAPI + "/api/v1/deviceToken/poll") {
      expect(url.searchParams.get("challenge_method")).toBe("S256")
      // the reporter's poll shape: the token alone
      return ++polls < 2 ? new Response("", { status: 404 }) : json({ token: "dt-vpc", refresh_token: "drt-vpc" })
    }
    if (at === OPENAPI + "/api/v1/me/jobToken") {
      expect(req.headers.get("authorization")).toBe("Bearer dt-vpc")
      expect(JSON.parse(body)).toEqual({ clientId: CN_CLIENT })
      return json({ message: "client not allowed" }, 403)
    }
    if (at === OPENAPI + "/api/v1/userinfo") {
      expect(req.headers.get("authorization")).toBe("Bearer dt-vpc")
      // the reporter's normalized user info
      return json({ id: "u-vpc", username: "alice", name: "Alice", email: "alice@corp.example", avatar: "https://x/a.png", orgId: "org-1", orgName: "Corp", isPrivacyPolicyModifiable: true })
    }
    return new Response("", { status: 404 })
  }
  const m = vpcMethod(await QoderCNAuthPlugin({ client: store().client }))
  const flow = await m.authorize({ vpc: "https://acme.vpc.qoder.com.cn" })
  const u = new URL(flow.url)
  expect(u.origin + u.pathname).toBe("https://" + WEB + "/device/selectAccounts")
  expect(u.searchParams.get("client_id")).toBe(CN_CLIENT)
  expect(u.searchParams.has("redirect_uri")).toBe(false)
  const cred = await flow.callback()
  expect(cred).toMatchObject({
    type: "success",
    access: "dt-vpc",
    refresh: "drt-vpc",
    deviceChat: true,
    uid: "u-vpc",
    email: "alice@corp.example",
    name: "Alice",
    accountId: "alice@corp.example (acme)",
    vpc: "acme",
    deviceToken: "dt-vpc",
    deviceRefresh: "drt-vpc",
  })
  expect(hostsOf()).toEqual([OPENAPI])
}, 10_000)

test("a VPC poll and user info that name no user fail the sign-in rather than keep an account with none", async () => {
  toServer()
  route = (at) => {
    if (at === OPENAPI + "/api/v1/deviceToken/poll") return json({ token: "dt-vpc", refresh_token: "drt-vpc" })
    if (at === OPENAPI + "/api/v1/me/jobToken") return json({ token: "jt", refresh_token: "jrt", expires_in: 3_600_000 })
    if (at === OPENAPI + "/api/v1/userinfo") return json({ email: "" })
    return new Response("", { status: 404 })
  }
  const flow = await vpcMethod(await QoderCNAuthPlugin({ client: store().client })).authorize({ vpc: "acme" })
  await expect(flow.callback()).rejects.toThrow("named no user")
})

// a model as the reporter's listing gives it, under its scene
const MODEL = {
  key: "performance",
  display_name: "Performance",
  is_default: false,
  enable: true,
  is_reasoning: true,
  is_vl: false,
  efforts: ["high"],
  default_effort: "high",
  max_input_tokens: 180000,
  available_context_windows: [180000],
  format: "openai",
  source: "system",
  price_factor: 1,
  original_price_factor: 1,
  tags: [],
  strategies: [{ tag: "t", enabled: true, disabled_message_key: "k" }],
  promotion: { active: false, discount_factor: 0, before_promotion_price_factor: 0 },
}

const sse = (...chunks) =>
  new Response(chunks.map((c) => `data: ${JSON.stringify({ statusCodeValue: 200, body: JSON.stringify(c) })}\n\n`).join(""), {
    headers: { "Content-Type": "text/event-stream" },
  })

const signedIn = (over = {}) => ({
  type: "oauth",
  access: "dt-vpc",
  refresh: "drt-vpc",
  expires: Date.now() + 3_600_000,
  deviceChat: true,
  accountId: "alice@corp.example (acme)",
  uid: "u-vpc",
  machineId: "m-vpc",
  deviceToken: "dt-vpc",
  deviceRefresh: "drt-vpc",
  vpc: "acme",
  ...over,
})

const chat = { model: "performance", messages: [{ role: "user", content: "hi" }] }

const gateway = (at) => {
  if (at === GATEWAY + "/algo/api/v2/model/list") return json({ chat: [MODEL] })
  if (at === GATEWAY + "/algo/api/v2/service/pro/sse/agent_chat_generation")
    // the reporter's OpenAI-compatible chunk
    return sse(
      { choices: [{ index: 0, delta: { role: "assistant", content: "OK", reasoning_content: "", tool_calls: [] }, finish_reason: null }] },
      { choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 5, completion_tokens: 1, total_tokens: 6 } },
    )
  return null
}

test("a VPC account's chat and list go to its gateway host, not the public one", async () => {
  toServer()
  route = (at, { req }) => {
    const r = gateway(at)
    if (r && at.endsWith("agent_chat_generation")) expect(req.headers.get("cosy-user")).toBe("u-vpc")
    return r ?? new Response("", { status: 404 })
  }
  const s = store(signedIn())
  const opts = await (await QoderCNAuthPlugin({ client: s.client })).auth.loader(s.get)
  expect(opts.baseURL).toBe("https://" + GATEWAY)
  const res = await opts.fetch("https://" + GATEWAY + "/chat/completions", { method: "POST", body: JSON.stringify(chat) })
  expect(res.status).toBe(200)
  const out = await res.json()
  expect(out.choices[0].message.content).toBe("OK")
  expect(out.usage).toEqual({ prompt_tokens: 5, completion_tokens: 1, total_tokens: 6 })
  expect(seen.map((x) => x.host + x.path)).toEqual([GATEWAY + "/algo/api/v2/model/list", GATEWAY + "/algo/api/v2/service/pro/sse/agent_chat_generation"])
  noPublic()
})

test("public and VPC accounts with the same uid keep separate model listings", async () => {
  toServer()
  const publicGateway = "gateway.qoder.com.cn"
  route = (at) => {
    if (at === publicGateway + "/algo/api/v2/model/list") return json({ chat: [{ ...MODEL, display_name: "Public Performance" }] })
    if (at === GATEWAY + "/algo/api/v2/model/list") return json({ chat: [{ ...MODEL, display_name: "VPC Performance" }] })
    if (at === publicGateway + "/algo/api/v2/service/pro/sse/agent_chat_generation" || at === GATEWAY + "/algo/api/v2/service/pro/sse/agent_chat_generation")
      return sse({ choices: [{ index: 0, delta: { content: "OK" }, finish_reason: "stop" }] })
    return new Response("", { status: 404 })
  }
  const publicAccount = store(signedIn({ vpc: undefined, accountId: "alice@corp.example" }))
  const enterpriseAccount = store(signedIn())
  const hooks = await QoderCNAuthPlugin({ client: publicAccount.client })
  const publicLoader = await hooks.auth.loader(publicAccount.get)
  const enterpriseLoader = await hooks.auth.loader(enterpriseAccount.get)
  expect((await publicLoader.fetch(publicLoader.baseURL + "/chat/completions", { method: "POST", body: JSON.stringify(chat) })).status).toBe(200)
  expect((await enterpriseLoader.fetch(enterpriseLoader.baseURL + "/chat/completions", { method: "POST", body: JSON.stringify(chat) })).status).toBe(200)
  expect(seen.map((x) => x.host + x.path)).toEqual([
    publicGateway + "/algo/api/v2/model/list",
    publicGateway + "/algo/api/v2/service/pro/sse/agent_chat_generation",
    GATEWAY + "/algo/api/v2/model/list",
    GATEWAY + "/algo/api/v2/service/pro/sse/agent_chat_generation",
  ])
})

test("public and VPC accounts with the same uid keep separate renewal marks", async () => {
  toServer()
  const publicOpenapi = "openapi.qoder.com.cn"
  const publicGateway = "gateway.qoder.com.cn"
  route = (at) => {
    if (at === publicOpenapi + "/api/v1/deviceToken/refresh")
      return json({ device_token: "dt-public-2", refresh_token: "drt-public-2", expires_at: new Date(Date.now() + 7_200_000).toISOString() })
    if (at === publicGateway + "/algo/api/v2/model/list" || at === GATEWAY + "/algo/api/v2/model/list") return json({ chat: [MODEL] })
    if (at === publicGateway + "/algo/api/v2/service/pro/sse/agent_chat_generation" || at === GATEWAY + "/algo/api/v2/service/pro/sse/agent_chat_generation")
      return sse({ choices: [{ index: 0, delta: { content: "OK" }, finish_reason: "stop" }] })
    return new Response("", { status: 404 })
  }
  const publicAccount = store(signedIn({ vpc: undefined, accountId: "alice@corp.example", expires: Date.now() + 60_000 }))
  const enterpriseAccount = store(signedIn())
  const hooks = await QoderCNAuthPlugin({ client: publicAccount.client })
  await hooks.provider.models({ models: {} }, { auth: publicAccount.auth() })
  const enterpriseLoader = await hooks.auth.loader(enterpriseAccount.get)
  const enterpriseResponse = await enterpriseLoader.fetch(enterpriseLoader.baseURL + "/chat/completions", { method: "POST", body: JSON.stringify(chat) })
  expect(enterpriseResponse.headers.get("X-Magpie-Sign-In")).toBe("kept")
  const publicLoader = await hooks.auth.loader(publicAccount.get)
  const publicResponse = await publicLoader.fetch(publicLoader.baseURL + "/chat/completions", { method: "POST", body: JSON.stringify(chat) })
  expect(publicResponse.headers.get("X-Magpie-Sign-In")).toBe("renewed")
})
test("a VPC device token is renewed on its openapi host with the reporter's refresh shape", async () => {
  toServer()
  route = (at, { body }) => {
    if (at === OPENAPI + "/api/v1/deviceToken/refresh") {
      expect(JSON.parse(body)).toEqual({ refresh_token: "drt-vpc" })
      return json({ device_token: "dt-vpc-2", refresh_token: "drt-vpc-2", expires_at: new Date(Date.now() + 7_200_000).toISOString(), refresh_token_expires_at: 0 })
    }
    return gateway(at) ?? new Response("", { status: 404 })
  }
  const s = store(signedIn({ expires: Date.now() + 60_000 }))
  const opts = await (await QoderCNAuthPlugin({ client: s.client })).auth.loader(s.get)
  const res = await opts.fetch("https://" + GATEWAY + "/chat/completions", { method: "POST", body: JSON.stringify(chat) })
  expect(res.status).toBe(200)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("renewed")
  expect(s.auth()).toMatchObject({ access: "dt-vpc-2", refresh: "drt-vpc-2", deviceToken: "dt-vpc-2", vpc: "acme" })
  expect(seen[0].host + seen[0].path).toBe(OPENAPI + "/api/v1/deviceToken/refresh")
  noPublic()
})

test("magpie's auth.refresh of a VPC job-token account goes to its openapi host", async () => {
  toServer()
  route = (at, { body }) => {
    if (at !== OPENAPI + "/api/v1/jobToken/refresh") return new Response("", { status: 404 })
    expect(JSON.parse(body)).toEqual({ refresh_token: "jrt" })
    // the reporter's job token refresh shape
    return json({ token: "jt-2", refresh_token: "jrt-2", expires_at: 0, expires_in: 3_600_000, refresh_token_expires_at: 0, refresh_token_expires_in: 0 })
  }
  const a = signedIn({ access: "jt", refresh: "jrt", deviceChat: undefined, expires: Date.now() + 60_000 })
  const got = await (await QoderCNAuthPlugin({ client: store(a).client })).auth.refresh(a)
  expect(got).toMatchObject({ access: "jt-2", refresh: "jrt-2" })
  expect(hostsOf()).toEqual([OPENAPI])
})

test("a VPC account's models come from its gateway, named on it", async () => {
  toServer()
  route = (at) => gateway(at) ?? new Response("", { status: 404 })
  const ms = await (await QoderCNAuthPlugin({ client: store().client })).provider.models({ models: {} }, { auth: signedIn() })
  expect(Object.keys(ms)).toEqual(["performance"])
  expect(ms.performance.api.url).toBe("https://" + GATEWAY)
  noPublic()
})

test("a VPC account's usage is read on its openapi host; the enterprise display mode is its plan", async () => {
  toServer()
  route = (at, { req }) => {
    if (at !== OPENAPI + "/sash/api/v2/me/usage") return new Response("", { status: 404 })
    expect(req.headers.get("authorization")).toBe("Bearer dt-vpc")
    return json({ displayMode: "enterprise", enterpriseUsage: { openMode: "externalBrowser", detailUrl: "https://" + WEB + "/usage" } })
  }
  const s = store(signedIn())
  expect(await (await QoderCNAuthPlugin({ client: s.client })).auth.usage(s.get)).toEqual({ plan: "Enterprise", signIn: "kept" })
  noPublic()
})

test("magpie's check-in on the public host is asked on the VPC instance", async () => {
  toServer()
  route = (at) => (at === OPENAPI + "/sash/api/v1/me/campaigns" ? json({ campaigns: [] }) : new Response("", { status: 404 }))
  const s = store(signedIn())
  const opts = await (await QoderCNAuthPlugin({ client: s.client })).auth.loader(s.get)
  const res = await opts.fetch("https://openapi.qoder.com.cn/sash/api/v1/me/campaigns", { method: "GET" })
  expect(res.status).toBe(200)
  expect(hostsOf()).toEqual([OPENAPI])
})

test("an account whose VPC instance on record isn't one is not sent to the public hosts", async () => {
  toServer()
  route = (at) => gateway(at) ?? new Response("", { status: 404 })
  const s = store(signedIn({ vpc: "evil.example.com" }))
  const hooks = await QoderCNAuthPlugin({ client: s.client })
  const opts = await hooks.auth.loader(s.get)
  const res = await opts.fetch("https://gateway.qoder.com.cn/chat/completions", { method: "POST", body: JSON.stringify(chat) })
  expect(res.status).toBe(401)
  expect((await res.json()).error.message).toContain("isn't one; sign in again")
  expect((await hooks.auth.usage(s.get)).error).toContain("isn't one")
  expect(seen).toEqual([])
})

test("a VPC account's renewal asks its own instance for the name, and keeps the suffix (review #487)", async () => {
  toServer()
  const at = []
  route = (where, { req }) => {
    at.push(where)
    if (where === OPENAPI + "/api/v1/jobToken/refresh")
      return json({ token: "jt-vpc-2", refresh_token: "jrt-vpc-2", expires_in: 86400000 })
    if (where === OPENAPI + "/api/v1/userinfo") {
      expect(req.headers.get("authorization")).toBe("Bearer jt-vpc-2")
      return json({ id: "u-vpc", name: "Alice", security_mobile: "13800138000" })
    }
    return new Response("", { status: 404 })
  }
  const hooks = await QoderCNAuthPlugin({ client: store().client })
  const got = await hooks.auth.refresh({
    type: "oauth",
    access: "jt-vpc-1",
    refresh: "jrt-vpc-1",
    uid: "u-vpc",
    vpc: "acme",
    accountId: "alice@corp.example (acme)",
    expires: Date.now() + 1_000,
  })
  // accountId does not move (it is the identity); the phone lands on phoneLabel only
  expect(got.accountId).toBeUndefined()
  expect(got.phoneLabel).toBe("138****8000 (acme)")
  // and no public host was touched: an enterprise token never goes there
  expect(at.some((w) => w.startsWith(OPENAPI))).toBe(true)
  expect(at.some((w) => w.startsWith("openapi.qoder.com.cn"))).toBe(false)
  expect(at.some((w) => PUBLIC.some((p) => w.startsWith(p)))).toBe(false)
})

test("a hanging user-info read does not hold another account's chat (review #487, C)", async () => {
  let release
  const gate = new Promise((r) => { release = r })
  const real = globalThis.fetch
  let userinfoReached = false
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url))
    if (u.pathname === "/api/v1/userinfo") { userinfoReached = true; await gate; return json({ id: "u-a", name: "A" }) }
    if (u.pathname === "/api/v1/jobToken/refresh") return json({ token: "jt-a2", refresh_token: "jrt-a2", expires_in: 86400000 })
    if (u.pathname.endsWith("/chat/completions")) return json({ id: "x", choices: [{ message: { content: "ok" } }] })
    return new Response("", { status: 404 })
  }
  try {
    const hooks = await QoderCNAuthPlugin({ client: { auth: { set: async () => {} } } })
    // account A renews: its token is swapped and the name read is hanging
    const pending = hooks.auth.refresh({ type: "oauth", access: "jt-a1", refresh: "jrt-a1", uid: "u-a", expires: Date.now() + 1_000 })
    for (let i = 0; i < 50 && !userinfoReached; i++) await new Promise((r) => setTimeout(r, 10))
    expect(userinfoReached).toBe(true)
    // account B's chat must not wait on it
    const loader = await hooks.auth.loader(async () => ({ type: "oauth", access: "jt-b", refresh: "jrt-b", uid: "u-b", expires: Date.now() + 86_400_000 }))
    const at = Date.now()
    const res = await loader.fetch("https://api3.qoder.sh/v1/chat/completions", { method: "POST", body: JSON.stringify({ model: "q", messages: [] }) })
    // the point is that it did not wait: any status is fine, being held is not
    expect(res).toBeInstanceOf(Response)
    expect(Date.now() - at).toBeLessThan(1_000)
    release()
    await pending
  } finally {
    release()
    globalThis.fetch = real
  }
})
