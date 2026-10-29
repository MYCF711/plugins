// Qoder CN (qoder-cn) against a local stand-in for its hosts: every request
// the plugin makes is sent to a Bun.serve server instead, which sees the
// host it was meant for, so each test says which of Qoder CN's hosts a call
// went to — the sign-in page on qoder.cn, accounts on openapi.qoder.com.cn,
// models on gateway.qoder.com.cn — and that none went to qoder.com's.
import { afterAll, afterEach, beforeAll, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { QoderAuthPlugin, QoderCNAuthPlugin, _internal } from "./index.mjs"

const CN_CLIENT = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
const OPENAPI = "openapi.qoder.com.cn"
const GATEWAY = "gateway.qoder.com.cn"

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

// every fetch goes to the stand-in, carrying the host it was meant for
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

test("the sign-in page is qoder.cn's, with Qoder CN's CLI client id and no redirect", async () => {
  const hooks = await QoderCNAuthPlugin({ client: store().client })
  expect(hooks.auth.provider).toBe("qoder-cn")
  expect(hooks.auth.methods[0].label).toBe("Sign in with Qoder CN")
  const flow = await hooks.auth.methods[0].authorize()
  const u = new URL(flow.url)
  expect(u.origin + u.pathname).toBe("https://qoder.cn/device/selectAccounts")
  expect(u.searchParams.get("client_id")).toBe(CN_CLIENT)
  expect(u.searchParams.get("challenge_method")).toBe("S256")
  expect(u.searchParams.has("redirect_uri")).toBe(false)
  for (const k of ["challenge", "nonce", "machine_id"]) expect(u.searchParams.get(k)).toBeTruthy()
})

test("qoder.com's sign-in sends no redirect_uri, as Qoder's CLI does, so Qoder.app isn't handed the page (#276)", async () => {
  const flow = await (await QoderAuthPlugin({ client: store().client })).auth.methods[0].authorize()
  const u = new URL(flow.url)
  expect(u.origin + u.pathname).toBe("https://qoder.com/device/selectAccounts")
  expect(u.searchParams.get("client_id")).toBe("732aef47-9cf2-46a2-95fe-4cebb5d0d1fa")
  expect(u.searchParams.get("challenge_method")).toBe("S256")
  for (const k of ["challenge", "nonce", "machine_id"]) expect(u.searchParams.get(k)).toBeTruthy()
  expect(u.searchParams.has("redirect_uri")).toBe(false)
  expect(flow.url).not.toContain("qoder-app")
})

test("the sign-in polls openapi.qoder.com.cn until authorized, then makes a job token there", async () => {
  toServer()
  let polls = 0
  route = (at, { url, body, req }) => {
    if (at === OPENAPI + "/api/v1/deviceToken/poll") {
      expect(url.searchParams.get("challenge_method")).toBe("S256")
      expect(url.searchParams.get("verifier")).toBeTruthy()
      return ++polls < 2 ? new Response("", { status: 404 }) : json({ token: "dt-cn", refresh_token: "drt-cn", user_id: "u-cn", user_name: "阿里云用户" })
    }
    if (at === OPENAPI + "/api/v1/me/jobToken") {
      expect(req.headers.get("authorization")).toBe("Bearer dt-cn")
      expect(JSON.parse(body)).toEqual({ clientId: CN_CLIENT })
      return json({ token: "jt-cn", refresh_token: "jrt-cn", expires_in: 3_600_000 })
    }
    if (at === OPENAPI + "/api/v1/userinfo") return json({ email: "", name: "" })
    return new Response("", { status: 404 })
  }
  const hooks = await QoderCNAuthPlugin({ client: store().client })
  const flow = await hooks.auth.methods[0].authorize()
  const nonce = new URL(flow.url).searchParams.get("nonce")
  const cred = await flow.callback()
  expect(polls).toBe(2)
  expect(seen[0].query.get("nonce")).toBe(nonce)
  expect(cred).toMatchObject({ type: "success", access: "jt-cn", refresh: "jrt-cn", uid: "u-cn", accountId: "u-cn", name: "阿里云用户", deviceToken: "dt-cn", deviceRefresh: "drt-cn" })
  expect(cred.deviceChat).toBeUndefined()
  expect(cred.machineId).toBe(new URL(flow.url).searchParams.get("machine_id"))
  expect(hostsOf()).toEqual([OPENAPI])
}, 10_000)

test("a job token qoder.cn refuses leaves the account chatting on its device token, as Qoder CN's CLI does", async () => {
  toServer()
  route = (at) => {
    if (at === OPENAPI + "/api/v1/deviceToken/poll") return json({ token: "dt-cn", refresh_token: "drt-cn", user_id: "u-cn", expires_in: 7200 })
    if (at === OPENAPI + "/api/v1/me/jobToken") return json({ message: "client not allowed" }, 403)
    if (at === OPENAPI + "/api/v1/userinfo") return json({ email: "cn@x", name: "CN" })
    return new Response("", { status: 404 })
  }
  const flow = await (await QoderCNAuthPlugin({ client: store().client })).auth.methods[0].authorize()
  const cred = await flow.callback()
  expect(cred).toMatchObject({ access: "dt-cn", refresh: "drt-cn", deviceChat: true, accountId: "cn@x", deviceToken: "dt-cn", deviceRefresh: "drt-cn" })
  expect(Math.abs(cred.expires - (Date.now() + 7_200_000))).toBeLessThan(5_000)
})

test("qoder.com's sign-in still fails on a refused job token", async () => {
  toServer()
  route = (at) => {
    if (at === "openapi.qoder.sh/api/v1/deviceToken/poll") return json({ token: "dt", refresh_token: "drt", user_id: "u" })
    if (at === "openapi.qoder.sh/api/v1/me/jobToken") return json({ message: "no" }, 403)
    return new Response("", { status: 404 })
  }
  const flow = await (await QoderAuthPlugin({ client: store().client })).auth.methods[0].authorize()
  await expect(flow.callback()).rejects.toThrow("Qoder job token: status 403")
})

const MODEL = {
  key: "performance",
  display_name: "Performance",
  enable: true,
  source: "system",
  max_input_tokens: 1_000_000,
  is_vl: true,
  thinking_config: { enabled: { efforts: { low: {}, medium: { is_default: true }, high: {} } }, disabled: {} },
}

const sse = (...chunks) =>
  new Response(chunks.map((c) => `data: ${JSON.stringify({ statusCodeValue: 200, body: JSON.stringify(c) })}\n\n`).join(""), {
    headers: { "Content-Type": "text/event-stream" },
  })

// chatServer answers the model list and a chat on gateway.qoder.com.cn,
// checking the COSY signature over the body as it arrived
const chatServer = (machines, refresh) => (at, { req, body, url }) => {
  if (refresh) {
    const r = refresh(at, body)
    if (r) return r
  }
  if (at === GATEWAY + "/algo/api/v2/model/list") return json({ chat: [MODEL, { key: "auto", enable: true }] })
  if (at === GATEWAY + "/algo/api/v2/service/pro/sse/agent_chat_generation") {
    expect(url.searchParams.get("Encode")).toBe("1")
    const auth = req.headers.get("authorization")
    const [, payload, sig] = auth.match(/^Bearer COSY\.([^.]+)\.([0-9a-f]{32})$/)
    const path = url.pathname.slice("/algo".length)
    const want = createHash("md5").update(`${payload}\n${req.headers.get("cosy-key")}\n${req.headers.get("cosy-date")}\n${body}\n${path}`).digest("hex")
    expect(sig).toBe(want)
    expect(req.headers.get("cosy-user")).toBe("u-cn")
    expect(req.headers.get("x-model-key")).toBe("performance")
    const q = JSON.parse(_internal.decodeBody(body))
    expect(q.model_config.key).toBe("performance")
    expect(q.parameters.reasoning_effort).toBe("high")
    const said = [{ type: "text", text: "你好", cache_control: { type: "ephemeral" } }]
    expect(q.messages.at(-1)).toEqual({ role: "user", content: said, contents: said })
    machines.push(req.headers.get("cosy-machineid"))
    return sse(
      { choices: [{ delta: { reasoning_content: "想想" } }] },
      { choices: [{ delta: { content: "你好！" } }] },
      { choices: [{ delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 3, completion_tokens: 2 } },
    )
  }
  return new Response("", { status: 404 })
}

const signedIn = (over = {}) => ({
  type: "oauth",
  access: "jt-cn",
  refresh: "jrt-cn",
  expires: Date.now() + 3_600_000,
  accountId: "cn@x",
  uid: "u-cn",
  machineId: "m-cn",
  deviceToken: "dt-cn",
  deviceRefresh: "drt-cn",
  ...over,
})

const chat = { model: "performance", reasoning_effort: "high", messages: [{ role: "user", content: "你好" }] }

test("a chat goes to gateway.qoder.com.cn, signed and encoded as Qoder's client does", async () => {
  toServer()
  const machines = []
  route = chatServer(machines)
  const s = store(signedIn())
  const hooks = await QoderCNAuthPlugin({ client: s.client })
  const opts = await hooks.auth.loader(s.get)
  expect(opts.baseURL).toBe("https://gateway.qoder.com.cn")
  const res = await opts.fetch("https://gateway.qoder.com.cn/chat/completions", { method: "POST", body: JSON.stringify(chat) })
  expect(res.status).toBe(200)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("kept")
  const out = await res.json()
  expect(out.choices[0]).toEqual({ index: 0, message: { role: "assistant", content: "你好！", reasoning_content: "想想" }, finish_reason: "stop" })
  expect(out.usage).toEqual({ prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 })
  expect(machines).toEqual(["m-cn"])
  expect(hostsOf()).toEqual([GATEWAY])
  expect(seen.map((x) => x.path)).toEqual(["/algo/api/v2/model/list", "/algo/api/v2/service/pro/sse/agent_chat_generation"])
  expect(s.saved).toEqual([])
})

test("a job token near its end is refreshed on openapi.qoder.com.cn and saved under qoder-cn before the chat", async () => {
  toServer()
  const refresh = (at, body) => {
    if (at !== OPENAPI + "/api/v1/jobToken/refresh") return null
    expect(JSON.parse(body)).toEqual({ refresh_token: "jrt-cn" })
    return json({ token: "jt-cn-2", refresh_token: "jrt-cn-2", expires_in: 3_600_000 })
  }
  route = chatServer([], refresh)
  const s = store(signedIn({ expires: Date.now() + 60_000 }))
  const opts = await (await QoderCNAuthPlugin({ client: s.client })).auth.loader(s.get)
  const res = await opts.fetch("https://gateway.qoder.com.cn/chat/completions", { method: "POST", body: JSON.stringify({ ...chat, stream: true }) })
  expect(res.status).toBe(200)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("renewed")
  const text = await res.text()
  expect(text).toContain('"content":"你好！"')
  expect(text.trim().endsWith("data: [DONE]")).toBe(true)
  expect(s.saved).toEqual(["qoder-cn"])
  expect(s.auth()).toMatchObject({ access: "jt-cn-2", refresh: "jrt-cn-2", deviceToken: "dt-cn" })
  expect(hostsOf()).toEqual([OPENAPI, GATEWAY])
})

test("a device-token account is renewed as a device token on openapi.qoder.com.cn, both pairs as one", async () => {
  toServer()
  const refresh = (at, body) => {
    if (at === OPENAPI + "/api/v1/jobToken/refresh") throw new Error("a device-token account made a job refresh")
    if (at !== OPENAPI + "/api/v1/deviceToken/refresh") return null
    expect(JSON.parse(body)).toEqual({ refresh_token: "drt-cn" })
    return json({ device_token: "dt-cn-2", refresh_token: "drt-cn-2", expires_at: new Date(Date.now() + 7_200_000).toISOString() })
  }
  route = chatServer([], refresh)
  const s = store(signedIn({ access: "dt-cn", refresh: "drt-cn", deviceChat: true, expires: Date.now() + 60_000 }))
  const opts = await (await QoderCNAuthPlugin({ client: s.client })).auth.loader(s.get)
  const res = await opts.fetch("https://gateway.qoder.com.cn/chat/completions", { method: "POST", body: JSON.stringify(chat) })
  expect(res.status).toBe(200)
  expect(s.auth()).toMatchObject({ access: "dt-cn-2", refresh: "drt-cn-2", deviceToken: "dt-cn-2", deviceRefresh: "drt-cn-2", deviceChat: true })
  expect(s.auth().expires).toBeGreaterThan(Date.now() + 7_000_000)
  expect(seen.map((x) => x.host + x.path)).toEqual([OPENAPI + "/api/v1/deviceToken/refresh", GATEWAY + "/algo/api/v2/model/list", GATEWAY + "/algo/api/v2/service/pro/sse/agent_chat_generation"])
})

test("a device-token account whose refresh qoder.cn refuses is signed out, marked expired", async () => {
  toServer()
  route = (at) => (at === OPENAPI + "/api/v1/deviceToken/refresh" ? new Response("", { status: 401 }) : new Response("", { status: 404 }))
  const s = store(signedIn({ access: "dt-cn", refresh: "drt-cn", deviceChat: true, expires: Date.now() + 60_000 }))
  const opts = await (await QoderCNAuthPlugin({ client: s.client })).auth.loader(s.get)
  const res = await opts.fetch("https://gateway.qoder.com.cn/chat/completions", { method: "POST", body: JSON.stringify(chat) })
  expect(res.status).toBe(401)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("expired")
  expect((await res.json()).error.message).toContain("Qoder CN sign-in has expired")
})

test("the account's list is read from gateway.qoder.com.cn as qoder-cn's models", async () => {
  toServer()
  route = chatServer([])
  const hooks = await QoderCNAuthPlugin({ client: store().client })
  const ms = await hooks.provider.models({ models: {} }, { auth: signedIn() })
  expect(Object.keys(ms)).toEqual(["performance"])
  expect(ms.performance).toMatchObject({ providerID: "qoder-cn", api: { url: "https://gateway.qoder.com.cn" }, variants: { low: {}, medium: {}, high: {} } })
  expect(hostsOf()).toEqual([GATEWAY])
})

test("usage is read from openapi.qoder.com.cn with the device token", async () => {
  toServer()
  route = (at, { req }) => {
    if (at !== OPENAPI + "/sash/api/v2/me/usage") return new Response("", { status: 404 })
    expect(req.headers.get("authorization")).toBe("Bearer dt-cn")
    return json({ displayMode: "qoder", qoderUsage: { userType: "pro", userQuota: { total: 100, used: 40 } } })
  }
  const s = store(signedIn())
  const hooks = await QoderCNAuthPlugin({ client: s.client })
  expect(await hooks.auth.usage(s.get)).toEqual({ plan: "pro", windows: [{ name: "Credits", used: 40, display: "40 / 100 credits" }], signIn: "kept" })
})

test("the config declares qoder-cn on its gateway, with the tiers Qoder CN's CLI names", async () => {
  const cfg = { provider: {} }
  await (await QoderCNAuthPlugin({ client: store().client })).config(cfg)
  await (await QoderAuthPlugin({ client: store().client })).config(cfg)
  expect(cfg.provider["qoder-cn"]).toMatchObject({ name: "Qoder CN", npm: "@ai-sdk/openai-compatible", api: "https://gateway.qoder.com.cn" })
  expect(Object.keys(cfg.provider["qoder-cn"].models)).toEqual(["ultimate", "performance", "efficient", "lite"])
  expect(cfg.provider.qoder.api).toBe("https://api3.qoder.sh")
  expect(Object.keys(cfg.provider.qoder.models)).toContain("qmodel")
})

test("qoder-cn: a device sign-in names the card by the phone (review #487, E)", async () => {
  toServer()
  let polls = 0
  route = (at) => {
    if (at === OPENAPI + "/api/v1/deviceToken/poll")
      return ++polls < 2 ? new Response("", { status: 404 }) : json({ token: "dt-p", refresh_token: "drt-p", user_id: "u-p" })
    if (at === OPENAPI + "/api/v1/me/jobToken") return json({ token: "jt-p", refresh_token: "jrt-p", expires_in: 3_600_000 })
    if (at === OPENAPI + "/api/v1/userinfo")
      return json({ id: "u-p", name: "dsh13800138000", security_mobile: "13800138000" })
    return new Response("", { status: 404 })
  }
  const hooks = await QoderCNAuthPlugin({ client: store().client })
  const flow = await hooks.auth.methods[0].authorize()
  const cred = await flow.callback()
  // accountId stays main's computation (Qoder CN's uuid); the card's name is cardName
  expect(cred.accountId).toBe("u-p")
  expect(cred.phoneLabel).toBe("138****8000")
  expect(cred.cardName).toBe("138****8000")
})

test("qoder-cn: a device sign-in with an email and a phone shows the email (review #487, round 5)", async () => {
  toServer()
  let polls = 0
  route = (at) => {
    if (at === OPENAPI + "/api/v1/deviceToken/poll")
      return ++polls < 2 ? new Response("", { status: 404 }) : json({ token: "dt-e", refresh_token: "drt-e", user_id: "u-e" })
    if (at === OPENAPI + "/api/v1/me/jobToken") return json({ token: "jt-e", refresh_token: "jrt-e", expires_in: 3_600_000 })
    if (at === OPENAPI + "/api/v1/userinfo")
      return json({ id: "u-e", email: "bob@example.com", name: "Bob", security_mobile: "13800138000" })
    return new Response("", { status: 404 })
  }
  const hooks = await QoderCNAuthPlugin({ client: store().client })
  const flow = await hooks.auth.methods[0].authorize()
  const cred = await flow.callback()
  // main names a device-only account by its email; the phone is the card's
  expect(cred.accountId).toBe("bob@example.com")
  expect(cred.cardName).toBe("bob@example.com")
  expect(cred.phoneLabel).toBe("138****8000")
})
