// PAT sign-in: exchange a Personal Access Token for a job token, bypassing
// the OAuth device flow. Offered on both sites: Qoder CN's exchange takes a
// PAT too, and the job token it returns signs the model list and chat calls
// with the COSY envelope as it does on qoder.com.
import { afterEach, expect, test } from "bun:test"
import { QoderAuthPlugin, QoderCNAuthPlugin } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => (globalThis.fetch = real))

const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } })

async function plugin(auth) {
  let stored = auth
  const client = { auth: { set: async ({ body }) => (stored = body) } }
  const hooks = await QoderAuthPlugin({ client })
  return { hooks, get: async () => stored }
}

test("qoder: PAT auth method is listed", async () => {
  const { hooks } = await plugin(null)
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  expect(patMethod).toBeDefined()
  expect(patMethod.type).toBe("oauth")
  expect(patMethod.prompts).toHaveLength(1)
  expect(patMethod.prompts[0].key).toBe("pat")
  expect(patMethod.prompts[0].type).toBe("password")
})

test("qoder-cn: PAT auth method is listed", async () => {
  const client = { auth: { set: async () => {} } }
  const hooks = await QoderCNAuthPlugin({ client })
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  expect(patMethod).toBeDefined()
  expect(patMethod.type).toBe("oauth")
  expect(patMethod.label).toBe("Sign in with Qoder CN PAT")
  expect(patMethod.prompts).toHaveLength(1)
  expect(patMethod.prompts[0].key).toBe("pat")
  expect(patMethod.prompts[0].type).toBe("password")
  // the prompt names the CN console, not qoder.com's
  expect(patMethod.prompts[0].message).toContain("https://qoder.cn/account/integrations")
})

test("qoder-cn: PAT sign-in exchanges at the CN openapi host", async () => {
  const calls = []
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url))
    calls.push(u.host + u.pathname)
    if (u.host === "openapi.qoder.com.cn" && u.pathname === "/api/v1/jobToken/exchange") {
      const body = JSON.parse(init.body)
      expect(body.personal_token).toBe("pt-cn123")
      return json({ token: "jt-cn", refresh_token: "jrt-cn", expires_in: 86400000 })
    }
    if (u.host === "openapi.qoder.com.cn" && u.pathname === "/api/v1/userinfo") {
      return json({ id: "cn-user-1", name: "CN User" })
    }
    return new Response("", { status: 500 })
  }
  const client = { auth: { set: async () => {} } }
  const hooks = await QoderCNAuthPlugin({ client })
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const flow = patMethod.authorize({ pat: "pt-cn123" })
  expect(flow.url).toBe("https://qoder.cn/account/integrations")

  const res = await flow.callback()
  expect(res.type).toBe("success")
  expect(res.access).toBe("jt-cn")
  expect(res.uid).toBe("cn-user-1")
  expect(res.patAuth).toBe(true)
  expect(res.pat).toBe("pt-cn123")
  // a PAT account keeps no device token: it is not a device-chat account
  expect(res.deviceToken).toBe("")
  expect(res.deviceChat).toBeUndefined()
  expect(calls).toContain("openapi.qoder.com.cn/api/v1/jobToken/exchange")
  expect(calls).toContain("openapi.qoder.com.cn/api/v1/userinfo")
  // nothing is asked of the global host
  expect(calls.some((c) => c.startsWith("openapi.qoder.sh"))).toBe(false)
})

test("qoder-cn: a PAT account keeps the name its browser sign-in takes", async () => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname === "/api/v1/jobToken/exchange") return json({ token: "jt-1", refresh_token: "jrt-1", expires_in: 86400000 })
    if (u.pathname === "/api/v1/userinfo") return json({ id: "same-user", name: "Someone" })
    return new Response("", { status: 500 })
  }
  const client = { auth: { set: async () => {} } }
  const hooks = await QoderCNAuthPlugin({ client })
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const res = await patMethod.authorize({ pat: "pt-x" }).callback()

  // no suffix: magpie's host replaces an account on a new sign-in when both
  // the accountId and the uid match, so a re-signed PAT must name the same
  // account the browser sign-in does, not a row of its own beside it.
  // This account has neither a phone nor an email: both paths keep naming it
  // by its uid, as they did before the phone label (review #487, 5).
  expect(res.accountId).toBe("same-user")
  expect(res.uid).toBe("same-user")
  expect(res.email).toBe("")
})

test("qoder: a PAT account is named by its email, as the browser sign-in is", async () => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname === "/api/v1/jobToken/exchange") return json({ token: "jt-g", refresh_token: "jrt-g", expires_in: 86400000 })
    if (u.pathname === "/api/v1/userinfo") return json({ id: "g-1", email: "g@example.com", name: "G" })
    return new Response("", { status: 500 })
  }
  const { hooks } = await plugin(null)
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const res = await patMethod.authorize({ pat: "pt-g" }).callback()
  expect(res.accountId).toBe("g@example.com")
})

test("qoder: PAT auth method validates PAT format", async () => {
  const { hooks } = await plugin(null)
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const validate = patMethod.prompts[0].validate
  expect(validate("pt-abc123")).toBeUndefined()
  expect(validate("invalid")).toContain("pt-")
  expect(validate("")).toContain("pt-")
})

test("qoder: PAT sign-in exchanges token and returns credentials", async () => {
  const calls = []
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url))
    calls.push(u.host + u.pathname)
    if (u.host === "openapi.qoder.sh" && u.pathname === "/api/v1/jobToken/exchange") {
      const body = JSON.parse(init.body)
      expect(body.personal_token).toBe("pt-test123")
      return json({ token: "jt-pat", refresh_token: "jrt-pat", expires_in: 86400000, expires_at: new Date(Date.now() + 86400000).toISOString(), refresh_token_expires_at: new Date(Date.now() + 172800000).toISOString(), refresh_token_expires_in: 172800000 })
    }
    if (u.host === "openapi.qoder.sh" && u.pathname === "/api/v1/userinfo") {
      return json({ id: "user-123", email: "test@example.com", name: "Test User" })
    }
    return new Response("", { status: 500 })
  }
  const { hooks } = await plugin(null)
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const flow = patMethod.authorize({ pat: "pt-test123" })
  expect(flow.url).toContain("account/integrations")
  expect(flow.method).toBe("auto")
  const result = await flow.callback()
  expect(result.type).toBe("success")
  expect(result.access).toBe("jt-pat")
  expect(result.refresh).toBe("jrt-pat")
  expect(result.uid).toBe("user-123")
  expect(result.email).toBe("test@example.com")
  expect(result.patAuth).toBe(true)
  expect(result.pat).toBe("pt-test123")
  expect(result.deviceToken).toBe("")
  expect(result.machineId).toBeTruthy()
  expect(calls).toContain("openapi.qoder.sh/api/v1/jobToken/exchange")
  expect(calls).toContain("openapi.qoder.sh/api/v1/userinfo")
})

test("qoder: PAT sign-in reads alternate response fields", async () => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname === "/api/v1/jobToken/exchange") {
      return json({ access_token: "jt-alt", refreshToken: "jrt-alt", expire_time: new Date(Date.now() + 7200_000).toISOString() })
    }
    if (u.pathname === "/api/v1/userinfo") {
      return json({ id: "user-alt", email: "alt@example.com" })
    }
    return new Response("", { status: 500 })
  }
  const { hooks } = await plugin(null)
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const result = await patMethod.authorize({ pat: "pt-alt" }).callback()
  expect(result.access).toBe("jt-alt")
  expect(result.refresh).toBe("jrt-alt")
  expect(result.expires).toBeGreaterThan(Date.now())
  expect(result.expires).toBeLessThanOrEqual(Date.now() + 7200_000)
})

test("qoder: PAT sign-in fails when Qoder refuses the PAT", async () => {
  globalThis.fetch = async () => new Response("Bad request", { status: 400 })
  const { hooks } = await plugin(null)
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const flow = patMethod.authorize({ pat: "pt-bad" })
  const err = await flow.callback().catch((e) => e)
  expect(err).toBeInstanceOf(Error)
  expect(err.message).toContain("refused the PAT")
})

test("qoder: PAT sign-in fails when no user id", async () => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname === "/api/v1/jobToken/exchange") return json({ token: "jt-x", refresh_token: "jrt-x", expires_in: 86400000 })
    if (u.pathname === "/api/v1/userinfo") return json({ email: "no-id@example.com" })
    return new Response("", { status: 500 })
  }
  const { hooks } = await plugin(null)
  const patMethod = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const flow = patMethod.authorize({ pat: "pt-no-id" })
  const err = await flow.callback().catch((e) => e)
  expect(err).toBeInstanceOf(Error)
  expect(err.message).toContain("user id")
})

const patCredential = (over = {}) => ({
  type: "oauth",
  access: "jt-old",
  refresh: "jrt-old",
  expires: Date.now() - 1000,
  uid: "user-re",
  email: "re@example.com",
  accountId: "re@example.com",
  name: "",
  machineId: "machine-1",
  deviceToken: "",
  deviceRefresh: "",
  patAuth: true,
  pat: "pt-reexchange",
  ...over,
})

// the exchange and refresh endpoints a renew through the real path meets,
// shared by the tests below
function mockRenew() {
  const calls = []
  let exchangeCount = 0
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url))
    calls.push(u.host + u.pathname + (init.body ? " " + init.body : ""))
    if (u.host === "openapi.qoder.sh" && u.pathname === "/api/v1/jobToken/refresh") {
      return json({ message: "refresh token expired" }, 401)
    }
    if (u.pathname === "/api/v1/jobToken/exchange") {
      exchangeCount++
      return json({ token: `jt-exchange-${exchangeCount}`, refresh_token: `jrt-exchange-${exchangeCount}`, expires_in: 86400000 })
    }
    if (u.pathname === "/api/v1/userinfo") {
      return json({ id: "user-re", email: "re@example.com" })
    }
    if (u.pathname === "/sash/api/v2/me/usage") {
      return json({ displayMode: "qoder", qoderUsage: { userType: "pro", userQuota: { name: "Credits", total: 100, used: 10, unit: "credits" } } })
    }
    return new Response("", { status: 500 })
  }
  return { calls, exchanged: () => exchangeCount }
}

test("qoder: lapsed job refresh re-exchanges the stored PAT on the real path", async () => {
  const mock = mockRenew()
  const { hooks, get } = await plugin(patCredential())
  const out = await hooks.auth.usage(get)
  // the exchange was asked with the stored PAT, not a prompt's
  expect(mock.calls.some((c) => c.startsWith("openapi.qoder.sh/api/v1/jobToken/exchange ") && c.endsWith('"personal_token":"pt-reexchange"}'))).toBe(true)
  expect(mock.exchanged()).toBe(1)
  // the usage request went on with the new job token
  const usage = mock.calls.find((c) => c.startsWith("openapi.qoder.sh/sash/api/v2/me/usage"))
  expect(usage).toBe("openapi.qoder.sh/sash/api/v2/me/usage")
  expect(out).toEqual({
    plan: "pro",
    windows: [{ name: "Credits", used: 10, display: "10 / 100 credits" }],
    signIn: "renewed",
  })
  // the saved credential is the renewed one, still carrying the PAT
  const saved = await get()
  expect(saved.access).toBe("jt-exchange-1")
  expect(saved.refresh).toBe("jrt-exchange-1")
  expect(saved.patAuth).toBe(true)
  expect(saved.pat).toBe("pt-reexchange")
})

test("qoder: lapsed job refresh without a stored PAT surfaces sign-in gone", async () => {
  const mock = mockRenew()
  const { pat, ...noPat } = patCredential()
  const { hooks, get } = await plugin(noPat)
  const out = await hooks.auth.usage(get)
  // no re-exchange without a PAT to re-exchange
  expect(mock.exchanged()).toBe(0)
  expect(out.error).toContain("sign-in has expired")
  expect(out.signIn).toBe("expired")
  // the store was left as it was
  expect((await get()).access).toBe("jt-old")
})

test("qoder: PAT account usage reads the usage endpoint with the job token", async () => {
  let auth = ""
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url))
    if (u.pathname === "/sash/api/v2/me/usage") {
      auth = init.headers.Authorization
      return json({ displayMode: "qoder", qoderUsage: { userType: "pro", userQuota: { name: "Credits", total: 200, used: 50, unit: "credits" } } })
    }
    return new Response("", { status: 500 })
  }
  const live = patCredential({ access: "jt-live", expires: Date.now() + 86400000 })
  const { hooks } = await plugin(live)
  const out = await hooks.auth.usage(async () => live)
  expect(auth).toBe("Bearer jt-live")
  expect(out).toEqual({
    plan: "pro",
    windows: [{ name: "Credits", used: 25, display: "50 / 200 credits" }],
    signIn: "kept",
  })
})

test("qoder: PAT account usage surfaces a refused job token", async () => {
  globalThis.fetch = async () => json({ message: "unauthorized" }, 401)
  const live = patCredential({ access: "jt-live", expires: Date.now() + 86400000 })
  const { hooks } = await plugin(live)
  const out = await hooks.auth.usage(async () => live)
  expect(out.error).toBe("qoder usage: upstream HTTP 401")
  expect(out.signIn).toBe("kept")
  expect(out.plan).toBeUndefined()
})

test("qoder: a refused PAT re-exchange ends the sign-in", async () => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname === "/api/v1/jobToken/refresh") return json({ message: "refresh token expired" }, 401)
    if (u.pathname === "/api/v1/jobToken/exchange") return json({ message: "PAT expired" }, 401)
    return new Response("", { status: 500 })
  }
  const { hooks, get } = await plugin(patCredential())
  const out = await hooks.auth.usage(get)
  expect(out.signIn).toBe("expired")
  expect(out.error).toContain("sign in again")
  const l = await hooks.auth.loader(get)
  const res = await l.fetch(l.baseURL + "/chat/completions", { method: "POST", body: JSON.stringify({ model: "efficient" }) })
  expect(res.status).toBe(401)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("expired")
})

test("qoder-cn: a non-phone account keeps one name through sign-in, renewal and sign-in again (review #487, A)", async () => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname === "/api/v1/jobToken/exchange") return json({ token: "jt-1", refresh_token: "jrt-1", expires_in: 86400000 })
    if (u.pathname === "/api/v1/jobToken/refresh") return json({ token: "jt-2", refresh_token: "jrt-2", expires_in: 86400000 })
    if (u.pathname === "/api/v1/userinfo") return json({ id: "same-user", name: "Someone" })
    return new Response("", { status: 500 })
  }
  const hooks = await QoderCNAuthPlugin({ client: { auth: { set: async () => {} } } })
  const pat = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const first = await pat.authorize({ pat: "pt-x" }).callback()
  expect(first.accountId).toBe("same-user")
  // a renewal must not rename it: no phone, so the name the sign-in gave stays
  const renewed = await hooks.auth.refresh({ ...first, type: "oauth", expires: Date.now() + 1_000 })
  expect(renewed.accountId).toBeUndefined()
  // 没有手机号也没有邮箱：续期不改名字，也不给 cardName
  expect(renewed.cardName).toBeUndefined()
  const again = await pat.authorize({ pat: "pt-x" }).callback()
  expect(again.accountId).toBe("same-user")
})

test("qoder-cn: an email account with a phone bound keeps its email, here and on renewal (review #487, B)", async () => {
  globalThis.fetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname === "/api/v1/jobToken/exchange") return json({ token: "jt-e", refresh_token: "jrt-e", expires_in: 86400000 })
    if (u.pathname === "/api/v1/jobToken/refresh") return json({ token: "jt-e2", refresh_token: "jrt-e2", expires_in: 86400000 })
    if (u.pathname === "/api/v1/userinfo")
      return json({ id: "u-e", email: "bob@example.com", security_mobile: "13800138000" })
    return new Response("", { status: 500 })
  }
  const hooks = await QoderCNAuthPlugin({ client: { auth: { set: async () => {} } } })
  const pat = hooks.auth.methods.find((m) => m.label?.includes("PAT"))
  const first = await pat.authorize({ pat: "pt-e" }).callback()
  expect(first.accountId).toBe("bob@example.com")
  expect(first.cardName).toBe("bob@example.com")
  const renewed = await hooks.auth.refresh({ ...first, type: "oauth", expires: Date.now() + 1_000 })
  expect(renewed.accountId).toBeUndefined()
  // 卡片名也保持邮箱：续期不能把它换成手机号
  expect(renewed.cardName).toBe("bob@example.com")
  expect(renewed.phoneLabel).toBe("138****8000")
})
