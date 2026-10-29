// auth.usage tells what magpie's built-in Qoder account shows
// (internal/provider/qoder_usage.go), against Qoder's replies as its tests
// give them (qoder_test.go).
import { afterEach, expect, test } from "bun:test"
import { QoderAuthPlugin, _internal } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => (globalThis.fetch = real))

const USAGE = {
  displayMode: "qoder",
  qoderUsage: {
    userType: "pro",
    userQuota: { total: 100, used: 25 },
    addOnQuota: { cap: 50, remaining: 40 },
    orgResourcePackage: { total: 20, used: 10 },
    dedicatedResourcePackages: [{ name: "Team", total: 10, used: 2 }],
  },
}

const account = () => ({
  type: "oauth",
  access: "jt-one",
  refresh: "rt-one",
  expires: Date.now() + 3_600_000,
  accountId: "one@x",
  uid: "u1",
  deviceToken: "dt-old",
  deviceRefresh: "drt-old",
})

async function plugin(serve) {
  let auth = account()
  const seen = []
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url))
    seen.push(u.pathname)
    return serve(u.pathname, init)
  }
  const client = { auth: { set: async ({ body }) => (auth = body) } }
  const hooks = await QoderAuthPlugin({ client })
  return { usage: () => hooks.auth.usage(async () => auth), seen, auth: () => auth }
}

const json = (v, status = 200) => new Response(JSON.stringify(v), { status })
const API_CHAT = "https://api3.qoder.sh/v1/chat/completions"

test("a refused device token is rotated, saved, and the usage read with it", async () => {
  const p = await plugin((path, init) => {
    if (path === "/api/v1/deviceToken/refresh") {
      expect(JSON.parse(init.body)).toEqual({ refresh_token: "drt-old" })
      return json({ device_token: "dt-new", refresh_token: "drt-new" })
    }
    if (path === "/sash/api/v2/me/usage") {
      expect(init.headers["Cosy-ClientType"]).toBe("10")
      return init.headers.Authorization === "Bearer dt-new" ? json(USAGE) : new Response("", { status: 401 })
    }
    return new Response("", { status: 404 })
  })
  expect(await p.usage()).toEqual({
    plan: "pro",
    windows: [
      { name: "Total credits", used: (100 * 45) / 170, display: "45 / 170 credits" },
      { name: "Credits", used: 25, display: "25 / 100 credits", aside: true },
      { name: "Add-on credits", used: 20, display: "10 / 50 credits", aside: true },
      { name: "Shared credits", used: 50, display: "10 / 20 credits", aside: true },
      { name: "Team", used: 20, display: "2 / 10 credits" },
    ],
    signIn: "kept",
  })
  expect(p.seen).toEqual(["/sash/api/v2/me/usage", "/api/v1/deviceToken/refresh", "/sash/api/v2/me/usage"])
  expect(p.auth()).toMatchObject({ deviceToken: "dt-new", deviceRefresh: "drt-new", access: "jt-one", refresh: "rt-one" })
})

test("a refused device refresh says usage is unavailable, chat still working", async () => {
  const p = await plugin((path) => new Response("", { status: path === "/api/v1/deviceToken/refresh" ? 403 : 401 }))
  expect(await p.usage()).toEqual({
    error:
      "Qoder usage is unavailable: Qoder refused the account-page sign-in (chat still works) — sign in again to see usage (qoder device token refresh: upstream HTTP 403)",
    signIn: "kept",
  })
  expect(p.auth().deviceToken).toBe("dt-old")
})

test("another failure is Qoder's status", async () => {
  const p = await plugin(() => new Response("", { status: 500 }))
  expect(await p.usage()).toEqual({ error: "qoder usage: upstream HTTP 500", signIn: "kept" })
})

test("an enterprise account has a plan and no windows", async () => {
  const p = await plugin(() => json({ displayMode: "enterprise" }))
  expect(await p.usage()).toEqual({ plan: "Enterprise", signIn: "kept" })
})

test("an unknown display mode, or no quota, is an error", async () => {
  let p = await plugin(() => json({ displayMode: "team" }))
  expect(await p.usage()).toEqual({ error: "qoder usage: unknown display mode", signIn: "kept" })
  p = await plugin(() => json({ displayMode: "qoder", qoderUsage: null }))
  expect(await p.usage()).toEqual({ error: "qoder usage: missing quota data", signIn: "kept" })
})

test("snake_case fields, an expiry, units, and pools too thin to show", () => {
  const u = _internal.parseUsage({
    displayMode: "qoder",
    qoderUsage: {
      user_type: "Pro Trial",
      expires_at: 1790812800, // seconds
      user_quota: { total: 2000000, remaining: 500000, unit: "tokens" },
      add_on_quota: { total: 0, used: 0 }, // no total
      org_resource_package: { total: 10 }, // neither used nor remaining
      dedicated_resource_packages: [{ total: 5, used: 9 }, { total: 5, remaining: 9 }, { total: "5", used: 1 }],
    },
  })
  expect(u).toEqual({
    plan: "Pro Trial",
    until: "2026-10-01T00:00:00.000Z",
    windows: [
      { name: "Credits", used: 75, display: "1.5e+06 / 2e+06 tokens" },
      { name: "Dedicated credits", used: 100, display: "9 / 5 credits" },
    ],
  })
  expect(_internal.when("2026-10-01T08:00:00+08:00")).toBe("2026-10-01T00:00:00.000Z")
  expect(_internal.when(1790812800000)).toBe("2026-10-01T00:00:00.000Z")
  expect(_internal.when("1790812800")).toBe("2026-10-01T00:00:00.000Z")
  expect(_internal.when(0)).toBeUndefined()
})

// magpie-community/plugins#454 (chansee97): a Qoder CN trial whose plan's
// 300 credits are spent, with 245 of 1,100 add-on credits used, read 0% left
// in Routing. Qoder spends the add-on credits once the plan's are gone, so
// the account has 855 of 1,400 left.
test("a spent plan beside add-on credits left is no account used up (#454)", () => {
  const u = _internal.parseUsage({
    displayMode: "qoder",
    qoderUsage: {
      userType: "personal_professional_trial",
      usageType: "credits",
      isQuotaExceeded: false,
      userQuota: { total: 300, used: 300, remaining: 0, percentage: 1, unit: "credits" },
      addOnQuota: { total: 1100, used: 245, remaining: 855, percentage: 0.22, unit: "credits" },
    },
  })
  expect(u.windows).toEqual([
    { name: "Total credits", used: (100 * 545) / 1400, display: "545 / 1400 credits" },
    { name: "Credits", used: 100, display: "300 / 300 credits", aside: true },
    { name: "Add-on credits", used: (100 * 245) / 1100, display: "245 / 1100 credits", aside: true },
  ])
  // what routing counts: the windows not set aside
  const counted = u.windows.filter((w) => !w.aside)
  expect(counted.map((w) => Math.round(100 - w.used))).toEqual([61])
})

test("one pool alone is shown as before, with nothing set aside", () => {
  // the owner's account (2026-10-28, read-only): a plan of 0 and add-on credits
  const u = _internal.parseUsage({
    displayMode: "qoder",
    qoderUsage: {
      userType: "personal_standard",
      totalUsagePercentage: 0.02,
      userQuota: { total: 0, used: 0, remaining: 0, percentage: 0, unit: "credits" },
      addOnQuota: { total: 600, used: 7, remaining: 593, percentage: 0.02, unit: "credits" },
    },
  })
  expect(u.windows).toEqual([{ name: "Add-on credits", used: (100 * 7) / 600, display: "7 / 600 credits" }])
})

test("pools in different units are not added up", () => {
  const u = _internal.parseUsage({
    displayMode: "qoder",
    qoderUsage: { userQuota: { total: 100, used: 100, unit: "tokens" }, addOnQuota: { total: 50, used: 0, unit: "credits" } },
  })
  expect(u.windows).toEqual([
    { name: "Credits", used: 100, display: "100 / 100 tokens" },
    { name: "Add-on credits", used: 0, display: "0 / 50 credits" },
  ])
})

// the loader's fetch, as OpenCode's engine calls it, against a listing and
// a chat reply
// a refresh is answered with a new pair, counted in refreshes: a refused
// job token is renewed once before the refusal is said (plugins#474)
async function chat(listing, reply) {
  const auth = { ...account(), machineId: "m1", name: "One" }
  const refreshes = []
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url))
    if (u.pathname.endsWith("/model/list")) return json(listing)
    if (u.pathname === "/api/v1/jobToken/refresh") {
      refreshes.push(JSON.parse(init.body).refresh_token)
      return json({ token: "jt-two", refresh_token: "rt-two", expires_in: 3_600_000 })
    }
    return reply()
  }
  const hooks = await QoderAuthPlugin({ client: { auth: { set: async () => {} } } })
  const l = await hooks.auth.loader(async () => auth)
  return { fetch: l.fetch, hooks, auth, refreshes }
}

const LISTING = {
  chat: [
    { key: "qmodel", display_name: "Q", enable: true, max_input_tokens: 1000 },
    { key: "fmodel", display_name: "F", enable: true, is_free: true },
    { key: "pmodel", display_name: "P", enable: true, price_factor: 0 },
    { key: "cmodel", display_name: "C", enable: true, priceFactor: 0.5 },
  ],
}

const ASK = { method: "POST", body: JSON.stringify({ model: "qmodel", messages: [{ role: "user", content: "hi" }] }) }

// Refused again after the one renewal a refusal gets: the job token was
// renewed (the account's mark comes off, as the built-in's renewal took it
// off), and the refusal is said as the built-in's 401, never "expired".
test("a refused chat, 401 or 403, is the built-in's 401 and leaves the account unmarked", async () => {
  for (const status of [401, 403]) {
    const { fetch, refreshes } = await chat(LISTING, () => new Response("", { status }))
    const res = await fetch(API_CHAT, ASK)
    expect(res.status).toBe(401)
    expect(res.headers.get("X-Magpie-Sign-In")).toBe("renewed")
    expect((await res.json()).error.message).toBe("the sign-in lapsed — sign in again")
    expect(refreshes).toEqual(["rt-one"])
  }
  // what Qoder says of the refusal is kept: a 401 just after signing in
  // has some other reason, and only Qoder's words tell it
  const said = await chat(LISTING, () => new Response(JSON.stringify({ message: "device not trusted" }), { status: 401 }))
  const r = await said.fetch(API_CHAT, ASK)
  expect([r.status, r.headers.get("X-Magpie-Sign-In")]).toEqual([401, "renewed"])
  expect((await r.json()).error.message).toBe("the sign-in lapsed — sign in again (Qoder said 401: device not trusted)")
  // refused in the stream, before any answer: the same
  const sse = (v) => new Response(`data: ${JSON.stringify(v)}\n\n`, { headers: { "Content-Type": "text/event-stream" } })
  const { fetch } = await chat(LISTING, () => sse({ statusCodeValue: 403, body: "" }))
  const res = await fetch(API_CHAT, ASK)
  expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([401, "renewed"])
})

test("other refusals keep their status and say nothing of the sign-in", async () => {
  for (const [status, want] of [[500, 500], [429, 429], [402, 402]]) {
    const { fetch } = await chat(LISTING, () => new Response("", { status }))
    const res = await fetch(API_CHAT, ASK)
    expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([want, null])
  }
  // an empty body is named as Go's http.StatusText names it; details may be an object
  expect(_internal.failure(502, "")).toEqual({ status: 502, message: "Bad Gateway" })
  expect(_internal.failure(400, JSON.stringify({ message: "bad", details: { error: { message: "effort" } } }))).toEqual({ status: 400, message: "bad: effort" })
})

// SlouchyQuill507 (Discord, qoder-cn): Qoder answers a failure of the model's
// own vendor behind it with a 400 "Error in upstream response". It is no
// fault of the request or the account, so it reaches magpie as a 502, which
// it asks again or of another account. A 400 that is the request's fault
// stays a 400.
test("Qoder's 400 \"Error in upstream response\" is a 502, the account unmarked", async () => {
  const UPSTREAM = "Error in upstream response"
  const sse = (v) => new Response(`data: ${JSON.stringify(v)}\n\n`, { headers: { "Content-Type": "text/event-stream" } })
  for (const [how, reply] of [
    ["an HTTP 400 with Qoder's JSON", () => new Response(JSON.stringify({ message: UPSTREAM }), { status: 400 })],
    ["an HTTP 400 in plain text", () => new Response(UPSTREAM, { status: 400 })],
    ["a 400 in the stream's envelope", () => sse({ headers: {}, body: JSON.stringify({ message: UPSTREAM }), statusCodeValue: 400, statusCode: "BAD_REQUEST" })],
    ["a 400 in the envelope as plain text", () => sse({ headers: {}, body: UPSTREAM, statusCodeValue: 400, statusCode: "BAD_REQUEST" })],
  ]) {
    const { fetch } = await chat(LISTING, reply)
    const res = await fetch(API_CHAT, ASK)
    expect([how, res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([how, 502, null])
    expect((await res.json()).error.message).toBe(UPSTREAM)
  }
  expect(_internal.failure(400, JSON.stringify({ code: "500", message: UPSTREAM }))).toEqual({ status: 502, message: UPSTREAM, signIn: "" })
  // a request Qoder refuses as the request's fault stays a 400
  expect(_internal.failure(400, JSON.stringify({ message: "invalid request: messages is empty" }))).toEqual({ status: 400, message: "invalid request: messages is empty" })
  expect(_internal.failure(400, JSON.stringify({ code: "416", message: "input too long" })).status).toBe(400)
  const { fetch } = await chat(LISTING, () => new Response(JSON.stringify({ message: "invalid request" }), { status: 400 }))
  expect((await fetch(API_CHAT, ASK)).status).toBe(400)
})

test("a model list Qoder won't give is a 502, the account unmarked", async () => {
  for (const status of [401, 403, 500]) {
    const auth = { ...account(), machineId: "m1" }
    globalThis.fetch = async () => new Response("no", { status })
    const hooks = await QoderAuthPlugin({ client: { auth: { set: async () => {} } } })
    const l = await hooks.auth.loader(async () => auth)
    const res = await l.fetch(API_CHAT, ASK)
    expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([502, null])
    expect((await res.json()).error.message).toBe(`Qoder models: HTTP ${status}: no`)
  }
})

test("a network failure fetching the model list is a 502 so magpie can fall back", async () => {
  const auth = { ...account(), machineId: "m1" }
  globalThis.fetch = async () => {
    throw new Error("getaddrinfo ENOTFOUND api3.qoder.sh")
  }
  const hooks = await QoderAuthPlugin({ client: { auth: { set: async () => {} } } })
  const l = await hooks.auth.loader(async () => auth)
  const res = await l.fetch(API_CHAT, ASK)
  expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([502, null])
  expect((await res.json()).error.message).toBe("getaddrinfo ENOTFOUND api3.qoder.sh")
})

// the loader's fetch for an account whose job token is due, the refresh answered by refresh()
async function due(refresh, fields = {}) {
  const auth = { ...account(), machineId: "m1", expires: 0, ...fields }
  globalThis.fetch = async (url) => (new URL(String(url)).pathname === "/api/v1/jobToken/refresh" ? refresh() : new Response("", { status: 500 }))
  const hooks = await QoderAuthPlugin({ client: { auth: { set: async () => {} } } })
  const l = await hooks.auth.loader(async () => auth)
  return l.fetch(API_CHAT, ASK)
}

test("a refresh Qoder refuses (401 or 403) marks the account lapsed, as qoderRefreshFailed did", async () => {
  for (const status of [401, 403]) {
    const res = await due(() => new Response("", { status }))
    expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([401, "expired"])
    expect((await res.json()).error.message).toBe(`one@x's Qoder sign-in has expired — sign in again (qoder job token refresh: status ${status})`)
  }
})

test("no refresh token is a 401 the built-in didn't mark; a refresh that failed otherwise is a 502", async () => {
  let res = await due(() => new Response("", { status: 401 }), { refresh: "" })
  expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([401, "kept"])
  res = await due(() => new Response("", { status: 500 }))
  expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([502, null])
  expect((await res.json()).error.message).toBe("qoder job token refresh: status 500")
})

test("errors don't name Qoder, which magpie adds", async () => {
  expect(_internal.failure(500, JSON.stringify({ message: "boom" }))).toEqual({ status: 500, message: "boom" })
  const { fetch } = await chat(LISTING, () => new Response("", { status: 500 }))
  let res = await fetch(API_CHAT, { method: "POST", body: JSON.stringify({ model: "nomodel", messages: [] }) })
  expect((await res.json()).error.message).toBe('unknown or disabled model "nomodel"')
  res = await fetch("https://api3.qoder.sh/v1/responses", { method: "POST", body: "{}" })
  expect((await res.json()).error.message).toBe("only chat completions are served")
  const gone = await QoderAuthPlugin({ client: { auth: { set: async () => {} } } })
  const l = await gone.auth.loader(async () => ({ type: "oauth" }))
  res = await l.fetch(API_CHAT, { method: "POST", body: JSON.stringify({ model: "qmodel", messages: [] }) })
  expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([401, "kept"])
  expect((await res.json()).error.message).toBe("not signed in")
})

test("a model at a price_factor of 0 is marked free; is_free only counts with no price", async () => {
  const { hooks, auth } = await chat(LISTING, () => new Response(""))
  const ms = await hooks.provider.models({ models: {} }, { auth })
  expect(Object.fromEntries(Object.entries(ms).map(([k, m]) => [k, m.free]))).toEqual({ qmodel: false, fmodel: true, pmodel: true, cmodel: false })
  expect(_internal.modelInfo({ key: "x", isFree: true }).free).toBe(true)
})

// Qoder's listing as it came on 2026-10-02 (the built-in's saved one): its
// app shows Qwen3.8-Max at 0.5× with an off-peak badge, Qwen3.8-Flash at 0×
// with 0.1× struck through — both carry is_free true.
const OFF_PEAK = {
  active: false,
  badge: { en: "Off-Peak 60% off", zh: "错峰 4 折" },
  description: { en: "Off-Peak 60% off (10 PM-8 AM UTC+8)", zh: "错峰时段4折优惠（10 PM-8 AM UTC+8）" },
  timezone: "Asia/Singapore",
  rule_id: "idle_time_model_credit_discount",
  discount_factor: 0.4,
  before_promotion_price_factor: 0.5,
  window_start: "22:00",
  window_end: "08:00",
}
const PRICED = {
  chat: [
    { key: "qmodel_38max", display_name: "Qwen3.8-Max", enable: true, is_reasoning: true, price_factor: 0.5, is_free: true, promotion: OFF_PEAK },
    { key: "qfmodel", display_name: "Qwen3.8-Flash", enable: true, is_reasoning: true, price_factor: 0.0, original_price_factor: 0.1, is_free: true },
    { key: "qmodel_latest", display_name: "Qwen3.7-Max", enable: true, price_factor: 0.5, original_price_factor: 0.5 },
    { key: "kmodel_latest", display_name: "Kimi-K3", enable: true, price_factor: 1.4, is_free: false },
    // 0 only while an active promotion lasts, with a price before it
    { key: "window", display_name: "W", enable: true, price_factor: 0, is_free: true, promotion: { ...OFF_PEAK, active: true, discount_factor: 0.0001, before_promotion_price_factor: 0.5 } },
    // a promotion over, or one that had nothing to take off
    { key: "over", display_name: "O", enable: true, price_factor: 0, promotion: { ...OFF_PEAK, active: false } },
    { key: "nothing", display_name: "N", enable: true, price_factor: 0, promotion: { ...OFF_PEAK, active: true, before_promotion_price_factor: 0 } },
    // no price: is_free says it
    { key: "unpriced", display_name: "U", enable: true, is_free: true },
    { key: "unpriced2", display_name: "U2", enable: true, is_free: false },
  ],
}

test("a discount is not free: Qwen3.8-Max (0.5×, is_free true) is priced, Qwen3.8-Flash (0×) is free", async () => {
  const { hooks, auth } = await chat(PRICED, () => new Response(""))
  const ms = await hooks.provider.models({ models: {} }, { auth })
  expect(Object.fromEntries(Object.entries(ms).map(([k, m]) => [k, m.free]))).toEqual({
    qmodel_38max: false,
    qfmodel: true,
    qmodel_latest: false,
    kmodel_latest: false,
    window: false,
    over: true,
    nothing: true,
    unpriced: true,
    unpriced2: false,
  })
  expect(_internal.modelInfo({ key: "x", priceFactor: 0.5, isFree: true }).free).toBe(false)
  expect(_internal.modelInfo({ key: "x", priceFactor: 0, promotion: { active: true, beforePromotionPriceFactor: 1 } }).free).toBe(false)
})

// Each model carries its price as Qoder's client shows it beside the model,
// as magpie's built-in reads it (internal/qoder/models_test.go,
// TestParseModelsRate): Qwen3.8-Max 0.5×, Kimi-K3 1.4×, Qwen3.8-Flash 0×
// with 0.1× struck through; a running promotion's price before it struck
// through, and its 0 that isn't free read as that price times its
// discount. A listing with no price gives none.
test("each model's rate, and its price before a running discount", async () => {
  const RATED = {
    chat: [
      { key: "qmodel_38max", enable: true, price_factor: 0.5, is_free: true, promotion: OFF_PEAK },
      { key: "qmodel_38max-offpeak", enable: true, price_factor: 0.2, promotion: { ...OFF_PEAK, active: true } },
      { key: "qfmodel", enable: true, price_factor: 0.0, original_price_factor: 0.1, is_free: true },
      { key: "qmodel_latest", enable: true, price_factor: 0.5, original_price_factor: 0.5 },
      { key: "kmodel_latest", enable: true, priceFactor: 1.4, originalPriceFactor: 2 },
      { key: "window", enable: true, price_factor: 0, promotion: { active: true, discount_factor: 0.5, before_promotion_price_factor: 1 } },
      { key: "window-camel", enable: true, priceFactor: 0, promotion: { active: true, discountFactor: 0.25, beforePromotionPriceFactor: 2 } },
      { key: "unpriced", enable: true, is_free: true },
    ],
  }
  const { hooks, auth } = await chat(RATED, () => new Response(""))
  const ms = await hooks.provider.models({ models: {} }, { auth })
  expect(Object.fromEntries(Object.entries(ms).map(([k, m]) => [k, [m.rate, m.rateWas]]))).toEqual({
    qmodel_38max: [0.5, 0],
    "qmodel_38max-offpeak": [0.2, 0.5],
    qfmodel: [0, 0.1],
    qmodel_latest: [0.5, 0],
    kmodel_latest: [1.4, 2],
    window: [0.5, 1],
    "window-camel": [0.5, 2],
    unpriced: [0, 0],
  })
  expect(ms.qfmodel.free).toBe(true)
  expect(ms.window.free).toBe(false)
})

// a usage read on an account whose job token is due, the refresh answered by refresh()
async function dueUsage(refresh, read) {
  let auth = { ...account(), expires: 0 }
  globalThis.fetch = async (url) => {
    const path = new URL(String(url)).pathname
    if (path === "/api/v1/jobToken/refresh") return refresh()
    if (path === "/sash/api/v2/me/usage") return read()
    return new Response("", { status: 404 })
  }
  const hooks = await QoderAuthPlugin({ client: { auth: { set: async ({ body }) => (auth = body) } } })
  return hooks.auth.usage(async () => auth)
}

const RENEWED = () => json({ token: "jt-new", refresh_token: "rt-new", expire_time: Date.now() + 3_600_000 })

test("a usage read marks the sign-in only on a refused job refresh and clears it only on a renewed one, as the built-in's", async () => {
  // a clean read cleared nothing in the built-in
  expect((await dueUsage(RENEWED, () => json(USAGE))).signIn).toBe("renewed")
  expect((await (await plugin(() => json(USAGE))).usage()).signIn).toBe("kept")
  // renewed, the mark came off whatever the read then met
  expect(await dueUsage(RENEWED, () => new Response("", { status: 500 }))).toEqual({ error: "qoder usage: upstream HTTP 500", signIn: "renewed" })
  for (const status of [401, 403]) {
    const u = await dueUsage(() => new Response("", { status }), () => json(USAGE))
    expect(u).toEqual({ error: `one@x's Qoder sign-in has expired — sign in again (qoder job token refresh: status ${status})`, signIn: "expired" })
  }
  expect((await dueUsage(() => new Response("", { status: 500 }), () => json(USAGE))).signIn).toBe("kept")
})

// a chat on an account whose job token is due, renewed, Qoder answering reply()
async function renewedChat(reply) {
  const auth = { ...account(), machineId: "m1", expires: 0 }
  globalThis.fetch = async (url) => {
    const path = new URL(String(url)).pathname
    if (path === "/api/v1/jobToken/refresh") return RENEWED()
    if (path.endsWith("/model/list")) return json(LISTING)
    return reply()
  }
  const hooks = await QoderAuthPlugin({ client: { auth: { set: async () => {} } } })
  const l = await hooks.auth.loader(async () => auth)
  return l.fetch(API_CHAT, ASK)
}

const OK = () =>
  new Response(`data: ${JSON.stringify({ statusCodeValue: 200, body: JSON.stringify({ choices: [{ delta: { content: "hi" }, finish_reason: "stop" }] }) })}\n\n`, {
    headers: { "Content-Type": "text/event-stream" },
  })

test("an answer that went through keeps the mark, as the built-in's did; after a renewed job token, every answer clears it", async () => {
  const { fetch } = await chat(LISTING, OK)
  let res = await fetch(API_CHAT, ASK)
  expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([200, "kept"])
  expect((await res.json()).choices[0].message.content).toBe("hi")
  for (const [reply, status] of [[OK, 200], [() => new Response("", { status: 500 }), 500], [() => new Response("", { status: 401 }), 401]]) {
    res = await renewedChat(reply)
    expect([res.status, res.headers.get("X-Magpie-Sign-In")]).toEqual([status, "renewed"])
  }
})

// the models hook, as the built-in's listing (qoderFetchModels through
// QoderCredentialOf) treated the sign-in: a refused job refresh marks it
// (thrown with signIn "expired"), a renewal clears it (said by the account's
// next usage read or answer), and nothing else marks it
async function dueModels(refresh, listing = () => json(LISTING)) {
  let auth = { ...account(), expires: 0, machineId: "m1", name: "One" }
  globalThis.fetch = async (url) => {
    const path = new URL(String(url)).pathname
    if (path === "/api/v1/jobToken/refresh") return refresh()
    if (path.endsWith("/model/list")) return listing()
    if (path === "/sash/api/v2/me/usage") return json(USAGE)
    return new Response("", { status: 404 })
  }
  const hooks = await QoderAuthPlugin({ client: { auth: { set: async ({ body }) => (auth = { ...body }) /* saved, then read back, as magpie does */ } } })
  const fallback = { models: { stat: { id: "stat" } } }
  return { hooks, fallback, list: () => hooks.provider.models(fallback, { auth }), usage: () => hooks.auth.usage(async () => auth) }
}

for (const status of [401, 403]) {
  test(`a job refresh refused ${status} while listing models throws signIn "expired"`, async () => {
    const m = await dueModels(() => new Response("", { status }))
    const err = await m.list().catch((e) => e)
    expect(err).toBeInstanceOf(Error)
    expect(err.signIn).toBe("expired")
    expect(err.message).toContain("sign-in has expired")
  })
}

test("a listing whose refresh fails otherwise, or has no refresh token, marks nothing", async () => {
  let m = await dueModels(() => new Response("", { status: 500 }))
  expect(await m.list()).toBe(m.fallback.models)
  m = await dueModels(RENEWED, () => new Response("", { status: 401 }))
  // the refresh went through: the refused listing marks nothing
  expect(await m.list()).toBe(m.fallback.models)
  const hooks = await QoderAuthPlugin({ client: { auth: { set: async () => {} } } })
  const fb = { models: {} }
  expect(await hooks.provider.models(fb, { auth: { ...account(), refresh: "", expires: 0 } })).toBe(fb.models)
})

test("a job token the models hook renewed is said renewed by the next usage read, once", async () => {
  const m = await dueModels(RENEWED)
  const ms = await m.list()
  expect(Object.keys(ms)).toEqual(["qmodel", "fmodel", "pmodel", "cmodel"])
  expect((await m.usage()).signIn).toBe("renewed")
  expect((await m.usage()).signIn).toBe("kept")
})

test("a job token the models hook renewed is said renewed by the next answer", async () => {
  const m = await dueModels(RENEWED)
  await m.list()
  const l = await m.hooks.auth.loader(async () => ({ ...account(), machineId: "m1" }))
  const res = await l.fetch(API_CHAT, { method: "POST", body: JSON.stringify({ model: "nomodel", messages: [] }) })
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("renewed")
  const again = await l.fetch(API_CHAT, { method: "POST", body: JSON.stringify({ model: "nomodel", messages: [] }) })
  expect(again.headers.get("X-Magpie-Sign-In")).toBe(null)
})

// Ariel on Discord: an international free account (personal_standard) signed
// in but showed no credits. Its envelope is the owner's free account's
// (2026-10-28, read-only) with no add-on credits: a plan of 0 beside add-on
// credits of 0, or none at all. Qoder's client shows it 0/0, out of credits.
test("a free account with no credits shows none left, not nothing", () => {
  const free = (extra) => ({
    displayMode: "qoder",
    qoderUsage: {
      userType: "personal_standard",
      usageType: "credits",
      totalUsagePercentage: 0,
      isQuotaExceeded: true,
      expiresAt: 253402214400000,
      userQuota: { total: 0, used: 0, remaining: 0, percentage: 0, unit: "credits" },
      ...extra,
      isPlanQuotaProrated: false,
    },
  })
  const none = [{ name: "Credits", used: 100, display: "0 credits left" }]
  expect(_internal.parseUsage(free({})).windows).toEqual(none)
  expect(_internal.parseUsage(free({ addOnQuota: { total: 0, used: 0, remaining: 0, percentage: 0, unit: "credits" } })).windows).toEqual(none)
  // a pool that can't be read is no word that the account has none
  expect(_internal.parseUsage({ displayMode: "qoder", qoderUsage: { userType: "personal_standard", userQuota: { total: "0" } } }).windows).toEqual([])
  expect(_internal.parseUsage({ displayMode: "qoder", qoderUsage: { userType: "personal_standard" } }).windows).toEqual([])
})

test("usage's user is the card's name, and the accountId stays the identity (review #487, round 3)", async () => {
  let auth = { ...account(), accountId: "one@x", cardName: "138****8000", phoneLabel: "138****8000" }
  globalThis.fetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname === "/sash/api/v2/me/usage") return json(USAGE)
    if (u.pathname === "/api/v1/deviceToken/refresh") return json({ token: "dt-new", refresh_token: "drt-new" })
    return new Response("", { status: 404 })
  }
  const hooks = await QoderAuthPlugin({ client: { auth: { set: async ({ body }) => (auth = body) } } })
  const u = await hooks.auth.usage(async () => auth)
  expect(u.user).toBe("138****8000")
  expect(auth.accountId).toBe("one@x")
})
