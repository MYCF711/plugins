// auth.refresh, magpie's hook for renewing a sign-in ahead of its end, on
// both sites: what it gives, that it shares a refresh token's one spending
// with a request's own refresh, and what a failure says.
import { afterEach, expect, test } from "bun:test"
import { QoderAuthPlugin, QoderCNAuthPlugin } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => (globalThis.fetch = real))

const json = (v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } })

const SITES = [
  { name: "qoder", plugin: QoderAuthPlugin, openapi: "openapi.qoder.sh" },
  { name: "qoder-cn", plugin: QoderCNAuthPlugin, openapi: "openapi.qoder.com.cn" },
]

const account = (over = {}) => ({
  type: "oauth",
  access: "jt-1",
  refresh: "jrt-1",
  expires: Date.now() + 60_000,
  accountId: "one@x",
  uid: "u1",
  machineId: "m1",
  deviceToken: "dt-1",
  deviceRefresh: "drt-1",
  ...over,
})

// serve answers the refresh calls, counting them by path and token; any
// other call (the chat) is a 500, which is enough for a request's refresh
function serve(site, { job, device } = {}) {
  const calls = []
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url))
    const token = init.body ? JSON.parse(init.body).refresh_token : undefined
    calls.push(u.host + u.pathname + " " + token)
    if (u.host === site.openapi && u.pathname === "/api/v1/jobToken/refresh") return job ? job(token) : json({ token: "jt-2", refresh_token: "jrt-2", expires_in: 3_600_000 })
    if (u.host === site.openapi && u.pathname === "/api/v1/deviceToken/refresh")
      return device ? device(token) : json({ device_token: "dt-2", refresh_token: "drt-2", expires_at: new Date(Date.now() + 7_200_000).toISOString() })
    // the card's name: a renewal reads the user info once (the phone it shows)
    if (u.host === site.openapi && u.pathname === "/api/v1/userinfo")
      return json({ id: "u1", name: "one@x", security_mobile: "18970098051" })
    return new Response("", { status: 500 })
  }
  return calls
}

async function plugin(site, auth) {
  let stored = auth
  const sets = []
  const client = { auth: { set: async ({ body }) => (sets.push(body), (stored = body)) } }
  const hooks = await site.plugin({ client })
  return { hooks, sets, get: async () => stored }
}

for (const site of SITES) {
  test(`${site.name}: auth.refresh renews the job token and gives what changed, leaving the save to magpie`, async () => {
    const calls = serve(site)
    const { hooks, sets } = await plugin(site, account())
    expect(hooks.auth.refreshLead).toBe(10 * 60 * 1000)
    const got = await hooks.auth.refresh(account(), { id: site.name })
    expect(got).toMatchObject({ access: "jt-2", refresh: "jrt-2" })
    // the renewal also names the account (the phone, not its uuid), so an
    // account stored by an earlier version is renamed here
    expect(Object.keys(got).sort()).toEqual(["access", "accountId", "expires", "refresh"])
    expect(got.accountId).toBe("189****8051")
    expect(got.expires).toBeGreaterThan(Date.now() + 3_000_000)
    expect(sets).toEqual([])
    expect(calls.filter((c) => c.includes("Token/refresh"))).toEqual([`${site.openapi}/api/v1/jobToken/refresh jrt-1`])
  })

  test(`${site.name}: auth.refresh and a request's refresh spend the refresh token once`, async () => {
    // the hook first: a request reading the store before magpie saved it
    let calls = serve(site)
    let p = await plugin(site, account())
    const opts = await p.hooks.auth.loader(p.get)
    const [got] = await Promise.all([
      p.hooks.auth.refresh(account(), { id: site.name }),
      opts.fetch("https://x/chat/completions", { method: "POST", body: JSON.stringify({ model: "m", messages: [] }) }),
    ])
    expect(got).toMatchObject({ access: "jt-2", refresh: "jrt-2" })
    expect(calls.filter((c) => c.includes("Token/refresh"))).toEqual([`${site.openapi}/api/v1/jobToken/refresh jrt-1`])
    expect(p.sets).toEqual([])

    // the request first: the hook, handed the sign-in as it was, gives
    // what the request got
    let release
    const held = new Promise((r) => (release = r))
    calls = serve(site, { job: async () => (await held, json({ token: "jt-2", refresh_token: "jrt-2", expires_in: 3_600_000 })) })
    p = await plugin(site, account())
    const opts2 = await p.hooks.auth.loader(p.get)
    const req = opts2.fetch("https://x/chat/completions", { method: "POST", body: JSON.stringify({ model: "m", messages: [] }) })
    while (!calls.length) await new Promise((r) => setTimeout(r, 1))
    const hook = p.hooks.auth.refresh(account(), { id: site.name })
    release()
    const [, got2] = await Promise.all([req, hook])
    expect(got2).toMatchObject({ access: "jt-2", refresh: "jrt-2" })
    expect(calls.filter((c) => c.includes("Token/refresh"))).toEqual([`${site.openapi}/api/v1/jobToken/refresh jrt-1`])
    expect(p.sets.map((s) => s.refresh)).toEqual(["jrt-2"])
  })

  test(`${site.name}: a refresh Qoder refuses (401/403) is signIn "expired"; another failure throws plainly`, async () => {
    for (const status of [401, 403]) {
      serve(site, { job: () => new Response("", { status }) })
      const { hooks } = await plugin(site, account())
      const err = await hooks.auth.refresh(account(), { id: site.name }).catch((e) => e)
      expect(err.signIn).toBe("expired")
      expect(err.message).toContain("sign-in has expired")
    }
    serve(site, { job: () => new Response("", { status: 500 }) })
    const { hooks } = await plugin(site, account())
    const err = await hooks.auth.refresh(account(), { id: site.name }).catch((e) => e)
    expect(err).toBeInstanceOf(Error)
    expect(err.signIn).toBeUndefined()
    expect(err.message).toBe("qoder job token refresh: status 500")
  })

  test(`${site.name}: nothing to renew with is undefined`, async () => {
    const calls = serve(site)
    const { hooks } = await plugin(site, account())
    expect(await hooks.auth.refresh(account({ refresh: "" }), { id: site.name })).toBeUndefined()
    expect(await hooks.auth.refresh({ type: "api", key: "k" }, { id: site.name })).toBeUndefined()
    expect(calls).toEqual([])
  })
}

test("qoder-cn: a device-token account is renewed as a device token, both pairs given", async () => {
  const site = SITES[1]
  const calls = serve(site)
  const a = account({ access: "dt-1", refresh: "drt-1", deviceChat: true })
  const { hooks, sets } = await plugin(site, a)
  const got = await hooks.auth.refresh(a, { id: "qoder-cn" })
  expect(got).toMatchObject({ access: "dt-2", refresh: "drt-2", deviceToken: "dt-2", deviceRefresh: "drt-2" })
  expect(got.expires).toBeGreaterThan(Date.now() + 7_000_000)
  expect(got.type).toBeUndefined()
  expect(sets).toEqual([])
  // a device-token renewal also reads the user info once, for the card's name
  expect(calls.filter((c) => c.includes("Token/refresh"))).toEqual([`${site.openapi}/api/v1/deviceToken/refresh drt-1`])

  serve(site, { device: () => new Response("", { status: 401 }) })
  const p = await plugin(site, a)
  const err = await p.hooks.auth.refresh(a, { id: "qoder-cn" }).catch((e) => e)
  expect(err.signIn).toBe("expired")
})
