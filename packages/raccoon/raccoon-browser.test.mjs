import { afterEach, beforeEach, expect, test } from "bun:test"
import { RaccoonAuthPlugin, _internal } from "./index.mjs"

let upstream
// 任何用例都不许碰真实网络：没有 startServer() 的用例指向一个不监听的端口。
// （accountPhoneOf 会读 user_info；指向真站会让整套测试依赖外网，评审 #486 第 1 条。）
beforeEach(() => {
  process.env.RACCOON_MAIN_SITE_URL = "http://127.0.0.1:9"
})

afterEach(() => {
  upstream?.stop(true)
  upstream = undefined
  delete process.env.RACCOON_MAIN_SITE_URL
})
function fakeAuth(handler) {
  upstream = Bun.serve({port: 0, hostname: "127.0.0.1", fetch: handler})
  process.env.RACCOON_MAIN_SITE_URL = `http://127.0.0.1:${upstream.port}`
}
function tokens() {
  const claims = Buffer.from(JSON.stringify({iss: "74350b", exp: Math.floor(Date.now()/1000)+3600})).toString("base64url")
  return {access_token: `synthetic.${claims}.signature`, refresh_token: "synthetic-refresh"}
}
function callbackURL(flow, code = "synthetic-code") {
  const auth = new URL(flow.url)
  const url = new URL(auth.searchParams.get("redirect"))
  url.searchParams.set("state", auth.searchParams.get("state"))
  url.searchParams.set("code", code)
  return url
}

test("browser authorization returns automatically and completes the code exchange", async () => {
  let calls = 0
  fakeAuth(async req => {
    const path = new URL(req.url).pathname
    // the card's name: one read of the account's own phone, after the exchange
    if (path === "/api/web/auth/v1/user_info") return Response.json({code: 0, data: {phone: "13800138000", name: "RaccoonBenjamin"}})
    expect(path).toBe("/api/web/auth/v1/login_with_authorization_code")
    expect(await req.json()).toEqual({authorization_code: "synthetic-code"})
    calls++
    return Response.json({code: 0, data: tokens()})
  })
  const plugin = await RaccoonAuthPlugin({client:{}})
  const flow = await plugin.auth.methods[0].authorize()
  const auth = new URL(flow.url)
  expect(flow.method).toBe("auto")
  expect(auth.searchParams.get("desktop_callback")).toBe("loopback")
  expect(auth.searchParams.get("state")).toMatch(/^[a-f0-9]{64}$/)
  const url = callbackURL(flow)
  expect(url.hostname).toBe("127.0.0.1")
  expect(url.pathname).toBe("/auth/callback")
  expect(Number(url.port)).toBeGreaterThanOrEqual(1024)
  const done = flow.callback()
  const response = await fetch(url)
  expect(response.status).toBe(200)
  expect(response.headers.get("cache-control")).toBe("no-store")
  const page = await response.text()
  expect(page).not.toContain("synthetic-code")
  expect(page).not.toContain("synthetic-refresh")
  const signedIn = await done
  expect(signedIn.type).toBe("success")
  // `accountId` is the phone, `uid` is the id the JWT names
  expect(signedIn.phone).toBe("138****8000")
  expect(signedIn.cardName).toBe("138****8000")
  expect(calls).toBe(1)
  await expect(fetch(url)).rejects.toThrow()
})

test("bad state, missing code, wrong host, path or method never consume a pending login", async () => {
  let calls = 0
  fakeAuth(req => {
    if (new URL(req.url).pathname === "/api/web/auth/v1/user_info") return Response.json({code: 0, data: {phone: "13800138000"}})
    calls++
    return Response.json({code:0,data:tokens()})
  })
  const flow = await _internal.browserSignIn()
  const done = flow.callback()
  const good = callbackURL(flow)
  const bad = new URL(good)
  bad.searchParams.set("state", "wrong-state")
  expect((await fetch(bad)).status).toBe(400)
  bad.searchParams.set("state",new URL(flow.url).searchParams.get("state"))
  bad.searchParams.append("state","duplicate")
  expect((await fetch(bad)).status).toBe(400)
  bad.searchParams.delete("code")
  bad.searchParams.delete("state")
  bad.searchParams.set("state",good.searchParams.get("state"))
  expect((await fetch(bad)).status).toBe(400)
  const wrongPath = new URL(good); wrongPath.pathname="/other"
  expect((await fetch(wrongPath)).status).toBe(404)
  expect((await fetch(good,{method:"POST"})).status).toBe(405)
  expect((await fetch(good,{headers:{host:"attacker.invalid"}})).status).toBe(404)
  expect(calls).toBe(0)
  expect((await fetch(good)).status).toBe(200)
  expect((await done).type).toBe("success")
  expect(calls).toBe(1)
})

test("a rejected code reports failure rather than a successful browser page", async () => {
  fakeAuth(() => Response.json({code:200035},{status:400}))
  const flow=await _internal.browserSignIn()
  const done=flow.callback()
  expect((await fetch(callbackURL(flow))).status).toBe(502)
  expect(await done).toMatchObject({type:"failed",error:"授权码已失效，请重新发起网页登录"})
  await expect(fetch(callbackURL(flow))).rejects.toThrow()
})

test("denied authorization closes the listener without exchanging a code", async () => {
  fakeAuth(() => { throw new Error("must not exchange denied authorization") })
  const flow=await _internal.browserSignIn()
  const done=flow.callback()
  const url=callbackURL(flow); url.searchParams.delete("code"); url.searchParams.set("error","access_denied")
  expect((await fetch(url)).status).toBe(400)
  expect((await done).type).toBe("failed")
  await expect(fetch(url)).rejects.toThrow()
})

test("an abandoned authorization times out and closes its listener even before callback is awaited", async () => {
  const flow=await _internal.browserSignIn(25)
  const result=await flow.callback()
  expect(result).toMatchObject({type:"failed",error:"商汤小浣熊登录超时，请重新登录"})
  await expect(fetch(callbackURL(flow))).rejects.toThrow()
})

test("manual callback and token sign-in remain available without a listener", async () => {
  fakeAuth(req => {
    if (new URL(req.url).pathname === "/api/web/auth/v1/user_info") return Response.json({code: 0, data: {phone: "13800138000"}})
    return Response.json({code: 0, data: tokens()})
  })
  const plugin=await RaccoonAuthPlugin({client:{}})
  const flow=await plugin.auth.methods[2].authorize()
  expect(flow.method).toBe("code")
  const t=tokens()
  expect(await flow.callback(JSON.stringify(t))).toMatchObject({type:"success",access:t.access_token,refresh:t.refresh_token})
})


test("concurrent replay exchanges the authorization code only once", async () => {
  let calls = 0, entered
  const started = new Promise(resolve => { entered = resolve })
  fakeAuth(async req => {
    if (new URL(req.url).pathname === "/api/web/auth/v1/user_info") return Response.json({code: 0, data: {phone: "13800138000"}})
    calls++
    entered()
    await Bun.sleep(200)
    return Response.json({code: 0, data: tokens()})
  })
  const flow = await _internal.browserSignIn()
  const url = callbackURL(flow)
  const first = fetch(url)
  await started
  const second = fetch(url)
  const responses = await Promise.all([first, second])
  expect((await flow.callback()).type).toBe("success")
  expect(calls).toBe(1)
  expect(responses.map(response => response.status)).toEqual([200, 409])
})

test("invalid authorization URL rejects without leaving a listening server", async () => {
  const source = `import { _internal } from ${JSON.stringify(new URL("./index.mjs", import.meta.url).href)};
    try { await _internal.browserSignIn(); process.exitCode = 1 }
    catch { console.log("invalid-url-rejected") }`
  const child = Bun.spawn([process.execPath, "--eval", source], {
    env: {...process.env, RACCOON_MAIN_SITE_URL: "not a URL"},
    stdout: "pipe", stderr: "pipe",
  })
  let timedOut = false
  const deadline = setTimeout(() => { timedOut = true; child.kill() }, 2000)
  let exitCode
  try { exitCode = await child.exited }
  finally { clearTimeout(deadline) }
  const output = await new Response(child.stdout).text()
  expect(output).toContain("invalid-url-rejected")
  expect(timedOut).toBe(false)
  expect(exitCode).toBe(0)
})
