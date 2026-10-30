import { describe, test, expect, beforeAll, afterAll, beforeEach } from "bun:test"
import { LoomyAuthPlugin, _internal } from "./index.mjs"
import { fakeLoomy } from "./fake.mjs"

// every test runs against the fake upstream in fake.mjs: no network, no real
// token ever leaves this process

let fake
let plugin
let saved = {}
const client = { auth: { set: async ({ body }) => (saved = body) } }
const getAuth = async () => saved

beforeAll(async () => {
  fake = fakeLoomy()
  process.env.LOOMY_POINTS_BASE_URL = fake.gatewayUrl
  process.env.LOOMY_XFYUN_BASE_URL = fake.accountUrl
})

afterAll(() => {
  fake.account.stop(true)
  fake.gateway.stop(true)
})

beforeEach(async () => {
  fake.state.reset()
  saved = { type: "oauth", access: fake.state.session, expires: 0, accountId: "138****8000", name: "138****8000", source: "manual" }
  plugin = await LoomyAuthPlugin({ client })
})

describe("sign-in methods", () => {
  test("SMS: sends the code, then trades it for a 14-day session", async () => {
    const method = plugin.auth.methods.find((m) => m.label.includes("SMS"))
    const flow = await method.authorize({ phone: "138 0013 8000" }) // spaces tolerated
    expect(flow.method).toBe("code")
    expect(flow.instructions).toContain("已发送")
    expect(fake.state.smsSent).toBeTruthy()
    // wrong code fails with a reason
    expect((await flow.callback("000000")).type).toBe("failed")
    const result = await flow.callback("123456")
    expect(result.type).toBe("success")
    expect(result.access).toBe("sess-1")
    expect(result.expires).toBeGreaterThan(Date.now() + 13 * 86400e3)
    expect(result.accountId).toBe("138****8000")
  })

  test("SMS: an invalid phone is refused before anything is sent", async () => {
    const method = plugin.auth.methods.find((m) => m.label.includes("SMS"))
    const bad = await method.authorize({ phone: "12345" })
    expect(bad.type).toBe("failed")
    expect(fake.state.smsSent).toBeNull()
  })

  test("manual paste works through the host's authorize → callback contract", async () => {
    const method = plugin.auth.methods.find((m) => m.label.includes("Paste"))
    const flow = await method.authorize({ session: "pasted" })
    expect(flow.method).toBe("auto")
    expect(typeof flow.callback).toBe("function")
    const result = await flow.callback()
    expect(result.type).toBe("success")
    expect(result.access).toBe("pasted")
    expect(await method.authorize({ session: "" })).toMatchObject({ type: "failed" })
  })
})

describe("chat", () => {
  test("forwards with the double auth headers and streams through", async () => {
    const loader = await plugin.auth.loader(getAuth)
    const res = await loader.fetch(`${fake.gatewayUrl}/api/v1/v1/chat/completions`.replace("/v1/v1/", "/api/v1/"), {
      method: "POST",
      body: JSON.stringify({ model: "spark-x", stream: true, messages: [{ role: "user", content: "hi" }] }),
    })
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('"content":"你"')
    expect(text).toContain("data: [DONE]")
    expect(fake.state.chatCalls.length).toBe(1)
    expect(fake.state.chatCalls[0].body.model).toBe("spark-x")
  })

  test("a genuinely over-length Kimi-k2.6 request still comes back 400", async () => {
    // 150 万 ASCII 字符 ≈ 37.5 万 token，对 262,144 窗口的 Kimi-k2.6 是真超长。
    // 旧实现按固定 200 万字符阈值判成「上游瞬时故障」并改成 502，magpie 会换号重试到整轮失败。
    fake.state.chatRefusal = "内容太长了，请精简输入或开启新对话"
    const loader = await plugin.auth.loader(getAuth)
    const huge = "word ".repeat(300_000)
    const res = await loader.fetch(`${fake.gatewayUrl}/api/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ model: "kimi-k2.6", stream: false, messages: [{ role: "user", content: huge }] }),
    })
    expect(res.status).toBe(400)
    expect(await res.text()).toContain("上下文超出长度限制")
  })

  test("reasoning effort folds to low/medium/high", async () => {
    const loader = await plugin.auth.loader(getAuth)
    await loader.fetch(`${fake.gatewayUrl}/api/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ model: "spark-x", stream: false, reasoning_effort: "minimal", messages: [] }),
    })
    await loader.fetch(`${fake.gatewayUrl}/api/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ model: "spark-x", stream: false, reasoning_effort: "max", messages: [] }),
    })
    await loader.fetch(`${fake.gatewayUrl}/api/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ model: "spark-x", stream: false, reasoning_effort: "none", messages: [] }),
    })
    expect(fake.state.chatCalls[0].body.reasoning_effort).toBe("low")
    expect(fake.state.chatCalls[1].body.reasoning_effort).toBe("high")
    expect(fake.state.chatCalls[2].body.reasoning_effort).toBeUndefined()
  })

  test("deepseek images become base64 markers merged into the text", async () => {
    const loader = await plugin.auth.loader(getAuth)
    await loader.fetch(`${fake.gatewayUrl}/api/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({
        model: "deepseek-v4-flash",
        stream: false,
        messages: [
          { role: "user", content: [
            { type: "text", text: "看这张图" },
            { type: "image_url", image_url: { url: "data:image/png;base64,QUJD" } },
            { type: "image_url", image_url: { url: "https://example.com/x.png" } },
          ] },
        ],
      }),
    })
    const content = fake.state.chatCalls[0].body.messages[0].content
    expect(content).toHaveLength(2)
    expect(content[0].text).toContain("看这张图")
    expect(content[0].text).toContain("<image_base64>data:image/png;base64,QUJD</image_base64>")
    // an http(s) URL stays as it was (no evidence the marker accepts URLs)
    expect(content[1].type).toBe("image_url")
  })

  test("a refused session says 401", async () => {
    saved = { type: "oauth", access: "gone", expires: 0 }
    const loader = await plugin.auth.loader(getAuth)
    const res = await loader.fetch(`${fake.gatewayUrl}/api/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ model: "spark-x", stream: false, messages: [] }),
    })
    expect(res.status).toBe(401)
  })

  test("only chat completions are served", async () => {
    const loader = await plugin.auth.loader(getAuth)
    const res = await loader.fetch(`${fake.gatewayUrl}/api/v1/embeddings`, { method: "POST", body: "{}" })
    expect(res.status).toBe(404)
  })
})

describe("checkin", () => {
  test("the day's first call claims the grant, a repeat is done", async () => {
    // the daily wallet moves 3000 → 5000 on the day's first call: claimed
    const result = await plugin.auth.checkin(getAuth)
    expect(result.outcome).toBe("claimed")
    expect(result.credit).toBe(2000)
    expect(result.message).toContain("5000")
    expect(fake.state.firstLoginCalls).toBe(1)
    // the endpoint answers success on a repeat too, but the wallet is flat:
    // done, not a second claim
    const again = await plugin.auth.checkin(getAuth)
    expect(again.outcome).toBe("done")
    expect(again.credit).toBeUndefined()
    expect(fake.state.firstLoginCalls).toBe(2)
  })

  test("a refused session says the sign-in expired", async () => {
    saved = { type: "oauth", access: "gone", expires: 0 }
    await expect(plugin.auth.checkin(getAuth)).rejects.toThrow(/失效/)
  })

  test("a failed pre-read is failed, not silently done", async () => {
    const realFetch = globalThis.fetch
    globalThis.fetch = (input, init) => {
      const url = typeof input === "string" ? input : String(input?.url ?? input)
      // fail only the records read; the first-login POST still goes through
      if (String(url).includes("/api/v2/points/records")) return new Response("boom", { status: 502 })
      return realFetch(input, init)
    }
    try {
      const result = await plugin.auth.checkin(getAuth)
      expect(result.outcome).toBe("failed")
      expect(result.message).toContain("无法读取签到前余额")
      expect(fake.state.firstLoginCalls).toBe(0)
    } finally {
      globalThis.fetch = realFetch
    }
  })
})

describe("models", () => {
  test("the catalog, with rates split out of the names", async () => {
    const p = { models: {} }
    const list = await plugin.provider.models(p, { auth: saved })
    expect(Object.keys(list)).toEqual(["spark-x", "deepseek-v4-flash", "glm-5.3-flash", "plain"])
    expect(list["spark-x"].rate).toBe("x0.1")
    expect(list["spark-x"].name).toBe("Spark X2.5")
    expect(list["spark-x"].reasoning).toBe(true)
    expect(list["spark-x"].tool_call).toBe(true)
    expect(list["deepseek-v4-flash"].rate).toBe("x3.0")
    expect(list["glm-5.3-flash"].modalities).toEqual({ input: ["text", "image"], output: ["text"] })
    expect(list["plain"].rate).toBeUndefined()
    expect(list["plain"].name).toBe("No Suffix At All")
  })
})

describe("usage", () => {
  test("the two wallets as windows", async () => {
    const usage = await plugin.auth.usage(getAuth)
    // a clean read says nothing about the sign-in, so magpie can clear a lapse
    expect(usage.signIn).toBeUndefined()
    const daily = usage.windows.find((w) => w.name === "每日赠送积分")
    // the vendor's own numbers: spent = dailyLimitPoints - dailyRemainingPoints
    expect(daily.limit).toBe(5000)
    expect(daily.amount).toBe(fake.state.dailyBalance)
    expect(daily.resetsAt).toBeGreaterThan(Date.now())
    const permanent = usage.windows.find((w) => w.name === "永久积分")
    expect(permanent.display).toBe("5000 credits")
  })

  test("a daily wallet without the limit pair is an amount without a limit", async () => {
    const realFetch = globalThis.fetch
    globalThis.fetch = (input, init) => {
      const url = typeof input === "string" ? input : String(input?.url ?? input)
      if (String(url).includes("/api/v2/points/records"))
        return new Response(JSON.stringify({ code: "000000", desc: "ok", data: { balance: 5000, dailyBalance: 3000, list: [], total: 0 } }), { status: 200 })
      return realFetch(input, init)
    }
    try {
      const usage = await plugin.auth.usage(getAuth)
      const daily = usage.windows.find((w) => w.name === "每日赠送积分")
      expect(daily.limit).toBeUndefined()
      expect(daily.display).toBe("3000 credits")
      // a reply with only the limit/remaining pair still shows the daily
      // wallet (remaining IS its number), without dailyBalance
      globalThis.fetch = (input, init) => {
        const url = typeof input === "string" ? input : String(input?.url ?? input)
        if (String(url).includes("/api/v2/points/records"))
          return new Response(JSON.stringify({ code: "000000", desc: "ok", data: { dailyLimitPoints: 5000, dailyRemainingPoints: 4200, list: [] } }), { status: 200 })
        return realFetch(input, init)
      }
      try {
        const pairOnly = await plugin.auth.usage(getAuth)
        const dw = pairOnly.windows.find((w) => w.name === "每日赠送积分")
        expect(dw).toBeTruthy()
        expect(dw.used).toBe(800)
        expect(dw.amount).toBe(4200)
        expect(dw.limit).toBe(5000)
        expect(pairOnly.windows.find((w) => w.name === "永久积分")).toBeUndefined()
      } finally {
        globalThis.fetch = realFetch
      }
      // a reply with neither balance field is an error, not a confident zero
      globalThis.fetch = (input, init) => {
        const url = typeof input === "string" ? input : String(input?.url ?? input)
        if (String(url).includes("/api/v2/points/records"))
          return new Response(JSON.stringify({ code: "000000", desc: "ok", data: { records: [] } }), { status: 200 })
        return realFetch(input, init)
      }
      try {
        const missing = await plugin.auth.usage(getAuth)
        expect(missing.error).toContain("没有返回余额字段")
      } finally {
        globalThis.fetch = realFetch
      }
    } finally {
      globalThis.fetch = realFetch
    }
  })
})

describe("signature", () => {
  test("the 9-part HMAC string matches the client's shape", () => {
    const headers = _internal.signHeaders("POST", "/login/phone/sendMsgCode", '{"a":1}')
    expect(headers.Authorization).toMatch(/^account 2thryby66wxi53sk:[A-Za-z0-9+/=]+$/)
    expect(headers.Date).toMatch(/GMT$/)
    expect(headers.Nonce).toMatch(/^[0-9a-f-]{36}$/)
    expect(headers["Content-MD5"]).toBe(_internal.contentMD5('{"a":1}'))
    // no body: no MD5 header, and the empty part sits in the string
    const empty = _internal.signHeaders("GET", "/x", "")
    expect(empty["Content-MD5"]).toBeUndefined()
  })

  test("paths are escaped and trailing slashes dropped", () => {
    expect(_internal.escapedPath("/login/phone/sendMsgCode")).toBe("/login/phone/sendMsgCode")
    expect(_internal.escapedPath("a/b/")).toBe("/a/b")
    expect(_internal.escapedPath("/带中文/段")).toBe(`/${encodeURIComponent("带中文")}/${encodeURIComponent("段")}`)
  })
})

describe("helpers", () => {
  test("phone normalization", () => {
    expect(_internal.normalizePhone("13800138000")).toBe("13800138000")
    expect(_internal.normalizePhone("+86 138-0013-8000")).toBe("13800138000")
    expect(_internal.normalizePhone("8613800138000")).toBe("13800138000")
    expect(_internal.normalizePhone("12345")).toBeNull()
    expect(_internal.normalizePhone("12800138000")).toBeNull() // second digit not 3-9
  })

  test("rate suffix split", () => {
    expect(_internal.splitRateSuffix("DeepSeek V4 Flash 0731 (x3.0)")).toEqual({ name: "DeepSeek V4 Flash 0731", rate: "x3.0" })
    expect(_internal.splitRateSuffix("GLM 5.3 Flash(x0.8)")).toEqual({ name: "GLM 5.3 Flash", rate: "x0.8" })
    expect(_internal.splitRateSuffix("Spark X2.5 （x0.1）")).toEqual({ name: "Spark X2.5", rate: "x0.1" })
    expect(_internal.splitRateSuffix("限时免费")).toEqual({ name: "限时免费", rate: undefined })
    expect(_internal.splitRateSuffix("Model (free)")).toEqual({ name: "Model (free)", rate: undefined })
  })
})

// ── 「内容太长了」的分流 ────────────────────────────────────────────────
//
// 上游这条 400 不含「上下文」：v0.1.2189 之前的 magpie 的 tooLongRe 认不出，
// 这笔 try 就被当成错误、账号被休息、组里其它成员一次没被问，整轮失败。
// 这里只改写文案（状态码不变），让旧宿主也能认成 overflow；
// v0.1.2189 起宿主自己认得，这是给旧宿主的兜底。

describe("a 400 that says the content is too long", () => {
  // magpie `internal/gateway/gateway.go` 的 tooLongRe 中文两条 —— 逐字抄，改这里等于改契约
  const tooLongRe = /上下文(长度)?(超|过长)|超(过|出)(了)?(模型)?(的)?(最大)?上下文/
  const vendor = "内容太长了，请精简输入或开启新对话"

  test("改写成 tooLongRe 认得的说法，状态码保持 400", async () => {
    const out = _internal.retryableRefusal(400, JSON.stringify({ error: { message: vendor } }))
    expect(out).not.toBeNull()
    expect(out.status).toBe(400)
    const body = await out.text()
    expect(body).toMatch(tooLongRe)
    expect(body).not.toContain("内容太长")
  })

  test("413 与 422 同办，状态码不变", async () => {
    for (const status of [413, 422]) {
      const out = _internal.retryableRefusal(status, vendor)
      expect(out.status).toBe(status)
      expect(await out.text()).toMatch(tooLongRe)
    }
  })

  test("别的 400 不碰", () => {
    expect(_internal.retryableRefusal(400, JSON.stringify({ error: { message: "invalid api key" } }))).toBeNull()
  })

  test("不是 400/413/422 的不碰（2xx 是 SSE 干流）", () => {
    expect(_internal.retryableRefusal(200, vendor)).toBeNull()
    expect(_internal.retryableRefusal(429, vendor)).toBeNull()
    expect(_internal.retryableRefusal(500, vendor)).toBeNull()
  })
})
