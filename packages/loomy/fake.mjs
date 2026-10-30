// the fake Loomy upstream: the account domain (HMAC-signed SMS login) and
// the integration gateway (models, chat, points, first-login) on local ports.

import { createHash, createHmac } from "node:crypto"

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })
const OK = "000000"

// the client's TASK_POINTS registry, key by key (the server knows these and
// refuses anything else)
const TASK_POINTS = {
  first_message: 500,
  pick_skill: 1000,
  generate_ppt: 1500,
  set_schedule: 1000,
  install_skill: 1500,
  configure_remote: 1000,
  create_soul: 1500,
  share_soul: 2000,
}

export function fakeLoomy() {
  const state = {
    session: "sess-1",
    phone: "13800138000",
    smsSent: null, // {phone, msgid}
    logins: 0,
    chatCalls: [],
    chatRefusal: null, // set to an upstream message to answer 400 instead
    firstLoginCalls: 0,
    dailyBalance: 3000, // the day's first first-login refreshes it to 5000
    recordsReads: 0,
    modelsReads: 0,
    // onboarding: done[key]=true once its complete call lands (idempotent)
    onboardingDone: {},
    onboardingQueries: 0,
    onboardingCompletes: 0,
    reset() {
      state.smsSent = null
      state.logins = 0
      state.chatCalls = []
      state.chatRefusal = null
      state.firstLoginCalls = 0
      state.dailyBalance = 3000
      state.recordsReads = 0
      state.modelsReads = 0
      state.onboardingDone = {}
      state.onboardingQueries = 0
      state.onboardingCompletes = 0
    },
  }
  const AK = "2thryby66wxi53sk"
  const SK = "zsak6eadrbawz683wf5r3m2snrwj868r"

  // the account domain: every request must carry the client's HMAC-SHA1
  // signature over the 9-part string, as the real one checks
  const account = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url)
      const bodyString = await req.text()
      const auth = req.headers.get("authorization") ?? ""
      if (!auth.startsWith(`account ${AK}:`)) return json(401, { code: "020002", desc: "no signature" })
      // re-sign what arrived and compare: path, date, nonce, md5 all take part
      const path = url.pathname
      let clean = path.startsWith("/") ? path : `/${path}`
      if (clean.length > 1 && clean.endsWith("/")) clean = clean.slice(0, -1)
      const escaped = clean.split("/").map((s) => encodeURIComponent(s)).join("/")
      const md5 = bodyString ? createHash("md5").update(bodyString).digest("base64") : ""
      const date = req.headers.get("date") ?? ""
      const nonce = req.headers.get("nonce") ?? ""
      const stringToSign = ["POST", escaped, "", md5, "application/json", date, nonce, "", ""].join("\n")
      const expect = createHmac("sha1", SK).update(stringToSign).digest("base64")
      if (auth !== `account ${AK}:${expect}`) return json(401, { code: "020002", desc: "bad signature" })
      if (md5 && req.headers.get("content-md5") !== md5) return json(400, { code: "020003", desc: "md5 mismatch" })

      const body = JSON.parse(bodyString || "{}")
      if (url.pathname === "/login/phone/sendMsgCode") {
        if (body?.param?.ccode !== "86") return json(400, { code: "020004", desc: "ccode" })
        if (body?.param?.phone !== state.phone) return json(400, { code: "020005", desc: "phone" })
        const msgid = `msg-${Date.now()}`
        state.smsSent = { phone: body.param.phone, msgid }
        return json(200, { code: OK, desc: "sent", data: { msgid } })
      }
      if (url.pathname === "/login/phone/checkCode") {
        if (!state.smsSent || body?.param?.msgid !== state.smsSent.msgid) return json(400, { code: "020006", desc: "msgid" })
        if (body?.param?.mcode !== "123456") return json(400, { code: "020007", desc: "wrong code" })
        state.logins++
        state.session = `sess-${state.logins}`
        return json(200, { code: OK, desc: "ok", data: { session: state.session, userid: "261014155255771375" } })
      }
      return json(404, { code: "020008", desc: "no route" })
    },
  })

  // the integration gateway: double auth headers on everything
  const gateway = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url)
      const token = req.headers.get("token") ?? ""
      const bearer = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "")
      if (token !== state.session || bearer !== state.session) return json(401, { code: "100002", desc: "session refused" })

      if (url.pathname === "/api/v1/models") {
        state.modelsReads++
        return json(200, {
          data: [
            { id: "spark-x", name: "Spark X2.5 (x0.1)", capabilities: { reasoning: true, function_calling: true, vision: false }, context_window: 128000, max_tokens: 8192 },
            { id: "deepseek-v4-flash", name: "DeepSeek V4 Flash 0731 (x3.0)", capabilities: { reasoning: true, function_calling: false, vision: true } },
            { id: "glm-5.3-flash", name: "GLM 5.3 Flash(x0.8)", capabilities: { reasoning: false, function_calling: false, vision: true } },
            { id: "plain", name: "No Suffix At All", capabilities: {} },
          ],
        })
      }

      if (url.pathname === "/api/v1/chat/completions") {
        // charset=utf-8 is load-bearing: without it the real upstream reads
        // the body as GBK; the fake checks it is sent
        const ct = req.headers.get("content-type") ?? ""
        if (!/charset\s*=\s*"?utf-8/i.test(ct)) return json(400, { code: "100009", desc: "content-type must name utf-8" })
        const body = await req.json().catch(() => ({}))
        state.chatCalls.push({ body })
        if (state.chatRefusal) return json(400, { error: { message: state.chatRefusal, type: "invalid_request_error" } })
        const reply = body.stream
          ? new Response(
              [
                `data: ${JSON.stringify({ id: "c1", model: body.model, choices: [{ index: 0, delta: { role: "assistant", content: "你" } }] })}\n\n`,
                `data: ${JSON.stringify({ id: "c1", model: body.model, choices: [{ index: 0, delta: { content: "好" } }] })}\n\n`,
                `data: ${JSON.stringify({ id: "c1", model: body.model, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`,
                "data: [DONE]\n\n",
              ].join(""),
              { headers: { "content-type": "text/event-stream" } },
            )
          : json(200, { id: "c1", model: body.model, choices: [{ index: 0, message: { role: "assistant", content: "你好" }, finish_reason: "stop" }] })
        return reply
      }

      if (url.pathname === "/api/v1/points/first-login") {
        state.firstLoginCalls++
        // the vendor's own semantics: the day's first call refreshes the
        // daily wallet (up), a repeat answers success with no change (flat)
        if (state.firstLoginCalls === 1) state.dailyBalance = 5000
        return json(200, { code: OK, desc: "ok", data: { dailyBalance: state.dailyBalance } })
      }

      if (url.pathname === "/api/v2/points/records") {
        state.recordsReads++
        return json(200, { code: OK, desc: "ok", data: { balance: 5000, dailyBalance: state.dailyBalance, dailyLimitPoints: 5000, dailyRemainingPoints: state.dailyBalance, list: [], total: 0 } })
      }

      // onboarding: the task status table and the per-key completion report
      // (the report carries no proof; the real vendor credits real points and
      // answers alreadyCompleted=true idempotently)
      if (url.pathname === "/api/v1/onboarding/tasks") {
        state.onboardingQueries++
        return json(200, { code: OK, desc: "ok", data: { tasks: { ...state.onboardingDone } } })
      }
      if (url.pathname === "/api/v1/onboarding/tasks/complete") {
        state.onboardingCompletes++
        const reqBody = await req.json().catch(() => ({}))
        const key = String(reqBody?.key ?? "")
        if (!key || !(key in TASK_POINTS)) return json(200, { code: "100001", desc: `未知的 task key：${key}` })
        const already = !!state.onboardingDone[key]
        state.onboardingDone[key] = true
        return json(200, { code: OK, desc: "ok", data: { alreadyCompleted: already } })
      }

      return json(404, { code: "100003", desc: "no route" })
    },
  })

  return { account, gateway, state, accountUrl: `http://127.0.0.1:${account.port}`, gatewayUrl: `http://127.0.0.1:${gateway.port}` }
}
