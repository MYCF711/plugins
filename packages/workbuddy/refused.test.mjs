// WorkBuddy's refusal of words in a client's prompt carries the hint
// magpie's Routing page knows (WB_REFUSED), at the end of the message,
// where the page looks for it.
import { expect, test } from "bun:test"
import { _internal } from "./index.mjs"

const { explained, REFUSED_HINT, RESTRICTED_HINT, EXHAUSTED_HINT, REFUSED_DOC } = _internal

test("the refusal ends in the hint", async () => {
  const res = await explained(new Response(JSON.stringify({ error: { message: "Illegal API invocation from an unapproved channel", code: 11004 } }), { status: 403 }))
  expect(res.status).toBe(403)
  expect((await res.json()).error.message).toBe("Illegal API invocation from an unapproved channel — " + REFUSED_DOC + " — " + REFUSED_HINT)
})

// The hint stays the message's end, where magpie's Routing page matches it
// (Routing client.js: HINTS.find((h) => error.endsWith(" — " + h))), so a
// refusal points at where its fix is written down and still ends as it did.
test("the refusal names where its fix is written, and still ends in the hint", async () => {
  const res = await explained(new Response(JSON.stringify({ error: { message: "Illegal API invocation from an unapproved channel" } }), { status: 400 }))
  const message = (await res.json()).error.message
  expect(message.endsWith(" — " + REFUSED_HINT)).toBe(true)
  expect(message).toContain(REFUSED_DOC)
  expect(message.indexOf(REFUSED_DOC)).toBeLessThan(message.indexOf(REFUSED_HINT))
  expect(REFUSED_DOC).toMatch(/^https:\/\/github\.com\/magpie-community\/plugins\/blob\/main\/packages\/workbuddy\/REFUSED\.md$/)
})

test("the hint is magpie's word for word, and blames no one client", () => {
  // magpie's Routing page splits it from WorkBuddy's words only when it
  // matches exactly; DeepSeek Harness's and Claude Desktop's chats are
  // refused too (#279, #170), so naming Codex and Claude Code misled them
  expect(REFUSED_HINT).toBe(
    "WorkBuddy refused words in this client's prompt (most often its system prompt); use it from Hermes, OpenCode or Pi, or add another provider to this group",
  )
  expect(REFUSED_HINT).not.toMatch(/Codex|Claude/)
})

test("credits exhausted error ends in the exhausted hint", async () => {
  const res = await explained(
    new Response(
      JSON.stringify({
        error: {
          data: {
            code: 14018,
            msg: "Credits exhausted. Please visit the link below to purchase add-on packs and get more credits: https://www.codebuddy.ai/profile/usage ",
            requestId: "test-req",
          },
        },
      }),
      { status: 429 }
    )
  )
  expect(res.status).toBe(429)
  const body = await res.json()
  expect(body.error.type).toBe("insufficient_quota")
  expect(body.error.code).toBe(14018)
  expect(body.error.message).toBe(
    "Credits exhausted. Please visit the link below to purchase add-on packs and get more credits: https://www.codebuddy.ai/profile/usage  — " +
      EXHAUSTED_HINT
  )
})

test("credits exhausted as {code, msg} says its msg, then the exhausted hint", async () => {
  const res = await explained(
    new Response(JSON.stringify({ code: 14018, msg: "Credits exhausted" }), { status: 429 })
  )
  expect(res.status).toBe(429)
  const body = await res.json()
  expect(body.error.type).toBe("insufficient_quota")
  expect(body.error.code).toBe(14018)
  expect(body.error.message).toBe("Credits exhausted — " + EXHAUSTED_HINT)
})

test("other errors pass as they came", async () => {
  const res = await explained(new Response('{"error":{"message":"rate limited"}}', { status: 429 }))
  expect(res.status).toBe(429)
  expect(await res.text()).toBe('{"error":{"message":"rate limited"}}')
})

test("unrelated errors containing 14018 in requestId pass through untouched", async () => {
  const timeout = '{"error":{"message":"upstream timeout","requestId":"req-1759614018"}}'
  const res1 = await explained(new Response(timeout, { status: 504 }))
  expect(res1.status).toBe(504)
  expect(await res1.text()).toBe(timeout)

  const notfound = '{"error":{"message":"model not found","requestId":"a1b2-14018-ff"}}'
  const res2 = await explained(new Response(notfound, { status: 404 }))
  expect(res2.status).toBe(404)
  expect(await res2.text()).toBe(notfound)
})

test("a code that only begins with 14018 passes through untouched", async () => {
  for (const body of ['{"error":{"code":140185,"message":"slow down"}}', '{"error":{"code":140185,"message":"slow do']) {
    const res = await explained(new Response(body, { status: 429 }))
    expect(res.status).toBe(429)
    expect(await res.text()).toBe(body)
  }
})

test("truncated body with code 14018 is explained", async () => {
  const trunc = '{"error":{"data":{"code":14018,"msg":"Credits exh'
  const res = await explained(new Response(trunc, { status: 429 }))
  expect(res.status).toBe(429)
  const body = await res.json()
  expect(body.error.type).toBe("insufficient_quota")
  expect(body.error.code).toBe(14018)
  expect(body.error.message).toBe(trunc + " — " + EXHAUSTED_HINT)
})

test("a model of no credits is free, as magpie's built-in read them", () => {
  const { freeCredits } = _internal
  for (const c of ["x0.00", "0", 0, " X0 "]) expect(freeCredits(c)).toBe(true)
  for (const c of ["x0.03", "", null, undefined, "free", 1]) expect(freeCredits(c)).toBe(false)
})

// wbExplain's refusal in WorkBuddy's own envelope reads its msg
test("a refusal as {code, msg} says its msg, then the hint", async () => {
  const res = await explained(new Response(JSON.stringify({ code: 11004, msg: "Illegal API invocation from an unapproved channel" }), { status: 403 }))
  expect(res.status).toBe(403)
  expect((await res.json()).error.message).toBe("Illegal API invocation from an unapproved channel — " + REFUSED_DOC + " — " + REFUSED_HINT)
})

// a body handed over as bytes still gets WorkBuddy's system message
test("a chat body in bytes is read, and given the system message", () => {
  const { withSystem } = _internal
  const chat = { model: "m", messages: [{ role: "user", content: "hi" }] }
  const want = { model: "m", messages: [{ role: "system", content: "You are a helpful assistant." }, { role: "user", content: "hi" }] }
  for (const b of [Buffer.from(JSON.stringify(chat)), new TextEncoder().encode(JSON.stringify(chat)), new TextEncoder().encode(JSON.stringify(chat)).buffer])
    expect(JSON.parse(withSystem(b))).toEqual(want)
  expect(JSON.parse(withSystem(JSON.stringify(chat)))).toEqual(want)
})

// magpie #1849: the body WorkBuddy AI answered for an account it restricted,
// byte for byte as the reporter posted it.
const RESTRICTED_BODY = `{"code":11140,"msg":"request illegal",
 "displayMsg":{"en":"Your account has been restricted due to unusual activity",
               "zh":"账号存在异常行为，已被限制使用","zh-hant":"帳號存在異常行為，已被限制使用"},
 "displayTips":{"en":"We detected unusual activity on this account. Submit feedback to appeal this restriction",
                "zh":"系统检测到该账号存在异常使用行为，如需申诉请提交反馈"},
 "actions":["EDIT_INPUT","SUBMIT_FEEDBACK"]}`

test("a restricted account's 11140 says its msg, then the restricted hint, word for word magpie's", async () => {
  const res = await explained(new Response(RESTRICTED_BODY, { status: 403 }))
  expect(res.status).toBe(403)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("kept")
  const body = await res.json()
  expect(body.error).toEqual({ message: "request illegal — " + RESTRICTED_HINT, type: "permission_error", code: 11140 })
  // magpie's routing.go looks for provider.WBRestrictedHint itself
  expect(RESTRICTED_HINT).toBe(
    "WorkBuddy restricted this account for unusual activity; it stays out until WorkBuddy lifts that, which an appeal (Submit feedback in WorkBuddy) asks for",
  )
})

test("the restriction is known by a string code, under error, or by its words alone", async () => {
  for (const b of [
    '{"code":"11140","msg":"request illegal"}',
    '{"error":{"code":11140,"message":"request illegal"}}',
    '{"error":{"data":{"code":11140,"msg":"request illegal"}}}',
    '{"msg":"账号存在异常行为，已被限制使用"}',
    '{"code":11140,"msg":"request ill',
  ]) {
    const body = await (await explained(new Response(b, { status: 403 }))).json()
    expect(body.error.code).toBe(11140)
    expect(body.error.message.endsWith(" — " + RESTRICTED_HINT)).toBe(true)
  }
})

test("a code that only begins with 11140, and 11128, are not a restriction", async () => {
  for (const b of ['{"code":111400,"msg":"request illegal"}', '{"error":{"code":111400,"message":"x"}}']) {
    const res = await explained(new Response(b, { status: 403 }))
    expect(await res.text()).toBe(b)
  }
  const body = await (await explained(new Response('{"error":{"message":"Illegal API invocation from an unapproved channel","code":11128}}', { status: 403 }))).json()
  expect(body.error.message.endsWith(REFUSED_HINT)).toBe(true)
})
