// WorkBuddy refuses a chat whose system (or an assistant) message holds a
// line it knows from another agent, as 400 11128 "Illegal API invocation
// from an unapproved channel"; the user's and tools' messages aren't read.
// Opening lines are matched only at the start of the message, others
// anywhere in it. REFUSAL is the body copilot.tencent.com and
// www.workbuddy.ai both sent on 2026-10-21 for a system prompt opening with
// Claude Code's identity line.
import { expect, test } from "bun:test"
import { WorkBuddyAuthPlugin, WorkBuddyAIAuthPlugin, _internal } from "./index.mjs"
import { unz } from "./testdata/unz.mjs"

const { systemAsUser, REFUSED_HINT, REFUSED_DOC, DEFAULT_SYSTEM } = _internal

const REFUSAL = JSON.stringify({
  code: 11128,
  msg: "Illegal API invocation from an unapproved channel",
  requestId: "77e85b2840d5e111705b54090bc89318",
  displayMsg: { en: "Request blocked. Please send it again", zh: "请求被拦截，请重新发送", "zh-hant": "請求已被攔截，請重新傳送" },
  displayTips: {
    en: "This call failed channel verification, possibly because it was not sent from an official client. Please resend from the official client.",
    zh: "这次调用没通过渠道校验，可能不是官方客户端发出的。请用官方版本重新发送。",
    "zh-hant": "本次呼叫未通過通路驗證，可能不是官方用戶端發出。請使用官方版本重新傳送。",
  },
  actions: ["EDIT_INPUT", "SUBMIT_FEEDBACK"],
})
const NOT_FIRST = JSON.stringify({ code: 11128, msg: "first message is not system prompt", requestId: "e83a1453a850789c0e647f25f0e788af" })

// lines FLAGGED doesn't know, refused as WorkBuddy refuses known ones: an
// agent's opening line at the start, a fingerprint anywhere
const OPENING = "You are Example Agent, the official CLI of Example Inc."
const ANYWHERE = "Example fingerprint (you will usually see this)"

const text = (c) => (typeof c === "string" ? c : Array.isArray(c) ? c.map((p) => p?.text ?? "").join("") : "")
const refuses = (m) => (m.role === "system" || m.role === "assistant") && (text(m.content).toLowerCase().startsWith(OPENING.toLowerCase()) || text(m.content).includes(ANYWHERE))

async function withService(Plugin, fn, answer) {
  const realFetch = globalThis.fetch
  const sent = []
  globalThis.fetch = async (_url, init) => {
    const b = JSON.parse(unz(init.body))
    sent.push(b)
    const said = answer?.(b)
    if (said) return said
    if (b.messages.some(refuses)) return new Response(REFUSAL, { status: 400, headers: { "content-type": "application/json; charset=utf-8" } })
    return new Response("data: [DONE]\n\n", { headers: { "content-type": "text/event-stream" } })
  }
  try {
    const hooks = await Plugin({ client: {} })
    const loader = await hooks.auth.loader(async () => ({ type: "oauth", access: "access", uid: "uid", expires: Date.now() + 3600_000 }))
    const post = (body) => loader.fetch("https://copilot.tencent.com/v2/chat/completions", { method: "POST", body: JSON.stringify({ model: "glm-5.3", stream: true, ...body }) })
    await fn(post, sent)
  } finally {
    globalThis.fetch = realFetch
  }
}

const tools = [{ type: "function", function: { name: "read", description: "Reads a file.", parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } } }]
let n = 0
// a system prompt of its own per test: what was refused stays remembered for as
// long as the plugin is loaded, across sign-ins
const systemOf = () => ({ role: "system", content: OPENING + "\nUse the tools to answer. (" + ++n + ")" })
const ask = { role: "user", content: "Read calc.py." }

for (const [name, Plugin] of [["WorkBuddy", WorkBuddyAuthPlugin], ["WorkBuddy AI", WorkBuddyAIAuthPlugin]]) {
  test(`${name}: a refused system prompt goes again as the user's instructions, tools and all`, async () => {
    const system = systemOf()
    await withService(Plugin, async (post, sent) => {
      const res = await post({ messages: [system, ask], tools })
      expect(res.status).toBe(200)
      expect(sent.length).toBe(2)
      const again = sent[1]
      expect(again.messages[0]).toEqual({ role: "system", content: DEFAULT_SYSTEM })
      expect(again.messages[1]).toEqual({ role: "user", content: "<instructions>\n" + system.content + "\n</instructions>\n\nRead calc.py." })
      expect(again.messages.length).toBe(2)
      expect(again.tools.map((t) => t.function.name)).toEqual(["read"])
    })
  })
}

test("the same system prompt's next chat goes moved at once, and another's is tried as it is", async () => {
  const system = systemOf()
  await withService(WorkBuddyAuthPlugin, async (post, sent) => {
    await post({ messages: [system, ask], tools })
    const call = { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "read", arguments: '{"path":"calc.py"}' } }] }
    const result = { role: "tool", tool_call_id: "c1", content: "def add(a, b): return a + b" }
    const res = await post({ messages: [system, ask, call, result], tools })
    expect(res.status).toBe(200)
    expect(sent.length).toBe(3)
    expect(sent[2].messages.map((m) => m.role)).toEqual(["system", "user", "assistant", "tool"])
    expect(sent[2].messages[1].content.startsWith("<instructions>\n" + OPENING)).toBe(true)
    // what the tool said and what the assistant called stay as they were
    expect(sent[2].messages[2]).toEqual(call)
    expect(sent[2].messages[3]).toEqual(result)
    await post({ messages: [{ role: "system", content: "You are a coding agent." }, ask] })
    expect(sent.length).toBe(4)
    expect(sent[3].messages[0].content).toBe("You are a coding agent.")
  })
})

test("a line refused anywhere in the system prompt is moved too", async () => {
  await withService(WorkBuddyAIAuthPlugin, async (post, sent) => {
    const res = await post({ messages: [{ role: "system", content: "You are a coding agent.\n\nGit status:\n" + ANYWHERE }, ask] })
    expect(res.status).toBe(200)
    expect(sent.length).toBe(2)
    expect(sent[1].messages[1].content).toContain(ANYWHERE)
  })
})

// An opening the plugin doesn't know is said with a comma before the system
// prompt is moved: the move costs the agent the slot its instructions are
// read in, and the comma keeps both the place and the harness's name.
test("a refused opening FLAGGED doesn't know is said with a comma, not moved", async () => {
  const opener = "You are an AI agent powered by Example Harness."
  const uncommaed = (b) =>
    b.messages.some((m) => (m.role === "system" || m.role === "assistant") && text(m.content).includes("You are an AI agent powered by Example Harness"))
  await withService(
    WorkBuddyAIAuthPlugin,
    async (post, sent) => {
      const res = await post({ messages: [{ role: "system", content: opener }, ask] })
      expect(res.status).toBe(200)
      expect(sent.length).toBe(2)
      expect(sent[1].messages[0].role).toBe("system")
      expect(sent[1].messages[0].content).toBe("You are an AI agent, powered by Example Harness.")
    },
    (b) => (uncommaed(b) ? new Response(REFUSAL, { status: 400, headers: { "content-type": "application/json; charset=utf-8" } }) : undefined),
  )
})

test("a refusal that stands after the move is the user's, with the hint, tried once", async () => {
  const system = systemOf()
  await withService(WorkBuddyAuthPlugin, async (post, sent) => {
    // an assistant message WorkBuddy refuses too, which nothing moves
    const res = await post({ messages: [system, ask, { role: "assistant", content: OPENING }, { role: "user", content: "go on" }] })
    expect(res.status).toBe(400)
    expect(sent.length).toBe(2)
    expect(res.headers.get("X-Magpie-Sign-In")).toBe("kept")
    expect((await res.json()).error.message).toBe("Illegal API invocation from an unapproved channel — " + REFUSED_DOC + " — " + REFUSED_HINT)
  })
})

test("a chat with nothing to move isn't sent again", async () => {
  await withService(WorkBuddyAuthPlugin, async (post, sent) => {
    const res = await post({ messages: [{ role: "user", content: "hi" }, { role: "assistant", content: OPENING }, ask] })
    expect(res.status).toBe(400)
    expect(sent.length).toBe(1)
  })
})

test("11128 for another reason moves nothing", async () => {
  await withService(
    WorkBuddyAIAuthPlugin,
    async (post, sent) => {
      const res = await post({ messages: [{ role: "system", content: "You are a coding agent." }, ask] })
      expect(res.status).toBe(400)
      expect(sent.length).toBe(1)
    },
    () => new Response(NOT_FIRST, { status: 400, headers: { "content-type": "application/json" } }),
  )
})

test("systemAsUser: parts, a later system message, no user message", () => {
  const parts = JSON.parse(
    systemAsUser(
      JSON.stringify({
        messages: [
          { role: "system", content: [{ type: "text", text: OPENING }, { type: "text", text: "Be brief." }] },
          { role: "user", content: [{ type: "text", text: "look" }, { type: "image_url", image_url: { url: "data:image/png;base64,AA==" } }] },
          { role: "assistant", content: "ok" },
          { role: "system", content: "Reminder: be brief." },
          { role: "user", content: "next" },
        ],
      }),
    ),
  )
  expect(parts.messages[0]).toEqual({ role: "system", content: DEFAULT_SYSTEM })
  expect(parts.messages[1].content[0]).toEqual({ type: "text", text: "<instructions>\n" + OPENING + "\nBe brief.\n</instructions>" })
  expect(parts.messages[1].content.slice(1).map((p) => p.type)).toEqual(["text", "image_url"])
  expect(parts.messages[3]).toEqual({ role: "user", content: "Reminder: be brief." })

  const alone = JSON.parse(systemAsUser(JSON.stringify({ messages: [{ role: "system", content: OPENING }] })))
  expect(alone.messages).toEqual([{ role: "system", content: DEFAULT_SYSTEM }, { role: "user", content: "<instructions>\n" + OPENING + "\n</instructions>" }])

  expect(systemAsUser(JSON.stringify({ messages: [{ role: "system", content: DEFAULT_SYSTEM }, ask] }))).toBeNull()
})

test("the words the move adds name no one", () => {
  const out = systemAsUser(JSON.stringify({ messages: [{ role: "system", content: "x" }, ask] }))
  const added = out.replace(/"x"|Read calc\.py\.|You are a helpful assistant\./g, "")
  expect(added).not.toMatch(/magpie|workbuddy|codebuddy|opencode|claude|codex/i)
})
