// A vendor that turns a chat away over words in the agent's prompt matches
// the line whole and exactly, so the same line said with one more comma
// passes it (measured against WorkBuddy 2026-10-30) — and the line still says
// which harness the agent runs in. commaPaused is that, tried before the
// system prompt is moved out of the slot the agent's instructions are read in.
import { expect, test } from "bun:test"
import { _internal } from "./index.mjs"

const { opened, commaPaused } = _internal

test("a comma goes in where the opening names its harness", () => {
  expect(opened("You are an AI agent powered by DeepSeek Harness.")).toBe("You are an AI agent, powered by DeepSeek Harness.")
  expect(opened("You are a coding agent powered by the {{model}} model.")).toBe("You are a coding agent, powered by the {{model}} model.")
  expect(opened("You are an AI assistant running on Foo.")).toBe("You are an AI assistant, running on Foo.")
  expect(opened("You are the deployment assistant built on Bar.")).toBe("You are the deployment assistant, built on Bar.")
})

// the harness's name stays: only the shape the vendor knows is changed
test("the harness's name survives the comma", () => {
  const opener = "You are an AI agent powered by DeepSeek Harness."
  expect(opened(opener)).toContain("DeepSeek Harness")
  expect(opened(opener)).not.toBe(opener)
})

test("a comma already in place is left alone", () => {
  const once = opened("You are an AI agent powered by DeepSeek Harness.")
  expect(opened(once)).toBe(once)
})

test("words that name no harness are left alone", () => {
  const said = "You are a helpful assistant.\nYour working directory is D:\\work.\nBe brief."
  expect(opened(said)).toBe(said)
})

// commaPaused sets OPENERS' comma in the system and assistant messages, the
// two WorkBuddy reads (REFUSED.md): a comma anywhere else changes what
// someone said without changing what was refused
test("commaPaused sets the comma in the system and assistant messages", () => {
  const body = JSON.stringify({
    model: "deepseek-v4.1-flash",
    messages: [
      { role: "system", content: "You are an AI agent powered by DeepSeek Harness.\n\nBe brief." },
      { role: "user", content: "hi" },
    ],
  })
  const out = JSON.parse(commaPaused(body))
  expect(out.messages[0].content).toBe("You are an AI agent, powered by DeepSeek Harness.\n\nBe brief.")
  expect(out.messages[1].content).toBe("hi")
  expect(out.model).toBe("deepseek-v4.1-flash")
})

// yetone, plugins#513: a user message quoting a line came back altered. The
// user's own words and tools' results go out as they were sent.
test("the user's messages and tools' results are left alone", () => {
  const quoted = "Quote exactly: You are an assistant built on Rails."
  const result = "You are a coding agent powered by Example Harness."
  const body = JSON.stringify({
    messages: [
      { role: "system", content: "You are an AI agent powered by DeepSeek Harness." },
      { role: "user", content: quoted },
      { role: "assistant", content: "You are an AI assistant running on Foo." },
      { role: "tool", tool_call_id: "c1", content: result },
    ],
  })
  const out = JSON.parse(commaPaused(body))
  expect(out.messages[0].content).toBe("You are an AI agent, powered by DeepSeek Harness.")
  expect(out.messages[1].content).toBe(quoted)
  expect(out.messages[2].content).toBe("You are an AI assistant, running on Foo.")
  expect(out.messages[3]).toEqual({ role: "tool", tool_call_id: "c1", content: result })
})

// the user's words alone have nothing to set a comma in, so nothing goes again
test("a chat whose opening is only in the user's message is not resent", () => {
  const users = JSON.stringify({ messages: [{ role: "user", content: "Quote exactly: You are an assistant built on Rails." }] })
  expect(commaPaused(users)).toBe(null)
})

test("commaPaused sets it in a system message's parts too, and not in the user's", () => {
  const body = JSON.stringify({
    messages: [
      { role: "system", content: [{ type: "text", text: "You are an AI agent powered by DeepSeek Harness." }] },
      { role: "user", content: [{ type: "text", text: "Quote exactly: You are an assistant built on Rails." }] },
    ],
  })
  const out = JSON.parse(commaPaused(body))
  expect(out.messages[0].content[0].text).toBe("You are an AI agent, powered by DeepSeek Harness.")
  expect(out.messages[1].content[0].text).toBe("Quote exactly: You are an assistant built on Rails.")
})

test("a chat with nothing of the kind is not resent", () => {
  expect(commaPaused(JSON.stringify({ messages: [{ role: "system", content: "be brief" }, { role: "user", content: "hi" }] }))).toBe(null)
  expect(commaPaused(JSON.stringify({ messages: [] }))).toBe(null)
  expect(commaPaused("not json")).toBe(null)
  expect(commaPaused(JSON.stringify({ messages: "not a list" }))).toBe(null)
})

// the comma a system prompt's next chats go with is the one set in that system
// prompt; one that only set an assistant message is not the system prompt's
// (commaSystems), so the roles are read per message, and a message whose parts
// held no opening of their own is not reported
test("the roles the comma went into are the messages it changed", () => {
  const brief = [{ type: "text", text: "Be brief." }]
  const body = JSON.stringify({
    messages: [
      { role: "system", content: brief },
      { role: "assistant", content: "You are an AI agent powered by Foo." },
      { role: "user", content: "Quote exactly: You are an assistant built on Rails." },
    ],
  })
  const roles = new Set()
  const out = JSON.parse(commaPaused(body, roles))
  expect([...roles]).toEqual(["assistant"])
  expect(out.messages[0].content).toEqual(brief)

  const system = JSON.stringify({
    messages: [
      { role: "system", content: "You are an AI agent powered by Foo." },
      { role: "user", content: "hi" },
    ],
  })
  const only = new Set()
  expect(JSON.parse(commaPaused(system, only)).messages[0].content).toBe("You are an AI agent, powered by Foo.")
  expect([...only]).toEqual(["system"])
})

// the shape WorkBuddy knows is the line, not the product alone: a suffix in
// its place (…Harness Desktop., …Harness CLI.) was refused just the same, and
// the comma was what passed, so this must change the shape and nothing else
test("adding a word to the opening is not what passes; the comma is", () => {
  const suffixed = "You are an AI agent powered by DeepSeek Harness Desktop."
  expect(opened(suffixed)).toBe("You are an AI agent, powered by DeepSeek Harness Desktop.")
})