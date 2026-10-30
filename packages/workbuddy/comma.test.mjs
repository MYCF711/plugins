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

test("commaPaused sets the comma in every message, the system one among them", () => {
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

test("commaPaused sets it in a message's parts too", () => {
  const body = JSON.stringify({
    messages: [
      { role: "system", content: [{ type: "text", text: "You are an AI agent powered by DeepSeek Harness." }] },
      { role: "user", content: [{ type: "text", text: "hi" }] },
    ],
  })
  const out = JSON.parse(commaPaused(body))
  expect(out.messages[0].content[0].text).toBe("You are an AI agent, powered by DeepSeek Harness.")
  expect(out.messages[1].content[0].text).toBe("hi")
})

test("a chat with nothing of the kind is not resent", () => {
  expect(commaPaused(JSON.stringify({ messages: [{ role: "system", content: "be brief" }, { role: "user", content: "hi" }] }))).toBe(null)
  expect(commaPaused(JSON.stringify({ messages: [] }))).toBe(null)
  expect(commaPaused("not json")).toBe(null)
  expect(commaPaused(JSON.stringify({ messages: "not a list" }))).toBe(null)
})

// the shape WorkBuddy knows is the line, not the product alone: a suffix in
// its place (…Harness Desktop., …Harness CLI.) was refused just the same, and
// the comma was what passed, so this must change the shape and nothing else
test("adding a word to the opening is not what passes; the comma is", () => {
  const suffixed = "You are an AI agent powered by DeepSeek Harness Desktop."
  expect(opened(suffixed)).toBe("You are an AI agent, powered by DeepSeek Harness Desktop.")
})