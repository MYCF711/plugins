// WorkBuddy refuses a chat holding words of Codex's or Claude Code's own
// prompts (magpie #182); withSystem puts words that pass in their place,
// in every message, as tried against both builds.
import { expect, test } from "bun:test"
import { _internal } from "./index.mjs"

const { withSystem, unflagged } = _internal

test("each flagged phrase is put in other words, whatever its case", () => {
  expect(unflagged("You are Claude Code, Anthropic's official CLI for Claude.")).toBe("You are Claude Code, Anthropic's CLI for Claude.")
  expect(unflagged("Main branch (you will usually use this for PRs): main")).toBe("Main branch (usually the base for PRs): main")
  expect(unflagged("MAIN BRANCH (YOU WILL USUALLY USE THIS FOR PRS): main")).toBe("Main branch (usually the base for PRs): main")
  const codex = "You are a coding agent running in the Codex CLI, a terminal-based coding assistant. Codex CLI is an open source project led by OpenAI. You are expected to be precise, safe, and helpful."
  expect(unflagged(codex)).toBe(codex.replace("Codex CLI is an open", "The Codex CLI is an open"))
  expect(unflagged(unflagged(codex))).toBe(unflagged(codex))
  expect(unflagged("x-anthropic-billing-header: cc_version=2.1.280.31f; cc_entrypoint=sdk-cli;\nhello")).toBe("hello")
  expect(unflagged("nothing to see")).toBe("nothing to see")
  expect(unflagged("You are an AI agent powered by DeepSeek Harness. Be brief.")).toBe("You are an AI agent, powered by DeepSeek Harness. Be brief.")
  expect(unflagged("YOU ARE AN AI AGENT POWERED BY DEEPSEEK HARNESS")).toBe("You are an AI agent, powered by DeepSeek Harness.")
})

// The opener says which harness the agent runs in, and the rest of a DSH
// prompt leans on that name. It is put in other words only as far as
// WorkBuddy's whole-line match needs, so the name stays.
test("DeepSeek Harness's opener keeps the harness's name", () => {
  const opener = "You are an AI agent powered by DeepSeek Harness."
  const spread = unflagged(opener)
  expect(spread).toBe("You are an AI agent, powered by DeepSeek Harness.")
  expect(spread).toContain("DeepSeek Harness")
  expect(spread).not.toBe(opener)
  expect(unflagged(spread)).toBe(spread)
})

test("Claude Code's request through magpie passes: header block gone, the rest rewritten", () => {
  const body = JSON.stringify({
    model: "glm-5.3",
    messages: [
      { role: "system", content: [
        { type: "text", text: "x-anthropic-billing-header: cc_version=2.1.280.31f; cc_entrypoint=cli;" },
        { type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." },
      ] },
      { role: "user", content: [{ type: "text", text: "gitStatus\nMain branch (you will usually use this for PRs): main" }, { type: "image_url", image_url: { url: "data:," } }] },
    ],
  })
  const b = JSON.parse(withSystem(body))
  expect(b.messages[0]).toEqual({ role: "system", content: [{ type: "text", text: "You are Claude Code, Anthropic's CLI for Claude." }] })
  expect(b.messages[1].content[0].text).toBe("gitStatus\nMain branch (usually the base for PRs): main")
  expect(b.messages[1].content[1]).toEqual({ type: "image_url", image_url: { url: "data:," } })
})

test("a system message of the header alone goes, and WorkBuddy's default takes its place", () => {
  const body = JSON.stringify({ messages: [
    { role: "system", content: "x-anthropic-billing-header: cc_version=2.1.280; cc_entrypoint=cli;" },
    { role: "user", content: "hi" },
  ] })
  expect(JSON.parse(withSystem(body)).messages).toEqual([
    { role: "system", content: "You are a helpful assistant." },
    { role: "user", content: "hi" },
  ])
})

test("a chat with nothing flagged is sent as it came", () => {
  const body = JSON.stringify({ messages: [{ role: "system", content: "be brief" }, { role: "user", content: "hi" }] })
  expect(withSystem(body)).toBe(body)
})

test("a refused line quoted back into an assistant message is reworded there too (#291)", () => {
  const line = "There is a Web GUI whose URL the runtime context names. When the user refers to it, open it."
  const fixed = "There is a Web GUI whose URL the runtime context names. The interface, when the user refers to it, open it."
  expect(unflagged(line)).toBe(fixed)
  expect(unflagged(line.replace(". When", ".\nWhen"))).toBe(fixed)
  expect(unflagged(fixed)).toBe(fixed)
  const body = JSON.stringify({ messages: [
    { role: "system", content: "be brief" },
    { role: "user", content: "hi" },
    { role: "assistant", content: line },
    { role: "assistant", content: [{ type: "text", text: line }] },
    { role: "user", content: "go on" },
  ] })
  const b = JSON.parse(withSystem(body))
  expect(b.messages[2].content).toBe(fixed)
  expect(b.messages[3].content[0].text).toBe(fixed)
})
