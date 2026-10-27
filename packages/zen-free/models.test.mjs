import assert from "node:assert/strict";
import test from "node:test";

const subject = import("./models.mjs").catch(() => ({}));
const provider = {
  npm: "@ai-sdk/openai-compatible",
  models: {
    "coder-free": {
      name: "Coder Free",
      cost: { input: 0, output: 0 },
      limit: { context: 200000, input: 160000, output: 32000 },
      reasoning: true,
      tool_call: true,
      modalities: { input: ["text", "image"], output: ["text"] },
      reasoning_options: [{ type: "effort", values: ["low", "high"] }],
    },
    "zero-cost": { cost: { input: 0, output: 0 } },
    paid: { cost: { input: 1, output: 3 } },
    "old-free": { status: "deprecated", cost: { input: 0, output: 0 } },
    "decision-free": { provider: { npm: "@vendor/systemone" } },
    "responses-free": { provider: { npm: "@ai-sdk/openai" } },
    "messages-free": { provider: { npm: "@ai-sdk/anthropic" } },
    "gone-free": {},
  },
};
const ids = Object.keys(provider.models).filter((id) => id !== "gone-free");
const baseURL = "https://opencode.ai/zen/v1";

test("lists only live free models with supported protocols and excludes retired models", async () => {
  const { buildModels } = await subject;
  assert.equal(typeof buildModels, "function", "model discovery must be implemented");
  const models = buildModels(ids, provider, {}, baseURL);
  assert.deepEqual(Object.keys(models).sort(), [
    "coder-free",
    "messages-free",
    "responses-free",
    "zero-cost",
  ]);
  assert.equal(models["coder-free"].free, true);
  assert.equal(models["coder-free"].providerID, "opencode-zen-free");
  assert.deepEqual(models["coder-free"].limit, { context: 200000, input: 160000, output: 32000 });
  assert.equal(models["coder-free"].capabilities.input.image, true);
  assert.equal(models["coder-free"].capabilities.toolcall, true);
  assert.deepEqual(Object.keys(models["coder-free"].variants), ["low", "high"]);
  assert.equal(models["responses-free"].api.npm, "@ai-sdk/openai");
  assert.equal(models["messages-free"].api.npm, "@ai-sdk/anthropic");
});

test("endpoint documentation overrides inherited SDK and excludes SystemOne", async () => {
  const { buildModels, parseProtocolDocs } = await subject;
  assert.equal(typeof parseProtocolDocs, "function", "protocol parsing must be implemented");
  const protocols = parseProtocolDocs(
    [
      "| Coder | coder-free | `https://opencode.ai/zen/v1/messages` | sdk |",
      "| Decision | decision-free | `https://opencode.ai/zen/v1/systemone` | - |",
    ].join("\n"),
  );
  const models = buildModels(ids, provider, protocols, baseURL);
  assert.equal(models["coder-free"].api.npm, "@ai-sdk/anthropic");
  assert.equal(models["decision-free"], undefined);
});

// A model Zen lists as -free before the catalog or the docs describe it is
// asked as the provider's own package asks (chat), as OpenCode asks a model
// with no package of its own (yetone/magpie#2385); anything else unknown
// still needs their word.
test("an unknown -free model is offered on the provider's package; another unknown model is not", async () => {
  const { buildModels } = await subject;
  assert.equal(typeof buildModels, "function", "model discovery must be implemented");
  assert.deepEqual(
    Object.keys(buildModels(["new-free", "unknown-paid", "freebie", "free-model"], {}, {}, baseURL)),
    ["new-free"],
  );
  assert.equal(buildModels(["new-free"], {}, {}, baseURL)["new-free"].api.npm, "@ai-sdk/openai-compatible");
  assert.equal(
    buildModels(["new-free"], { npm: "@ai-sdk/openai" }, {}, baseURL)["new-free"].api.npm,
    "@ai-sdk/openai",
  );
  // the docs saying SystemOne keep it out
  assert.deepEqual(Object.keys(buildModels(["new-free"], {}, { "new-free": "systemone" }, baseURL)), []);
  const models = buildModels(["new-free"], {}, { "new-free": "chat" }, baseURL);
  assert.equal(models["new-free"].api.url, baseURL);
  assert.equal(models["new-free"].cost.input, 0);
});

// Rows as OpenCode's console docs have them since 2026-10-12
// (services/www/src/docs/content/console/models.mdx), and the pricing
// table beside it that names no endpoint (#2305 on yetone/magpie).
const consoleDocs = [
  "| Claude Haiku 4.5                | claude-haiku-4-5                | `https://opencode.ai/inference/v1/messages`                     | `@ai-sdk/anthropic`         |",
  "| Gemini 3 Flash                  | gemini-3-flash                  | `https://opencode.ai/inference/v1/models/gemini-3-flash`        | `@ai-sdk/google`            |",
  "| Jev 1.13 Free                   | jev-1.13-free                   | `https://opencode.ai/inference/v1/systemone`                    | -                           |",
  "| Big Pickle                      | big-pickle                      | `https://opencode.ai/inference/v1/chat/completions`             | `@ai-sdk/openai-compatible` |",
  "| Step 5 Preview Free             | step-5-preview-free             | `https://opencode.ai/inference/v1/chat/completions`             | `@ai-sdk/openai-compatible` |",
  "| Muse Spark 1.3 Contributor Free | muse-spark-1.3-contributor-free | `https://opencode.ai/inference/v1/responses`                    | `@ai-sdk/openai`            |",
  "| Step 5 Preview Free               | Free            | Free            | Free            | -            |",
].join("\n");

test("reads the console docs' endpoint table, and Jev stays out as SystemOne", async () => {
  const { buildModels, parseProtocolDocs, bootstrapProtocols } = await subject;
  const protocols = parseProtocolDocs(consoleDocs);
  assert.deepEqual(protocols, {
    "claude-haiku-4-5": "anthropic",
    "jev-1.13-free": "systemone",
    "big-pickle": "chat",
    "step-5-preview-free": "chat",
    "muse-spark-1.3-contributor-free": "responses",
  });
  // the snapshot kept for when the docs can't be read says the same
  for (const [id, protocol] of Object.entries(protocols)) {
    if (bootstrapProtocols[id]) assert.equal(bootstrapProtocols[id], protocol, id);
  }
  const models = buildModels(["jev-1.13-free", "step-5-preview-free"], {}, protocols, baseURL);
  assert.deepEqual(Object.keys(models), ["step-5-preview-free"]);
});

// The catalog's 200000 for deepseek-v4.1-flash-free is stale: Zen's free
// tier answered a 258,624-token request and refused 283,545 as over the
// maximum (magpie routing history, 2026-10-26), so the model takes the
// 258K (264,192) window the paid model is listed with.
test("deepseek-v4.1-flash-free keeps its measured 258K window over a stale 200K catalog", async () => {
  const { buildModels } = await subject;
  const model = {
    name: "DeepSeek V4.1 Flash Free",
    cost: { input: 0, output: 0 },
    limit: { context: 200000, output: 32000 },
    reasoning: true,
    tool_call: true,
  };
  const models = buildModels(
    ["deepseek-v4.1-flash-free"],
    { npm: "@ai-sdk/openai-compatible", models: { "deepseek-v4.1-flash-free": model } },
    {},
    baseURL,
  );
  assert.equal(models["deepseek-v4.1-flash-free"].limit.context, 264192);
  assert.equal(models["deepseek-v4.1-flash-free"].limit.output, 32000);
});
