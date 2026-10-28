// Every model a site ships says whether it takes images — either way.
//
// A kind left out is not "text only" to magpie: it is "the vendor didn't
// say", and magpie then falls back to models.dev's vote by bare model id,
// where a same-named model of another vendor that takes images licenses
// sending them to this one. The shipped list is what magpie has before
// anyone signs in, and what `provider.models` falls back to when a listing
// can't be fetched, so those entries are the ones most likely to be asked
// for an image — and the ones with nothing to answer with.
//
// Measured before the fix (magpie 0.1.1932): all three QwenWork models and
// all three of its enterprise sibling's were `imageSaid: false` in
// ~/.cache/magpie/plugin-providers.json, i.e. magpie had to guess. The same
// omission in codearts 0.2.3 sent 161 screenshots to a model that answers
// `InferHub.001001020.406` "The request model is not multimodal".
import { test, expect } from "bun:test"

import {
  QoderAuthPlugin,
  QoderCNAuthPlugin,
  QwenWorkAuthPlugin,
  QwenWorkEnterpriseAuthPlugin,
} from "./index.mjs"

const client = {
  app: { log: async () => {} },
  auth: { set: async () => {} },
  tui: { showToast: async () => {} },
  config: { get: async () => ({ data: {} }) },
}
const load = (fn) => fn({ client, directory: process.cwd(), worktree: process.cwd(), $: undefined, project: {} })

const SITES = [
  ["qoder", QoderAuthPlugin],
  ["qoder-cn", QoderCNAuthPlugin],
  ["qwenwork", QwenWorkAuthPlugin],
  ["qwenwork-enterprise", QwenWorkEnterpriseAuthPlugin],
]

test("every model a site ships says, either way, whether it takes images", async () => {
  for (const [id, fn] of SITES) {
    const plugin = await load(fn)
    const cfg = {}
    await plugin.config(cfg)
    const models = Object.entries(cfg.provider[id]?.models ?? {})
    expect(models.length, `${id}: the config hook lists models`).toBeGreaterThan(0)
    for (const [key, m] of models) {
      const where = `${id}/${key}`
      expect(Array.isArray(m.modalities?.input), `${where}: modalities.input is a list`).toBe(true)
      expect(m.modalities.input.includes("text"), `${where}: takes text`).toBe(true)
      expect(
        m.attachment,
        `${where}: attachment matches modalities.input (${JSON.stringify(m.modalities.input)})`,
      ).toBe(m.modalities.input.includes("image"))
    }
  }
})

test("a model that takes images says so, one that doesn't says text alone", async () => {
  // qoder's list is all vision (MODELS maps images: true onto every entry)
  const qoder = await load(QoderAuthPlugin)
  const qoderCfg = {}
  await qoder.config(qoderCfg)
  for (const m of Object.values(qoderCfg.provider.qoder.models)) {
    expect(m.attachment).toBe(true)
    expect(m.modalities.input).toEqual(["text", "image"])
  }

  // QwenWork ships no image key, so every one of its models is text only
  const qwenwork = await load(QwenWorkAuthPlugin)
  const qwCfg = {}
  await qwenwork.config(qwCfg)
  for (const m of Object.values(qwCfg.provider.qwenwork.models)) {
    expect(m.attachment).toBe(false)
    expect(m.modalities.input).toEqual(["text"])
    expect(m.modalities.output).toEqual(["text"])
  }
})
