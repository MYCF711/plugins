// The four probe tests from the review of #522, kept as regression tests (the
// only edit is the test import, so they run under `node --test` too).
import { test } from "node:test"
import assert from "node:assert/strict"
import os from "node:os"
import path from "node:path"
import { CodeArtsAuthPlugin, OfficeAceAuthPlugin, _internal as x, _officeace as oa } from "./index.mjs"

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url")
const URN = "iam::d1:user:hwprobe"
const rt = (jti) => `h.${b64u({ jti, user_profile: JSON.stringify({ principal_urn: URN, principal_id: "pid", account_id: "01a1642ad2ae7f93bf6387ad2fc5f09e" }) })}.s`
const opts = (fetcher) => ({ fetch: fetcher, ledgerPath: path.join(os.tmpdir(), `probe-${Math.random()}.json`) })

async function records() {
  const kp = await x.generateDpopKeyPair()
  // the officeace-auth record: its own chain X, issued to pdp5_for_agentarts
  const oaCred = { modelAppKey: "app-key", modelAppSecret: "app-secret", maasBaseUrl: "", access: "AK-X", secret: "SK-X",
    securityToken: "ST-X", projectId: "", expiresAt: "2031-01-01T00:00:00Z", refreshToken: rt("X1"), codeVerifier: "",
    dpopPrivateJwk: kp.privateKeyJwk, accountId: "01a1642ad2ae7f93bf6387ad2fc5f09e" }
  const officeace = { type: "oauth", access: JSON.stringify(oaCred), refresh: rt("X1"), expires: Date.parse("2031-01-01T00:00:00Z"),
    accountId: "01a1642ad2ae7f93bf6387ad2fc5f09e", uid: "01a1642ad2ae7f93bf6387ad2fc5f09e" }
  // the codearts record of the same account: its own chain Y (signed in before 0.3.0)
  const caCred = { access_key_id: "AK-Y", secret_access_key: "SK-Y", security_token: "ST-Y", expires_at: "2031-01-01T00:00:00Z",
    refresh_token: rt("Y1"), code_verifier: "v", dpop_private_key_jwk: kp.privateKeyJwk, session_id: "0123456789abcdef0123456789abcdef",
    user_phone: "189****8051" }
  const codearts = { type: "oauth", access: JSON.stringify(caCred), refresh: rt("Y1"), expires: Date.parse("2031-01-01T00:00:00Z"), accountId: URN, uid: URN }
  return { officeace, codearts }
}

test("probe: an officeace-auth record's renewal stays on its own chain after a CodeArts usage read", async () => {
  oa.liveAccounts.clear(); oa.renewalGates.clear()
  const { officeace, codearts } = await records()
  const sts = []
  const fetcher = async (url, init) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) { sts.push(String(init?.body)); return new Response(JSON.stringify({ credentials: { access_key_id: "AK-X2", secret_access_key: "s", security_token: "t", expiration: "2031-01-02T00:00:00Z" }, refresh_token: rt("X2") }), { status: 200 }) }
    return new Response("{}", { status: 200 })
  }
  const ca = await CodeArtsAuthPlugin({ client: { auth: { set: async () => {} } } }, opts(fetcher))
  const of = await OfficeAceAuthPlugin({ client: { auth: { set: async () => {} } } }, { fetch: fetcher })
  await ca.auth.usage(async () => codearts) // magpie polls usage of every account
  const out = await of.auth.refresh(officeace)
  const got = JSON.parse(out.access)
  console.log("STS calls:", sts.length, "returned access:", got.access, "oauth_client:", got.oauth_client, "modelAppKey:", JSON.stringify(got.modelAppKey), "accountId:", out.accountId)
  assert.equal(sts.length, 1, "the old record's own refresh token should be spent at STS")
  assert.equal(got.access, "AK-X2")
})

test("probe: a CodeArts renewal that fails at STS is not handed the OfficeAce chain", async () => {
  oa.liveAccounts.clear(); oa.renewalGates.clear()
  const { officeace, codearts } = await records()
  const fetcher = async (url) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) return new Response("upstream down", { status: 503 })
    return new Response("{}", { status: 200 })
  }
  const ca = await CodeArtsAuthPlugin({ client: { auth: { set: async () => {} } } }, opts(fetcher))
  const of = await OfficeAceAuthPlugin({ client: { auth: { set: async () => {} } } }, { fetch: fetcher })
  await of.auth.usage(async () => officeace)
  let out, err
  try { out = await ca.auth.refresh(codearts) } catch (e) { err = e }
  const got = out && JSON.parse(out.access)
  console.log("codearts refresh ->", err ? `threw ${err.message}` : `access_key_id ${got.access_key_id}, oauth_client ${got.oauth_client}, refresh ${got.refresh_token === rt("X1") ? "X1 (officeace's)" : got.refresh_token}`)
  assert.ok(err || got.access_key_id !== "AK-X")
})

test("probe: a new OfficeAce sign-in's accountId", async () => {
  oa.seenProviderAccounts.clear(); oa.liveAccounts.clear(); oa.sharedAccountKeys.clear()
  const fetcher = async (url) => {
    if (String(url) === x.STS_TOKEN_ENDPOINT) return new Response(JSON.stringify({ credentials: { access_key_id: "AK-N", secret_access_key: "s", security_token: "t", expiration: "2031-01-02T00:00:00Z" }, refresh_token: rt("N1") }), { status: 200 })
    if (String(url).includes("iam.cn-north-4")) return new Response(JSON.stringify({ user: { phone: "0086-18970098051" } }), { status: 200 })
    return new Response("{}", { status: 200 })
  }
  const of = await OfficeAceAuthPlugin({ client: { auth: { set: async () => {} } } }, { fetch: fetcher })
  const a = await of.auth.methods[0].authorize()
  const done = a.callback()
  const port = new URL(a.url).searchParams.get("port")
  await fetch(`http://127.0.0.1:${port}${x.REDIRECT_PATH}?code=C1`, { redirect: "manual" })
  const out = await done
  console.log("officeace sign-in accountId:", out.accountId, "uid:", out.uid)
  assert.notEqual(out.accountId, "189****8051", "accountId must be the vendor's stable id, not the masked phone")
})

test("probe: an officeace record renewal keeps the stored accountId", async () => {
  oa.liveAccounts.clear(); oa.renewalGates.clear()
  const { officeace } = await records()
  const stored = { ...officeace, accountId: "189****8051" } // what officeace-auth 0.1.14 stored
  const cred = JSON.parse(stored.access); delete cred.user_phone
  stored.access = JSON.stringify(cred)
  const fetcher = async (url) => String(url) === x.STS_TOKEN_ENDPOINT
    ? new Response(JSON.stringify({ credentials: { access_key_id: "AK-X2", secret_access_key: "s", security_token: "t", expiration: "2031-01-02T00:00:00Z" }, refresh_token: rt("X2") }), { status: 200 })
    : new Response("{}", { status: 200 })
  const of = await OfficeAceAuthPlugin({ client: { auth: { set: async () => {} } } }, { fetch: fetcher })
  const out = await of.auth.refresh(stored)
  console.log("stored accountId 189****8051 -> refresh returns accountId:", out.accountId)
  assert.ok(out.accountId === undefined || out.accountId === "189****8051")
})
