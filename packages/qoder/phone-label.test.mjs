// The card's name: what a phone sign-in shows, and the uuid it used to show.
//
// Both sites answer a phone account differently — Qoder CN gives the full
// number as `security_mobile`, QwenWork gives four digits as `name` beside a
// synthetic `phone_<uuid>@phone.local` email — and the card used to show a
// uuid for either. These lock the label, not the sign-in.

import { expect, test } from "bun:test"
import { _internal as x } from "./index.mjs"

test("maskPhone: 0086- / +86 / bare / already masked, always 3+4", () => {
  expect(x.maskPhone("0086-13800138000")).toBe("138****8000")
  expect(x.maskPhone("+86 138 0013 8000")).toBe("138****8000")
  expect(x.maskPhone("13800138000")).toBe("138****8000")
  expect(x.maskPhone("139****1234")).toBe("139****1234")
  // not a number → empty, so the label falls through to the next candidate
  expect(x.maskPhone("")).toBe("")
  expect(x.maskPhone(undefined)).toBe("")
  expect(x.maskPhone("123")).toBe("")
  // a number that merely starts with 86 is not a country code either
  expect(x.maskPhone("86123456789")).toBe("123****6789")
})

test("accountLabelOf: a name carrying the whole number is masked (review #487, E)", () => {
  expect(x.accountLabelOf({ id: "u", name: "dsh13800138000" }, "u", "dsh13800138000", "")).toBe("dsh138****8000")
  expect(x.maskedName("1234567")).toBe("123****4567")
  expect(x.maskedName("user12345")).toBe("user12345")
  expect(x.maskedName("Bob")).toBe("Bob")
})

test("accountLabelOf: the phone first, then a real email, then the name, then the id", () => {
  // Qoder CN, measured: `security_mobile` is the full number
  expect(x.accountLabelOf({ id: "11111111-2222-3333-4444-555555555555", name: "dsh13800138000", security_mobile: "13800138000" }, "11111111-2222-3333-4444-555555555555", "dsh13800138000", "")).toBe("138****8000")
  // QwenWork's phone accounts: four digits as `name`, a synthetic email
  const synthetic = "phone_66666666-7777-8888-9999-000000000000@phone.local"
  expect(x.accountLabelOf({ id: "66666666-7777-8888-9999-000000000000", name: "8000", email: synthetic }, "66666666-7777-8888-9999-000000000000", "8000", synthetic)).toBe("****8000")
  // an email sign-in keeps its email
  expect(x.accountLabelOf({ id: "u1", name: "DSH-MYCF", email: "someone@example.com" }, "u1", "DSH-MYCF", "someone@example.com")).toBe("someone@example.com")
  // nothing usable but the id: the id, as before (never a fabricated name)
  expect(x.accountLabelOf({ id: "u1" }, "u1", "", "")).toBe("u1")
  // a synthetic phone email with no four-digit name is not shown at all
  expect(x.accountLabelOf({}, "u2", "", synthetic)).toBe("u2")
})
