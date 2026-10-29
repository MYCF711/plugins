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
  // already masked → fewer than 11 digits → not a number to mask again
  expect(x.maskPhone("139****1234")).toBe("")
  // not a number → empty, so the label falls through to the next candidate
  expect(x.maskPhone("")).toBe("")
  expect(x.maskPhone(undefined)).toBe("")
  expect(x.maskPhone("123")).toBe("")
  // a number that merely starts with 86 is not a country code either
  expect(x.maskPhone("86123456789")).toBe("")
})

test("phoneLabelOf: the phone, or a synthetic email's four digits, else nothing", () => {
  expect(x.phoneLabelOf({ security_mobile: "13800138000" }, "", "")).toBe("138****8000")
  const synthetic = "phone_66666666-7777-8888-9999-000000000000@phone.local"
  expect(x.phoneLabelOf({ name: "8000", email: synthetic }, synthetic, "8000")).toBe("****8000")
  expect(x.phoneLabelOf({ id: "u1" }, "", "")).toBe("")
})

test("realEmailOf: a real email, never a synthetic phone one", () => {
  expect(x.realEmailOf("someone@example.com")).toBe("someone@example.com")
  expect(x.realEmailOf("phone_66666666-7777-8888-9999-000000000000@phone.local")).toBe("")
  expect(x.realEmailOf("")).toBe("")
  expect(x.realEmailOf(undefined)).toBe("")
})
