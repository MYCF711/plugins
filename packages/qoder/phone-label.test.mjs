// The card's name: what a phone sign-in shows, and the uuid it used to show.
//
// Both sites answer a phone account differently — Qoder CN gives the full
// number as `security_mobile`, QwenWork gives four digits as `name` beside a
// synthetic `phone_<uuid>@phone.local` email — and the card used to show a
// uuid for either. These lock the label, not the sign-in.

import { expect, test } from "bun:test"
import { _internal as x } from "./index.mjs"

test("maskPhone: 0086- / +86 / bare / already masked, always 3+4", () => {
  expect(x.maskPhone("0086-18970098051")).toBe("189****8051")
  expect(x.maskPhone("+86 189 7009 8051")).toBe("189****8051")
  expect(x.maskPhone("18970098051")).toBe("189****8051")
  expect(x.maskPhone("181****0632")).toBe("181****0632")
  // not a number → empty, so the label falls through to the next candidate
  expect(x.maskPhone("")).toBe("")
  expect(x.maskPhone(undefined)).toBe("")
  expect(x.maskPhone("123")).toBe("")
  // an 86-prefixed real number is not a country code
  expect(x.maskPhone("86123456789")).toBe("123****6789")
})

test("accountLabelOf: the phone first, then a real email, then the name, then the id", () => {
  // Qoder CN, measured: `security_mobile` is the full number
  expect(x.accountLabelOf({ id: "01a0cbf7-5fac-773b-ad7f-1caa4539a32d", name: "dsh18970098051", security_mobile: "18970098051" }, "01a0cbf7-5fac-773b-ad7f-1caa4539a32d", "dsh18970098051", "")).toBe("189****8051")
  // QwenWork's phone accounts: four digits as `name`, a synthetic email
  const synthetic = "phone_21089c96-6908-4178-b254-9d84c062b59d@phone.local"
  expect(x.accountLabelOf({ id: "21089c96-6908-4178-b254-9d84c062b59d", name: "8051", email: synthetic }, "21089c96-6908-4178-b254-9d84c062b59d", "8051", synthetic)).toBe("****8051")
  // an email sign-in keeps its email
  expect(x.accountLabelOf({ id: "u1", name: "DSH-MYCF", email: "1470292681@qq.com" }, "u1", "DSH-MYCF", "1470292681@qq.com")).toBe("1470292681@qq.com")
  // nothing usable but the id: the id, as before (never a fabricated name)
  expect(x.accountLabelOf({ id: "u1" }, "u1", "", "")).toBe("u1")
  // a synthetic phone email with no four-digit name is not shown at all
  expect(x.accountLabelOf({}, "u2", "", synthetic)).toBe("u2")
})
