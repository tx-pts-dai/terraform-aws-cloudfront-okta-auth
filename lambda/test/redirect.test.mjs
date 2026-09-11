import { test } from "node:test";
import assert from "node:assert/strict";
import { safeReturnTo } from "../auth.mjs";

test("safeReturnTo keeps same-site paths with query strings", () => {
  assert.equal(safeReturnTo("/a/b?x=1&y=2"), "/a/b?x=1&y=2");
  assert.equal(safeReturnTo("/"), "/");
});

const rejected = [
  "//evil.com",
  "/\\evil.com",
  "https://evil.com",
  "javascript:alert(1)",
  "/path\\x",
  "/path\nX",
  "/_auth/callback",
  "/_auth",
  "",
  "/" + "a".repeat(3000),
  undefined,
];

for (const input of rejected) {
  test(`safeReturnTo rejects ${JSON.stringify(input)}`, () => {
    assert.equal(safeReturnTo(input), "/");
  });
}
