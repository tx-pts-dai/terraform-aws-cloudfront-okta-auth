import { test } from "node:test";
import assert from "node:assert/strict";
import { clearCookie, makeCookie, parseCookies, stripCookies } from "../auth.mjs";

test("parseCookies merges multiple cookie headers and keeps the first duplicate", () => {
  const headers = {
    cookie: [
      { key: "Cookie", value: "a=1; b=two" },
      { key: "Cookie", value: "c=3;a=ignored" },
    ],
  };
  assert.deepEqual(parseCookies(headers), { a: "1", b: "two", c: "3" });
});

test("parseCookies tolerates missing header and malformed parts", () => {
  assert.deepEqual(parseCookies({}), {});
  assert.deepEqual(parseCookies({ cookie: [{ key: "Cookie", value: "novalue; =x; ok=1" }] }), { ok: "1" });
});

test("makeCookie sets hardened attributes", () => {
  assert.equal(makeCookie("n", "v", 60), "n=v; Max-Age=60; Path=/; Secure; HttpOnly; SameSite=Lax");
  assert.equal(clearCookie("n"), "n=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax");
});

test("stripCookies removes only the named cookies", () => {
  const headers = {
    host: [{ key: "Host", value: "h" }],
    cookie: [{ key: "Cookie", value: "__Host-okta_session=tok; theme=dark; __Host-okta_login=x" }],
  };
  const out = stripCookies(headers, ["__Host-okta_session", "__Host-okta_login"]);
  assert.deepEqual(out.cookie, [{ key: "Cookie", value: "theme=dark" }]);
  assert.deepEqual(out.host, headers.host);
});

test("stripCookies drops the header when nothing remains", () => {
  const out = stripCookies({ cookie: [{ key: "Cookie", value: "__Host-okta_session=tok" }] }, ["__Host-okta_session"]);
  assert.equal(out.cookie, undefined);
});
