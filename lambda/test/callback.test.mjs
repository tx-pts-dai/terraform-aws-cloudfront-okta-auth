import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { signPayload, verifyPayload } from "../auth.mjs";
import {
  claims,
  CLIENT_SECRET,
  config,
  cookieValue,
  HOST,
  location,
  makeEvent,
  makeHandler,
  makeKeyPair,
  NOW_MS,
  setCookies,
  signJwt,
} from "./helpers.mjs";

const kp = makeKeyPair();
const signingKey = createHmac("sha256", CLIENT_SECRET).update("cookie-signing-v1").digest();
const nowSeconds = Math.floor(NOW_MS / 1000);

function loginCookie(overrides = {}) {
  return signPayload(signingKey, { s: "state1", n: "nonce1", v: "verifier1", r: "/return?x=1", t: nowSeconds - 5, ...overrides });
}

function callbackEvent({ querystring = "code=abc&state=state1", cookie = loginCookie(), method = "GET" } = {}) {
  return makeEvent({ uri: config.callback_path, querystring, method, cookies: cookie ? [`${config.login_cookie}=${cookie}`] : [] });
}

function tokenRoute(idToken, status = 200) {
  return { [config.token_endpoint]: { status, body: status === 200 ? { id_token: idToken, token_type: "Bearer" } : { error: "invalid_grant" } } };
}

test("successful callback sets the session cookie and redirects to the stored path", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1" }));
  const { handler, fetch } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  const res = await handler(callbackEvent());

  assert.equal(res.status, "302");
  assert.equal(location(res), "/return?x=1");
  assert.equal(cookieValue(res, config.session_cookie), idToken);
  const session = setCookies(res).find((c) => c.startsWith(config.session_cookie));
  assert.match(session, /Max-Age=3600; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
  assert.equal(cookieValue(res, config.login_cookie), "");

  const tokenCall = fetch.calls.find((c) => c.url === config.token_endpoint);
  assert.equal(tokenCall.init.method, "POST");
  assert.equal(tokenCall.init.headers.authorization, `Basic ${Buffer.from(`${config.client_id}:${CLIENT_SECRET}`).toString("base64")}`);
  assert.equal(tokenCall.init.headers["content-type"], "application/x-www-form-urlencoded");
  const body = new URLSearchParams(tokenCall.init.body);
  assert.equal(body.get("grant_type"), "authorization_code");
  assert.equal(body.get("code"), "abc");
  assert.equal(body.get("code_verifier"), "verifier1");
  assert.equal(body.get("redirect_uri"), `https://${HOST}/_auth/callback`);
});

test("Okta error parameter yields 403 and clears the login cookie", async () => {
  const { handler, fetch } = makeHandler({ jwk: kp.jwk });
  const res = await handler(callbackEvent({ querystring: "error=access_denied&error_description=User+is+not+assigned&state=state1" }));
  assert.equal(res.status, "403");
  assert.match(res.body, /access_denied: User is not assigned/);
  assert.equal(cookieValue(res, config.login_cookie), "");
  assert.equal(fetch.calls.length, 0);
});

const badRequests = {
  "missing login cookie": { cookie: null },
  "bad cookie signature": { cookie: loginCookie().slice(0, -3) + "abc" },
  "expired login state": { cookie: loginCookie({ t: nowSeconds - 601 }) },
  "state mismatch": { querystring: "code=abc&state=other" },
  "missing state": { querystring: "code=abc" },
  "missing code": { querystring: "state=state1" },
};

for (const [name, opts] of Object.entries(badRequests)) {
  test(`${name} yields 400 without calling Okta`, async () => {
    const { handler, fetch } = makeHandler({ jwk: kp.jwk });
    const res = await handler(callbackEvent(opts));
    assert.equal(res.status, "400");
    assert.equal(cookieValue(res, config.login_cookie), "");
    assert.equal(fetch.calls.length, 0);
  });
}

test("POST to the callback is not allowed", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  assert.equal((await handler(callbackEvent({ method: "POST" }))).status, "405");
});

for (const status of [400, 500]) {
  test(`token endpoint ${status} yields 502`, async () => {
    const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute("", status) });
    const res = await handler(callbackEvent());
    assert.equal(res.status, "502");
    assert.equal(cookieValue(res, config.session_cookie), undefined);
  });
}

test("token endpoint network failure yields 502", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk, routes: { [config.token_endpoint]: new Error("ECONNRESET") } });
  assert.equal((await handler(callbackEvent())).status, "502");
});

test("nonce mismatch yields 401", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "wrong" }));
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  const res = await handler(callbackEvent());
  assert.equal(res.status, "401");
  assert.equal(cookieValue(res, config.session_cookie), undefined);
});

test("ID token signed by an unknown key yields 401", async () => {
  const other = makeKeyPair("k1");
  const idToken = signJwt(other.privateKey, claims({ nonce: "nonce1" }));
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  assert.equal((await handler(callbackEvent())).status, "401");
});

test("oversized ID token yields an explicit 500 instead of a login loop", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1", groups: Array(200).fill("group-name-that-is-long") }));
  assert.ok(idToken.length > 3900);
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  const res = await handler(callbackEvent());
  assert.equal(res.status, "500");
  assert.match(res.body, /too large/);
});

test("stored return path is re-validated before redirecting", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1" }));
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  const res = await handler(callbackEvent({ cookie: loginCookie({ r: "//evil.com" }) }));
  assert.equal(location(res), "/");
});

test("verifyPayload round-trips signPayload", () => {
  assert.deepEqual(verifyPayload(signingKey, signPayload(signingKey, { a: 1 })), { a: 1 });
});
