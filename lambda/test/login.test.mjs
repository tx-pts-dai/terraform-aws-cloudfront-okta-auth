import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { b64url, sha256, verifyPayload } from "../auth.mjs";
import { CLIENT_SECRET, config, cookieValue, HOST, location, makeEvent, makeHandler, setCookies } from "./helpers.mjs";

const signingKey = createHmac("sha256", CLIENT_SECRET).update("cookie-signing-v1").digest();

test("unauthenticated GET redirects to Okta authorize with PKCE and a signed login cookie", async () => {
  const { handler } = makeHandler();
  const res = await handler(makeEvent({ uri: "/docs/page", querystring: "a=1" }));
  assert.equal(res.status, "302");
  assert.equal(res.headers["cache-control"][0].value, "no-store");

  const url = new URL(location(res));
  assert.equal(`${url.origin}${url.pathname}`, config.authorize_endpoint);
  assert.equal(url.searchParams.get("client_id"), config.client_id);
  assert.equal(url.searchParams.get("redirect_uri"), `https://${HOST}/_auth/callback`);
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("scope"), "openid email profile");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");

  const cookies = setCookies(res);
  assert.equal(cookies.length, 1);
  assert.match(cookies[0], /^__Host-okta_login=.+; Max-Age=600; Path=\/; Secure; HttpOnly; SameSite=Lax$/);

  const login = verifyPayload(signingKey, cookieValue(res, config.login_cookie));
  assert.equal(login.s, url.searchParams.get("state"));
  assert.equal(login.n, url.searchParams.get("nonce"));
  assert.equal(b64url(sha256(login.v)), url.searchParams.get("code_challenge"));
  assert.equal(login.r, "/docs/page?a=1");
});

test("state and nonce are distinct random values", async () => {
  const { handler } = makeHandler();
  const url = new URL(location(await handler(makeEvent())));
  assert.notEqual(url.searchParams.get("state"), url.searchParams.get("nonce"));
  assert.ok(url.searchParams.get("state").length >= 43);
});

test("tampered login cookie fails verification", async () => {
  const { handler } = makeHandler();
  const value = cookieValue(await handler(makeEvent()), config.login_cookie);
  assert.equal(verifyPayload(signingKey, value.slice(0, -2) + "xx"), null);
  assert.equal(verifyPayload(signingKey, "junk"), null);
});

test("HEAD is redirected like GET, other methods get 401", async () => {
  const { handler } = makeHandler();
  assert.equal((await handler(makeEvent({ method: "HEAD" }))).status, "302");
  const post = await handler(makeEvent({ method: "POST" }));
  assert.equal(post.status, "401");
  assert.equal(post.headers["content-type"][0].value, "text/plain; charset=utf-8");
});

test("secret fetch failure is retried on the next request", async () => {
  let attempts = 0;
  const { handler } = makeHandler({
    getSecret: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("ssm down");
      return CLIENT_SECRET;
    },
  });
  assert.equal((await handler(makeEvent())).status, "500");
  assert.equal((await handler(makeEvent())).status, "302");
});

test("missing Host header is rejected", async () => {
  const { handler } = makeHandler();
  const event = makeEvent();
  delete event.Records[0].cf.request.headers.host;
  assert.equal((await handler(event)).status, "400");
});
