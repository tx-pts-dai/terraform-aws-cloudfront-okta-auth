import { test } from "node:test";
import assert from "node:assert/strict";
import { claims, config, cookieValue, HOST, location, makeEvent, makeHandler, makeKeyPair, NOW_MS, signJwt } from "./helpers.mjs";

const kp = makeKeyPair();
const nowSeconds = Math.floor(NOW_MS / 1000);

test("valid session passes the request through with auth cookies stripped", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  const token = signJwt(kp.privateKey, claims());
  const event = makeEvent({
    uri: "/index.html",
    cookies: [`theme=dark; ${config.session_cookie}=${token}`, `${config.login_cookie}=x`],
    headers: { "user-agent": [{ key: "User-Agent", value: "test" }] },
  });
  const res = await handler(event);
  assert.equal(res.uri, "/index.html");
  assert.deepEqual(res.headers.cookie, [{ key: "Cookie", value: "theme=dark" }]);
  assert.equal(res.headers["user-agent"][0].value, "test");
  assert.equal(res.headers.host[0].value, HOST);
});

test("expired session starts a new login", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  const token = signJwt(kp.privateKey, claims({ exp: nowSeconds - 120 }));
  const res = await handler(makeEvent({ uri: "/page", cookies: [`${config.session_cookie}=${token}`] }));
  assert.equal(res.status, "302");
  assert.ok(location(res).startsWith(config.authorize_endpoint));
});

test("garbage session cookie starts a new login", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  const res = await handler(makeEvent({ cookies: [`${config.session_cookie}=garbage`] }));
  assert.equal(res.status, "302");
});

test("logout clears the session and redirects to Okta with id_token_hint", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  const token = signJwt(kp.privateKey, claims());
  const res = await handler(makeEvent({ uri: config.logout_path, cookies: [`${config.session_cookie}=${token}`] }));
  assert.equal(res.status, "302");
  const url = new URL(location(res));
  assert.equal(`${url.origin}${url.pathname}`, config.logout_endpoint);
  assert.equal(url.searchParams.get("id_token_hint"), token);
  assert.equal(url.searchParams.get("post_logout_redirect_uri"), `https://${HOST}/`);
  assert.equal(cookieValue(res, config.session_cookie), "");
});

test("logout without a session redirects to the site root", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  const res = await handler(makeEvent({ uri: config.logout_path }));
  assert.equal(location(res), "/");
  assert.equal(cookieValue(res, config.session_cookie), "");
});

test("JWKS unreachable with an empty cache yields 503, not a redirect loop", async () => {
  const { handler } = makeHandler({ routes: { [config.jwks_endpoint]: new Error("ENOTFOUND") } });
  const token = signJwt(kp.privateKey, claims());
  const res = await handler(makeEvent({ cookies: [`${config.session_cookie}=${token}`] }));
  assert.equal(res.status, "503");
});
