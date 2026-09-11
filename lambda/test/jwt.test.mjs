import { test } from "node:test";
import assert from "node:assert/strict";
import { b64url, TokenError, verifyJwt } from "../auth.mjs";
import { claims, config, makeEvent, makeHandler, makeKeyPair, NOW_MS, signJwt } from "./helpers.mjs";

const kp = makeKeyPair();
const nowSeconds = Math.floor(NOW_MS / 1000);
const getKey = async (kid) => (kid === kp.kid ? kp.publicKey : null);

function verify(token, extra = {}) {
  return verifyJwt({ token, getKey, issuer: config.issuer, clientId: config.client_id, nowSeconds, ...extra });
}

test("valid token passes and returns claims", async () => {
  const { payload } = await verify(signJwt(kp.privateKey, claims()));
  assert.equal(payload.sub, "user-1");
});

test("aud array containing the client id passes", async () => {
  await verify(signJwt(kp.privateKey, claims({ aud: ["other", config.client_id] })));
});

test("nonce is enforced when provided", async () => {
  await verify(signJwt(kp.privateKey, claims({ nonce: "n1" })), { nonce: "n1" });
  await assert.rejects(verify(signJwt(kp.privateKey, claims({ nonce: "n2" })), { nonce: "n1" }), TokenError);
});

const rejectedTokens = {
  "tampered payload": () => {
    const [h, , s] = signJwt(kp.privateKey, claims()).split(".");
    return `${h}.${b64url(JSON.stringify(claims({ sub: "attacker" })))}.${s}`;
  },
  "wrong iss": () => signJwt(kp.privateKey, claims({ iss: "https://evil.okta.com" })),
  "wrong aud": () => signJwt(kp.privateKey, claims({ aud: "other" })),
  expired: () => signJwt(kp.privateKey, claims({ exp: nowSeconds - 60 })),
  "iat far in the future": () => signJwt(kp.privateKey, claims({ iat: nowSeconds + 600 })),
  "alg none": () => {
    const h = b64url(JSON.stringify({ alg: "none", kid: kp.kid }));
    return `${h}.${b64url(JSON.stringify(claims()))}.`;
  },
  "alg HS256": () => signJwt(kp.privateKey, claims(), { alg: "HS256" }),
  "missing kid": () => signJwt(kp.privateKey, claims(), { kid: undefined }),
  "unknown kid": () => signJwt(kp.privateKey, claims(), { kid: "other" }),
  "two segments": () => "a.b",
  garbage: () => "not-a-token",
};

for (const [name, make] of Object.entries(rejectedTokens)) {
  test(`rejects ${name}`, async () => {
    await assert.rejects(verify(make()), TokenError);
  });
}

test("expiry tolerates 30 seconds of clock skew", async () => {
  await verify(signJwt(kp.privateKey, claims({ exp: nowSeconds - 10 })));
});

test("JWKS is fetched once and cached across requests", async () => {
  const { handler, fetch } = makeHandler({ jwk: kp.jwk });
  const token = signJwt(kp.privateKey, claims());
  const event = () => makeEvent({ uri: "/page", cookies: [`${config.session_cookie}=${token}`] });
  const first = await handler(event());
  const second = await handler(event());
  assert.equal(first.uri, "/page");
  assert.equal(second.uri, "/page");
  assert.equal(fetch.calls.filter((c) => c.url === config.jwks_endpoint).length, 1);
});

test("unknown kid triggers exactly one refetch, rate limited to once per minute", async () => {
  const rotated = makeKeyPair("k2");
  let keys = [kp.jwk];
  const { handler, fetch, clock } = makeHandler({
    routes: { [config.jwks_endpoint]: () => ({ status: 200, body: { keys } }) },
  });
  const rotatedToken = signJwt(rotated.privateKey, claims(), { kid: "k2" });
  const event = () => makeEvent({ uri: "/page", cookies: [`${config.session_cookie}=${rotatedToken}`] });

  const beforeRotation = await handler(event());
  assert.equal(beforeRotation.status, "302");
  assert.equal(fetch.calls.length, 2);

  const againWithinMinute = await handler(event());
  assert.equal(againWithinMinute.status, "302");
  assert.equal(fetch.calls.length, 2);

  keys = [kp.jwk, rotated.jwk];
  clock.ms += 61_000;
  const afterRotation = await handler(event());
  assert.equal(afterRotation.uri, "/page");
  assert.equal(fetch.calls.length, 3);
});

test("JWKS cache is refreshed after one hour", async () => {
  const { handler, fetch, clock } = makeHandler({ jwk: kp.jwk });
  const token = signJwt(kp.privateKey, claims({ exp: nowSeconds + 10_000 }));
  const event = () => makeEvent({ uri: "/page", cookies: [`${config.session_cookie}=${token}`] });
  await handler(event());
  clock.ms += 3_600_001;
  await handler(event());
  assert.equal(fetch.calls.filter((c) => c.url === config.jwks_endpoint).length, 2);
});

test("JWKS refresh failure keeps the cached keys", async () => {
  let fail = false;
  const { handler, clock } = makeHandler({
    routes: {
      [config.jwks_endpoint]: () => (fail ? { status: 500, body: {} } : { status: 200, body: { keys: [kp.jwk] } }),
    },
  });
  const token = signJwt(kp.privateKey, claims({ exp: nowSeconds + 10_000 }));
  const event = () => makeEvent({ uri: "/page", cookies: [`${config.session_cookie}=${token}`] });
  await handler(event());
  fail = true;
  clock.ms += 3_600_001;
  const res = await handler(event());
  assert.equal(res.uri, "/page");
});
