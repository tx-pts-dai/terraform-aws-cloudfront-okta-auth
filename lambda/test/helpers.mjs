import { generateKeyPairSync, sign } from "node:crypto";
import { b64url, createHandler } from "../auth.mjs";

export const config = {
  issuer: "https://acme.okta.com",
  client_id: "0oa123",
  authorize_endpoint: "https://acme.okta.com/oauth2/v1/authorize",
  token_endpoint: "https://acme.okta.com/oauth2/v1/token",
  jwks_endpoint: "https://acme.okta.com/oauth2/v1/keys",
  logout_endpoint: "https://acme.okta.com/oauth2/v1/logout",
  callback_path: "/_auth/callback",
  logout_path: "/_auth/logout",
  secret_parameter_name: "/test/okta-client-secret",
  secret_region: "us-east-1",
  session_cookie: "__Host-okta_session",
  login_cookie: "__Host-okta_login",
};

export const CLIENT_SECRET = "s3cret";
export const HOST = "site.example.com";
export const NOW_MS = 1_800_000_000_000;

export function makeKeyPair(kid = "k1") {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" };
  return { publicKey, privateKey, jwk, kid };
}

export function signJwt(privateKey, payload, header = {}) {
  const h = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "k1", ...header }));
  const p = b64url(JSON.stringify(payload));
  const sig = sign("sha256", Buffer.from(`${h}.${p}`), privateKey).toString("base64url");
  return `${h}.${p}.${sig}`;
}

export function claims(overrides = {}) {
  const nowS = Math.floor(NOW_MS / 1000);
  return {
    iss: config.issuer,
    aud: config.client_id,
    sub: "user-1",
    iat: nowS - 10,
    exp: nowS + 3600,
    ...overrides,
  };
}

export function makeEvent({ uri = "/", querystring = "", method = "GET", host = HOST, cookies = [], headers = {} } = {}) {
  const h = { host: [{ key: "Host", value: host }], ...headers };
  if (cookies.length > 0) h.cookie = cookies.map((value) => ({ key: "Cookie", value }));
  return { Records: [{ cf: { request: { uri, querystring, method, headers: h } } }] };
}

export function fakeFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    calls.push({ url, init });
    const route = routes[url];
    if (!route) throw new Error(`unexpected fetch ${url}`);
    const result = typeof route === "function" ? await route(init) : route;
    if (result instanceof Error) throw result;
    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status,
      json: async () => result.body,
    };
  };
  fn.calls = calls;
  return fn;
}

export function makeHandler({ jwk, routes = {}, now, random, getSecret } = {}) {
  const clock = { ms: NOW_MS };
  const fetch = fakeFetch({
    [config.jwks_endpoint]: { status: 200, body: { keys: jwk ? [jwk] : [] } },
    ...routes,
  });
  let counter = 0;
  const handler = createHandler(config, {
    fetch,
    now: now || (() => clock.ms),
    random: random || ((n) => Buffer.alloc(n, ++counter)),
    getSecret: getSecret || (async () => CLIENT_SECRET),
  });
  return { handler, fetch, clock };
}

export function setCookies(response) {
  return (response.headers["set-cookie"] || []).map((h) => h.value);
}

export function cookieValue(response, name) {
  const cookie = setCookies(response).find((c) => c.startsWith(`${name}=`));
  return cookie ? cookie.slice(name.length + 1, cookie.indexOf(";")) : undefined;
}

export function location(response) {
  return response.headers.location[0].value;
}
