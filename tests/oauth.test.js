import { test } from "node:test";
import assert from "node:assert/strict";

// Minimal browser stand-ins for public/js/cloud.js
function setup(hash, userOk = true) {
  const store = new Map();
  globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) };
  globalThis.window = { dispatchEvent() {} };
  globalThis.Event = class { constructor(t) { this.type = t; } };
  const replaced = [];
  globalThis.history = { replaceState: (_s, _t, url) => replaced.push(url) };
  globalThis.location = { hash, pathname: "/projects/", search: "", origin: "https://chucksi.com", href: "" };
  globalThis.fetch = async (url, init) => {
    if (url === "/api/config") return { ok: true, json: async () => ({ cloud: true, supabaseUrl: "https://x.supabase.co", publishableKey: "pk" }) };
    if (url.endsWith("/auth/v1/user")) {
      assert.equal(init.headers.Authorization, "Bearer AT");
      return { ok: userOk, json: async () => ({ id: "u1", email: "a@b.c" }) };
    }
    throw new Error("unexpected " + url);
  };
  return { store, replaced };
}

test("a browser-initiated PKCE callback exchanges its code once and tidies the URL", async () => {
  const { store, replaced } = setup("");
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  await cloud.signInWithProvider("github");
  const authorize = new URL(location.href);
  const flow = JSON.parse(store.get("massless.cloud-pkce"));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(flow.verifier)));
  const challenge = Buffer.from(digest).toString("base64url");
  assert.equal(authorize.searchParams.get("code_challenge"), challenge);
  assert.equal(authorize.searchParams.get("code_challenge_method"), "s256");
  location.search = "?keep=1&code=one-time-code";
  const base = globalThis.fetch;
  let exchanges = 0;
  globalThis.fetch = async (url, init) => {
    if (url.endsWith("/auth/v1/token?grant_type=pkce")) {
      exchanges++;
      assert.deepEqual(JSON.parse(init.body), { auth_code: "one-time-code", code_verifier: flow.verifier });
      return Response.json({ access_token: "AT", refresh_token: "RT", expires_in: 3600, user: { id: "u1", email: "a@b.c" } });
    }
    return base(url, init);
  };
  assert.equal(await cloud.completeRedirect(), true);
  assert.equal(cloud.session().access_token, "AT");
  assert.equal(cloud.session().user.email, "a@b.c");
  assert.ok(cloud.session().expires_at > Date.now() / 1000);
  assert.deepEqual(replaced, ["/projects/?keep=1"]);
  await assert.rejects(cloud.completeRedirect(), /Start sign-in/);
  assert.equal(exchanges, 1);
});

test("an error in the fragment is shown and nothing is stored", async () => {
  const { store } = setup("#error=access_denied&error_description=User+cancelled");
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  await assert.rejects(cloud.completeRedirect(), /User cancelled/);
  assert.equal(store.size, 0);
});

test("no fragment: nothing happens", async () => {
  setup("");
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  assert.equal(await cloud.completeRedirect(), false);
});

test("sign-in goes to Supabase authorize with the provider and a return address", async () => {
  setup("");
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  await cloud.signInWithProvider("github");
  const target = new URL(location.href);
  assert.equal(target.searchParams.get("provider"), "github");
  assert.equal(target.searchParams.get("redirect_to"), "https://chucksi.com/projects/");
  assert.match(target.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  await assert.rejects(cloud.signInWithProvider("myspace"), /Unknown/);
});

test("only providers switched on in Supabase get a button", async () => {
  setup("");
  const base = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (url.endsWith("/auth/v1/settings")) {
      assert.equal(init.headers.apikey, "pk");
      return { ok: true, json: async () => ({ external: { google: true, github: false, email: true } }) };
    }
    return base(url, init);
  };
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  assert.deepEqual(await cloud.enabledProviders(), ["google"]);
});

test("provider check fails closed when Supabase can't be reached", async () => {
  setup("");
  const base = globalThis.fetch;
  globalThis.fetch = async (url, init) => (url.endsWith("/auth/v1/settings") ? Promise.reject(new Error("offline")) : base(url, init));
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  assert.deepEqual(await cloud.enabledProviders(), []);
});

test("LinkedIn, X and Facebook are offered when switched on, and unknown providers are refused", async () => {
  setup("");
  const base = globalThis.fetch;
  globalThis.fetch = async (url, init) =>
    url.endsWith("/auth/v1/settings")
      ? { ok: true, json: async () => ({ external: { google: true, github: true, linkedin_oidc: true, twitter: true, facebook: true, linkedin: true } }) }
      : base(url, init);
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  assert.deepEqual(await cloud.enabledProviders(), ["google", "github", "linkedin_oidc", "twitter", "facebook"]);
  await cloud.signInWithProvider("facebook");
  assert.match(location.href, /authorize\?provider=facebook&redirect_to=/);
  await assert.rejects(cloud.signInWithProvider("myspace"), /Unknown sign-in provider/);
});

test("unsolicited token fragments preserve an existing session", async () => {
  const { store } = setup("#access_token=AT&refresh_token=RT");
  const original = JSON.stringify({ access_token: "victim-token", user: { id: "victim" } });
  store.set("massless.cloud-session", original);
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  await assert.rejects(cloud.completeRedirect(), /Start sign-in|sign in/i);
  assert.equal(store.get("massless.cloud-session"), original);
});

test("unsolicited, expired and wrong-path codes preserve the current session", async () => {
  for (const pending of [null, { verifier: "v".repeat(43), createdAt: Date.now() - 3600001, path: "/projects/" }, { verifier: "v".repeat(43), createdAt: Date.now(), path: "/other/" }]) {
    const { store } = setup("");
    location.search = "?code=unsolicited";
    const original = JSON.stringify({ user: { id: "victim" } });
    store.set("massless.cloud-session", original);
    if (pending) store.set("massless.cloud-pkce", JSON.stringify(pending));
    const cloud = await import("../public/js/cloud.js?" + Math.random());
    await assert.rejects(cloud.completeRedirect(), /Start sign-in/);
    assert.equal(store.get("massless.cloud-session"), original);
    assert.equal(store.has("massless.cloud-pkce"), false);
  }
});

test("a failed code/verifier exchange cannot replace the existing session", async () => {
  const { store } = setup("");
  const original = JSON.stringify({ user: { id: "victim" } });
  store.set("massless.cloud-session", original);
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  await cloud.signInWithProvider("google");
  location.search = "?code=attacker-code";
  const base = globalThis.fetch;
  globalThis.fetch = async (url, init) => url.endsWith("/auth/v1/token?grant_type=pkce")
    ? Response.json({ error_description: "Invalid code verifier" }, { status: 400 }) : base(url, init);
  await assert.rejects(cloud.completeRedirect(), /Invalid code verifier/);
  assert.equal(store.get("massless.cloud-session"), original);
  await assert.rejects(cloud.completeRedirect(), /Start sign-in/);
});

test("sign-up confirmation uses the same browser-bound code exchange", async () => {
  const { store } = setup("");
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  const base = globalThis.fetch;
  let signup;
  globalThis.fetch = async (url, init) => {
    if (url.includes("/auth/v1/signup?")) {
      signup = JSON.parse(init.body);
      return Response.json({ user: { id: "new-user" } });
    }
    if (url.endsWith("/auth/v1/token?grant_type=pkce")) {
      const flow = JSON.parse(store.get("test-flow"));
      assert.equal(JSON.parse(init.body).code_verifier, flow.verifier);
      return Response.json({ access_token: "AT", refresh_token: "RT", expires_in: 3600, user: { id: "new-user" } });
    }
    return base(url, init);
  };
  await cloud.signUp("new@example.test", "password");
  const flow = store.get("massless.cloud-pkce");
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.parse(flow).verifier))).toString("base64url");
  assert.equal(signup.code_challenge, challenge);
  assert.equal(signup.code_challenge_method, "s256");
  store.set("test-flow", flow);
  location.search = "?code=email-code";
  assert.equal(await cloud.completeRedirect(), true);
  assert.equal(cloud.session().user.id, "new-user");
});

test("external callback addresses are refused before saving a verifier", async () => {
  const { store } = setup("");
  const cloud = await import("../public/js/cloud.js?" + Math.random());
  await assert.rejects(cloud.signInWithProvider("github", "//other.example/projects/"), /on this site/);
  assert.equal(store.size, 0);
});
