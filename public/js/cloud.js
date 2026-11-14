// Optional cloud projects. Local libraries are never uploaded automatically.
let configPromise;
let refreshPromise;
const SESSION_KEY = "massless.cloud-session";
const FLOW_KEY = "massless.cloud-pkce";
const FLOW_MS = 60 * 60 * 1000;
const base64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function beginFlow(returnPath) {
  const target = new URL(returnPath, location.origin);
  if (target.origin !== location.origin) throw new Error("Choose a return address on this site.");
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  // Same-browser storage also allows email confirmation in a new tab.
  localStorage.setItem(FLOW_KEY, JSON.stringify({ verifier, createdAt: Date.now(), path: target.pathname }));
  return { challenge, redirect: target.href };
}
export const cloudConfig = () =>
  (configPromise ||= fetch("/api/config")
    .then((r) => (r.ok ? r.json() : { cloud: false, models: {} }))
    .catch(() => ({ cloud: false, models: {} })));
export function session() {
  try {
    return JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
  } catch {
    return null;
  }
}
function saveSession(s) {
  if (s) localStorage.setItem(SESSION_KEY, JSON.stringify(s));
  else localStorage.removeItem(SESSION_KEY);
  window.dispatchEvent(new Event("massless-session"));
}
async function auth(path, body) {
  const c = await cloudConfig();
  if (!c.cloud)
    throw new Error(
      "Sign-in is not available right now. Try again later.",
    );
  const r = await fetch(c.supabaseUrl + "/auth/v1/" + path, {
    method: "POST",
    headers: { apikey: c.publishableKey, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  if (!r.ok)
    throw new Error(
      j.msg || j.error_description || j.message || "Sign-in failed.",
    );
  return j;
}
export async function signIn(email, password) {
  const s = await auth("token?grant_type=password", { email, password });
  saveSession({
    ...s,
    expires_at: Math.floor(Date.now() / 1000) + s.expires_in,
  });
  return s;
}
export async function signUp(email, password) {
  // Confirmation codes can only be exchanged by the browser that started sign-up.
  const flow = await beginFlow("/projects/");
  const j = await auth(`signup?redirect_to=${encodeURIComponent(flow.redirect)}`, { email, password, code_challenge: flow.challenge, code_challenge_method: "s256" });
  if (j.access_token) {
    localStorage.removeItem(FLOW_KEY);
    saveSession({
      ...j,
      expires_at: Math.floor(Date.now() / 1000) + j.expires_in,
    });
  }
  return j;
}
/** Social sign-ins the site offers, by Supabase provider name. */
export const PROVIDERS = ["google", "github", "linkedin_oidc", "twitter", "facebook"];
/** Which social sign-ins are switched on in Supabase, so the page only shows buttons that work. */
export async function enabledProviders() {
  const c = await cloudConfig();
  if (!c.cloud) return [];
  try {
    const r = await fetch(c.supabaseUrl + "/auth/v1/settings", { headers: { apikey: c.publishableKey } });
    const j = r.ok ? await r.json() : {};
    return PROVIDERS.filter((p) => j.external?.[p] === true);
  } catch {
    return [];
  }
}
/** Start a browser-bound Supabase PKCE sign-in. */
export async function signInWithProvider(provider, returnPath = "/projects/") {
  if (!PROVIDERS.includes(provider)) throw new Error("Unknown sign-in provider.");
  const c = await cloudConfig();
  if (!c.cloud) throw new Error("Sign-in is not available right now. Try again later.");
  const flow = await beginFlow(returnPath);
  location.href =
    c.supabaseUrl + "/auth/v1/authorize?provider=" + provider +
    "&redirect_to=" + encodeURIComponent(flow.redirect) +
    "&code_challenge=" + flow.challenge + "&code_challenge_method=s256";
}
/** Exchange a one-time code using this browser's verifier, leaving existing sessions intact on failure. */
export async function completeRedirect() {
  const query = new URLSearchParams(location.search);
  const fragment = new URLSearchParams((location.hash || "").slice(1));
  const code = query.get("code");
  const error = query.get("error_description") || query.get("error") || fragment.get("error_description") || fragment.get("error");
  if (!code && !error && !fragment.has("access_token") && !fragment.has("refresh_token")) return false;
  query.delete("code");
  query.delete("error");
  query.delete("error_description");
  const search = query.toString();
  history.replaceState(null, "", location.pathname + (search ? "?" + search : ""));
  if (error) {
    localStorage.removeItem(FLOW_KEY);
    throw new Error(error.replace(/\+/g, " "));
  }
  if (fragment.has("access_token") || fragment.has("refresh_token"))
    throw new Error("Start sign-in from this browser. After confirming an older email link, sign in with your email and password.");
  let flow;
  try { flow = JSON.parse(localStorage.getItem(FLOW_KEY) || "null"); } catch { /* invalid pending flow */ }
  localStorage.removeItem(FLOW_KEY);
  if (!flow || !/^[A-Za-z0-9_-]{43}$/.test(flow.verifier) || flow.path !== location.pathname ||
      !Number.isFinite(flow.createdAt) || Date.now() - flow.createdAt > FLOW_MS || flow.createdAt > Date.now())
    throw new Error("Start sign-in from this browser, then open the confirmation here. You can also sign in with your email and password.");
  const next = await auth("token?grant_type=pkce", { auth_code: code, code_verifier: flow.verifier });
  if (!next.access_token || !next.refresh_token || !next.user?.id)
    throw new Error("Sign-in could not be confirmed. Try again.");
  saveSession({ ...next, expires_at: Math.floor(Date.now() / 1000) + next.expires_in });
  return true;
}
export async function accessToken() {
  let s = session();
  if (!s)
    throw new Error("Sign in first. It’s free.");
  if (s.expires_at < Date.now() / 1000 + 60) {
    refreshPromise ||= auth("token?grant_type=refresh_token", {
      refresh_token: s.refresh_token,
    })
      .then((next) => {
        const fresh = {
          ...next,
          expires_at: Math.floor(Date.now() / 1000) + next.expires_in,
        };
        saveSession(fresh);
        return fresh;
      })
      .catch((e) => {
        saveSession(null);
        throw e;
      })
      .finally(() => {
        refreshPromise = null;
      });
    s = await refreshPromise;
  }
  return s.access_token;
}
export async function signOut() {
  const c = await cloudConfig();
  let s = session();
  saveSession(null);
  if (s)
    await fetch(c.supabaseUrl + "/auth/v1/logout?scope=local", {
      method: "POST",
      headers: {
        apikey: c.publishableKey,
        Authorization: "Bearer " + s.access_token,
      },
    }).catch(() => {});
}
export async function cloudRequest(path, options = {}) {
  const c = await cloudConfig();
  const token = await accessToken();
  const r = await fetch(c.supabaseUrl + path, {
    ...options,
    headers: {
      apikey: c.publishableKey,
      Authorization: "Bearer " + token,
      ...options.headers,
    },
  });
  if (!r.ok) {
    let j = await r.json().catch(() => ({}));
    throw new Error(j.message || j.error || "Something went wrong. Try again.");
  }
  return r.status === 204 ? null : r.json();
}
export const projects = () =>
  cloudRequest("/rest/v1/massless_projects?select=*&order=created_at.desc");
export const createProject = (name) =>
  cloudRequest("/rest/v1/massless_projects", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify({ name }),
  });
export const assets = (id) =>
  cloudRequest(
    "/rest/v1/massless_assets?select=*&project_id=eq." +
      encodeURIComponent(id) +
      "&order=created_at.desc",
  );
export async function uploadAsset(projectId, file, metadata = {}) {
  if (file.size > 30 * 1024 * 1024)
    throw new Error("Choose a file smaller than 30 MB.");
  const uid = session()?.user?.id;
  if (!uid) throw new Error("Sign in first.");
  const kind = file.type.startsWith("image/")
    ? "image"
    : file.type.startsWith("audio/")
      ? "audio"
      : file.type.startsWith("video/")
        ? "video"
        : file.type === "application/pdf"
          ? "document"
          : "workflow";
  const ext = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "audio/mpeg": "mp3",
    "audio/wav": "wav",
    "audio/x-wav": "wav",
    "audio/mp4": "m4a",
    "video/mp4": "mp4",
    "application/pdf": "pdf",
    "application/json": "json",
  }[file.type];
  if (!ext)
    throw new Error(
      "Choose JPG, PNG, WebP, MP3, WAV, M4A, MP4, PDF or workflow JSON.",
    );
  const object_path = uid + "/" + crypto.randomUUID() + "." + ext;
  await cloudRequest("/storage/v1/object/massless-private/" + object_path, {
    method: "POST",
    headers: { "content-type": file.type },
    body: file,
  });
  try {
    return await cloudRequest("/rest/v1/massless_assets", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify({
        project_id: projectId,
        name: file.name.slice(0, 200),
        object_path,
        kind,
        metadata,
      }),
    });
  } catch (e) {
    await cloudRequest("/storage/v1/object/massless-private", {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ prefixes: [object_path] }),
    }).catch(() => {});
    throw e;
  }
}
export async function assetURL(path) {
  const c = await cloudConfig();
  const j = await cloudRequest(
    "/storage/v1/object/sign/massless-private/" + path,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresIn: 300 }),
    },
  );
  return c.supabaseUrl + "/storage/v1" + (j.signedURL || j.signedUrl);
}
export async function hostedImage({
  model,
  prompt,
  w,
  h,
  seed,
  signal,
  onWait,
}) {
  const token = await accessToken();
  const idempotencyKey = crypto.randomUUID();
  let r = await fetch("/api/generations", {
    method: "POST",
    signal,
    headers: {
      Authorization: "Bearer " + token,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model,
      prompt,
      width: w,
      height: h,
      seed,
      idempotencyKey,
    }),
  });
  let j = await r.json();
  if (!r.ok) throw new Error(j.error || "Couldn't create the image. Try again.");
  const id = j.id,
    deadline = Date.now() + 22 * 60 * 1000;
  const cancel = () =>
    fetch("/api/generations/" + id + "/cancel", {
      method: "POST",
      headers: { Authorization: "Bearer " + token },
    }).catch(() => {});
  signal?.addEventListener("abort", cancel, { once: true });
  try {
    while (
      ![
        "COMPLETED",
        "FAILED",
        "CANCELLED",
        "TIMED_OUT",
        "SUBMISSION_UNKNOWN",
      ].includes(j.status)
    ) {
      if (signal?.aborted) throw new Error("Cancelled");
      if (Date.now() > deadline) {
        await cancel();
        throw new Error("This image took too long. Try another style.");
      }
      onWait?.(0, j.status);
      await new Promise((resolve) => setTimeout(resolve, 2500));
      r = await fetch("/api/generations/" + id, {
        signal,
        headers: { Authorization: "Bearer " + (await accessToken()) },
      });
      j = await r.json();
      if (!r.ok) throw new Error(j.error || "Lost track of this image. Try again.");
    }
    if (j.status !== "COMPLETED")
      throw new Error(j.status === "CANCELLED" ? "Cancelled." : "Couldn't create the image. Try again.");
    const imageResponse = await fetch("/api/generations/" + id + "/image", {
      signal,
      headers: { Authorization: "Bearer " + (await accessToken()) },
    });
    if (!imageResponse.ok)
      throw new Error("Couldn't download the image. Try again.");
    const blob = await imageResponse.blob();
    const image = await createImageBitmap(blob);
    return { image, engine: "hosted", model, jobId: id };
  } finally {
    signal?.removeEventListener("abort", cancel);
  }
}
export const workflowRuns = (id) =>
  cloudRequest(
    "/rest/v1/massless_workflow_runs?select=*&project_id=eq." +
      encodeURIComponent(id) +
      "&order=updated_at.desc",
  );
export const workflowRun = (id) =>
  cloudRequest(
    "/rest/v1/massless_workflow_runs?select=*&id=eq." +
      encodeURIComponent(id) +
      "&limit=1",
  );

// ---- GPU worker jobs (Animate, Music, Upscale; Lab jobs when the site enables them) ----
// Signed-in users only; the Worker's ledger enforces one daily budget and a per-user daily limit.
export async function gpuBudget() {
  const c = await cloudConfig();
  if (!c.gpu?.on) return { on: false };
  if (!session()) return { on: true, signedIn: false };
  const r = await fetch("/api/generations/budget", {
    headers: { Authorization: "Bearer " + (await accessToken()) },
  });
  const j = await r.json().catch(() => ({}));
  return r.ok ? { ...j, signedIn: true } : { on: true, signedIn: r.status !== 401, error: j.error };
}
/** Run one GPU job; resolves { blob, audio?, output, costCents }. onProgress({ status, message, percent }). */
export async function gpuJob({ job, input, lab = false, signal, onProgress }) {
  const token = await accessToken();
  let r = await fetch("/api/generations", {
    method: "POST",
    signal,
    headers: { Authorization: "Bearer " + token, "content-type": "application/json" },
    body: JSON.stringify({ job, input, ...(lab ? { lab: true } : {}), idempotencyKey: crypto.randomUUID() }),
  });
  let j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.error || "Couldn't start. Try again."), { status: r.status, budget: !!j.budget });
  const id = j.id,
    deadline = Date.now() + (j.timeoutSec || 1500) * 1000,
    auth = async () => ({ Authorization: "Bearer " + (await accessToken()) });
  const cancel = async () => fetch("/api/generations/" + id + "/cancel", { method: "POST", headers: await auth() }).catch(() => {});
  signal?.addEventListener("abort", cancel, { once: true });
  let delay = 2000;
  try {
    while (!["COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT", "SUBMISSION_UNKNOWN"].includes(j.status)) {
      onProgress?.({ status: j.status, message: j.status === "IN_PROGRESS" && j.percent >= 80 ? "Almost done…" : "Creating…", percent: j.percent ?? null });
      if (Date.now() > deadline) {
        await cancel();
        throw new Error("This took too long and was stopped. Try again.");
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
      if (signal?.aborted) throw new DOMException("Cancelled", "AbortError");
      delay = j.status === "IN_PROGRESS" ? 2500 : Math.min(8000, delay * 1.4);
      r = await fetch("/api/generations/" + id, { signal, headers: await auth() });
      j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || "Lost track of this one. Try again.");
    }
    if (j.status !== "COMPLETED") throw new Error(j.status === "CANCELLED" ? "Cancelled." : "Couldn't finish this one. Try again.");
    onProgress?.({ status: "COMPLETED", message: "Ready", percent: 100 });
    const get = async (part) => {
      const f = await fetch("/api/generations/" + id + "/" + part, { signal, headers: await auth() });
      if (!f.ok) throw new Error("The result could not be downloaded.");
      return f.blob();
    };
    return { blob: await get("file"), audio: j.output?.audio ? await get("audio") : undefined, output: j.output, costCents: j.costCents, id };
  } finally {
    signal?.removeEventListener("abort", cancel);
    window.dispatchEvent(new Event("massless-gpu"));
  }
}
/** The members' free video model (OpenRouter): whether it's on and how many clips this account has left today. */
export async function promoBudget() {
  const c = await cloudConfig();
  if (!c.promoVideo?.on) return { on: false };
  if (!session()) return { on: true, signedIn: false, model: c.promoVideo.model, perUserDaily: c.promoVideo.perUserDaily };
  const r = await fetch("/api/promo-video/budget", { headers: { Authorization: "Bearer " + (await accessToken()) } });
  const j = await r.json().catch(() => ({}));
  return r.ok ? { ...j, signedIn: true } : { on: true, signedIn: r.status !== 401, error: j.error };
}
/** Make one free clip; resolves { blob, costCents, id }. onProgress(message). */
export async function promoVideoJob({ prompt, duration, resolution, image, signal, onProgress }) {
  const auth = async () => ({ Authorization: "Bearer " + (await accessToken()) });
  let r = await fetch("/api/promo-video", {
    method: "POST",
    signal,
    headers: { ...(await auth()), "content-type": "application/json" },
    body: JSON.stringify({ prompt, duration, resolution, ...(image ? { image } : {}), idempotencyKey: crypto.randomUUID() }),
  });
  let j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.error || "Couldn't create the video. Try again."), { status: r.status, budget: !!j.budget });
  const id = j.id, started = Date.now();
  let delay = 3000;
  while (!["completed", "failed", "cancelled", "expired", "unknown"].includes(j.status)) {
    const s = Math.round((Date.now() - started) / 1000);
    onProgress?.(s > 60 ? "Almost done…" : "Creating…");
    if (Date.now() - started > 10 * 60 * 1000) throw new Error("The clip took too long. Try again later.");
    await new Promise((resolve) => setTimeout(resolve, delay));
    if (signal?.aborted) throw new DOMException("Cancelled", "AbortError");
    delay = Math.min(8000, delay * 1.25);
    r = await fetch("/api/promo-video/" + id, { signal, headers: await auth() });
    j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || "Lost track of this video. Try again.");
  }
  if (j.status !== "completed") throw new Error(j.status === "cancelled" ? "Cancelled." : "Couldn't create the video. Try again.");
  onProgress?.("Almost done…");
  const f = await fetch("/api/promo-video/" + id + "/file", { signal, headers: await auth() });
  if (!f.ok) throw new Error("Couldn't download the video. Try again.");
  return { blob: await f.blob(), costCents: j.costCents, id };
}
