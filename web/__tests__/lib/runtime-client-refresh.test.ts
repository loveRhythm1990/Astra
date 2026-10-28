// @vitest-environment node
vi.mock("next/headers", () => ({ cookies: vi.fn() }));

import { cookies } from "next/headers";
import { WebRuntimeClient } from "@/lib/runtime-client/server";
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, type RuntimeConfig } from "@/lib/runtime-config";

beforeEach(() => vi.mocked(cookies).mockReset());
afterEach(() => vi.unstubAllGlobals());

function runtimeConfig(accessToken: string, refreshToken: string): RuntimeConfig {
  return {
    mode: "live", source: "cookie", apiUrl: "https://example.test",
    accessToken, refreshToken, demoMode: false,
    hasAccessToken: true, hasRefreshToken: true, message: "",
  };
}

it("persists refreshed httpOnly cookies before the initiating SDK request completes", async () => {
  let release!: () => void;
  const available = new Promise<void>(resolve => { release = resolve; });
  const set = vi.fn();
  vi.mocked(cookies).mockImplementation(async () => {
    await available;
    // This consumer only uses the cookie store's setter.
    return { set } as unknown as Awaited<ReturnType<typeof cookies>>;
  });
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith("/auth/refresh")) {
      return Response.json({ access_token: "new-access", refresh_token: "new-refresh" });
    }
    return new Headers(init?.headers).get("Authorization") === "Bearer new-access"
      ? Response.json({ user_id: "alice" }) : Response.json({}, { status: 401 });
  });
  vi.stubGlobal("fetch", fetchMock);
  const runtime = new WebRuntimeClient(runtimeConfig("old-access", "old-refresh"));
  const settled = vi.fn();
  const pending = runtime.sdk.getMe();
  void pending.then(settled, settled);
  await vi.waitFor(() => expect(cookies).toHaveBeenCalledTimes(1));
  expect(settled).not.toHaveBeenCalled();
  expect(set).not.toHaveBeenCalled();
  await expect(runtime.get("/auth/me", { auth: "required" })).resolves.toEqual({ user_id: "alice" });
  expect(settled).not.toHaveBeenCalled();
  release();
  await expect(pending).resolves.toEqual({ user_id: "alice" });
  const options = { httpOnly: true, sameSite: "lax", path: "/" };
  expect(set.mock.calls).toEqual([
    [REFRESH_TOKEN_COOKIE, "new-refresh", options],
    [ACCESS_TOKEN_COOKIE, "new-access", options],
  ]);
  expect(fetchMock.mock.calls.map(([, init]) => new Headers(init?.headers).get("Authorization"))).toEqual([
    "Bearer old-access", null, "Bearer new-access", "Bearer new-access",
  ]);
});

it("does not replay a delayed old-token request while cookie persistence fails", async () => {
  let release401!: (response: Response) => void;
  let releaseCookies!: () => void;
  const late401 = new Promise<Response>(resolve => { release401 = resolve; });
  const cookiesReady = new Promise<void>(resolve => { releaseCookies = resolve; });
  vi.mocked(cookies).mockImplementation(async () => {
    await cookiesReady;
    return { set: () => { throw new Error("cookie write unavailable"); } } as unknown as Awaited<ReturnType<typeof cookies>>;
  });
  const expired = () => new Response("expired", { status: 401 });
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/auth/refresh')) return Response.json({ access_token: 'new', refresh_token: 'rotated' });
    const auth = new Headers(init?.headers).get('Authorization');
    if (url.endsWith('/late') && auth === 'Bearer old') return late401;
    return auth === 'Bearer old' ? expired() : new Response('ok');
  });
  vi.stubGlobal('fetch', fetchMock);
  const runtime = new WebRuntimeClient(runtimeConfig('old', 'old-refresh'));
  const late = runtime.fetchResponse('/late', { auth: 'required' });
  const first = runtime.fetchResponse('/first', { auth: 'required' });
  await vi.waitFor(() => expect(cookies).toHaveBeenCalledTimes(1));
  release401(expired());
  expect((await late).status).toBe(401);
  releaseCookies();
  expect((await first).status).toBe(401);
  expect(fetchMock.mock.calls.filter(([url]) => url.endsWith('/late'))).toHaveLength(1);
  expect(fetchMock.mock.calls.filter(([url]) => url.endsWith('/first'))).toHaveLength(1);
});

it("can recover when writing the access cookie fails after the rotated refresh cookie", async () => {
  const jar = new Map([[ACCESS_TOKEN_COOKIE, 'old'], [REFRESH_TOKEN_COOKIE, 'old-refresh']]);
  let failAccess = true;
  vi.mocked(cookies).mockResolvedValue({
    set(name: string, value: string) {
      if (name === ACCESS_TOKEN_COOKIE && failAccess) {
        failAccess = false;
        throw new Error('access cookie write failed');
      }
      jar.set(name, value);
    },
  } as unknown as Awaited<ReturnType<typeof cookies>>);
  let validRefresh = 'old-refresh';
  let rotations = 0;
  const seenRefresh: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/auth/refresh')) {
      const refresh = JSON.parse(String(init?.body)).refresh_token;
      seenRefresh.push(refresh);
      if (refresh !== validRefresh) return new Response('expired', { status: 401 });
      rotations++;
      validRefresh = `refresh-${rotations}`;
      return Response.json({ access_token: `access-${rotations}`, refresh_token: validRefresh });
    }
    return new Headers(init?.headers).get('Authorization') === `Bearer access-${rotations}`
      ? Response.json({ user_id: 'alice' }) : new Response('expired', { status: 401 });
  }));
  const first = new WebRuntimeClient(runtimeConfig('old', 'old-refresh'));
  expect((await first.fetchResponse('/resource', { auth: 'required' })).status).toBe(401);
  expect(jar.get(ACCESS_TOKEN_COOKIE)).toBe('old');
  expect(jar.get(REFRESH_TOKEN_COOKIE)).toBe('refresh-1');
  const retry = new WebRuntimeClient(runtimeConfig(jar.get(ACCESS_TOKEN_COOKIE)!, jar.get(REFRESH_TOKEN_COOKIE)!));
  await expect(retry.get('/resource', { auth: 'required' })).resolves.toEqual({ user_id: 'alice' });
  expect(seenRefresh).toEqual(['old-refresh', 'refresh-1']);
});

it.each([
  { name: "SDK notification", sdkRefresh: true },
  { name: "Web transport", sdkRefresh: false },
])("does not rotate during an outstanding $name notification and recovers afterward", async ({ sdkRefresh }) => {
  let release!: () => void;
  const available = new Promise<void>(resolve => { release = resolve; });
  const jar = new Map<string, string>();
  const set = vi.fn((name: string, value: string) => { jar.set(name, value); });
  vi.mocked(cookies).mockImplementation(async () => {
    if (vi.mocked(cookies).mock.calls.length === 1) await available;
    return { set } as unknown as Awaited<ReturnType<typeof cookies>>;
  });

  const issued = new Set(["access-0"]);
  const expired = new Set(["access-0"]);
  const refreshRequests: string[] = [];
  let rotation = 0;
  let validRefresh = "refresh-0";
  const unauthorized = () => Response.json({ detail: "Unauthorized" }, { status: 401 });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith("/auth/refresh")) {
      const token = JSON.parse(String(init?.body)).refresh_token;
      refreshRequests.push(token);
      if (token !== validRefresh) return unauthorized();
      rotation++;
      validRefresh = `refresh-${rotation}`;
      const access = `access-${rotation}`;
      issued.add(access);
      return Response.json({ access_token: access, refresh_token: validRefresh });
    }
    const token = new Headers(init?.headers).get("Authorization")?.replace("Bearer ", "");
    return token && issued.has(token) && !expired.has(token)
      ? Response.json({ user_id: "alice" }) : unauthorized();
  }));

  const runtime = new WebRuntimeClient(runtimeConfig("access-0", "refresh-0"));
  const first = Promise.allSettled([runtime.sdk.getMe()]);
  await vi.waitFor(() => expect(cookies).toHaveBeenCalledTimes(1));
  expired.add("access-1");
  if (sdkRefresh) {
    await expect(runtime.sdk.getMe()).rejects.toMatchObject({ status: 401 });
  } else {
    await expect(runtime.get("/auth/me", { auth: "required" })).rejects.toMatchObject({ status: 401 });
  }
  release();
  expect(await first).toMatchObject([{ status: "rejected", reason: { status: 401 } }]);

  expect(set.mock.calls.map(([name, value]) => [name, value])).toEqual([
    [REFRESH_TOKEN_COOKIE, "refresh-1"],
    [ACCESS_TOKEN_COOKIE, "access-1"],
  ]);
  const next = new WebRuntimeClient(runtimeConfig(jar.get(ACCESS_TOKEN_COOKIE)!, jar.get(REFRESH_TOKEN_COOKIE)!));
  await expect(next.sdk.getMe()).resolves.toEqual({ user_id: "alice" });
  expect(jar.get(REFRESH_TOKEN_COOKIE)).toBe(validRefresh);
  expect(refreshRequests).toEqual(["refresh-0", "refresh-1"]);
});

it("shares one in-flight refresh between SDK and Web requests", async () => {
  let release!: () => void;
  const refresh = new Promise<void>(resolve => { release = resolve; });
  const set = vi.fn();
  vi.mocked(cookies).mockResolvedValue({ set } as unknown as Awaited<ReturnType<typeof cookies>>);
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith("/auth/refresh")) {
      await refresh;
      return Response.json({ access_token: "new", refresh_token: "rotated" });
    }
    return new Headers(init?.headers).get("Authorization") === "Bearer new"
      ? Response.json({ user_id: "alice" }) : new Response("expired", { status: 401 });
  });
  vi.stubGlobal("fetch", fetchMock);
  const runtime = new WebRuntimeClient(runtimeConfig("old", "refresh"));
  const pending = Promise.all([runtime.sdk.getMe(), runtime.get("/auth/me", { auth: "required" })]);
  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
  release();
  expect(await pending).toEqual([{ user_id: "alice" }, { user_id: "alice" }]);
  expect(fetchMock.mock.calls.filter(([url]) => url.endsWith("/auth/refresh"))).toHaveLength(1);
  expect(cookies).toHaveBeenCalledTimes(1);
  expect(set).toHaveBeenCalledTimes(2);
});

it("keeps Web raw responses, body, cancellation and origin routing intact", async () => {
  const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response("data: event\n\n", { status: 403 }));
  vi.stubGlobal("fetch", fetchMock);
  const runtime = new WebRuntimeClient({ ...runtimeConfig("access", "refresh"), apiUrl: "https://example.test/ignored?query=ignored" });
  const body = new FormData();
  body.set("upload", "contents");
  const signal = new AbortController().signal;
  const response = await runtime.fetchResponse("/stream", { method: "POST", body, signal, headers: { Accept: "text/event-stream" } });
  expect(response.bodyUsed).toBe(false);
  expect(await response.text()).toBe("data: event\n\n");
  const [url, init] = fetchMock.mock.calls[0];
  expect(url).toBe("https://example.test/stream");
  expect(init).toMatchObject({ method: "POST", body, signal, cache: "no-store" });
  expect(new Headers(init?.headers).get("Accept")).toBe("text/event-stream");
  expect(new Headers(init?.headers).has("Content-Type")).toBe(false);
  await expect(runtime.get("/error", { operation: "read item" })).rejects.toMatchObject({ status: 403, operation: "read item" });
  await expect(runtime.sdk.getMe()).rejects.toMatchObject({ status: 403 });
  expect(fetchMock.mock.calls[2][0]).toBe("https://example.test/auth/me");
});

it("uses current SDK credentials for Web auth and keeps old requests fenced on identity replacement", async () => {
  let release!: () => void;
  const refresh = new Promise<void>(resolve => { release = resolve; });
  const set = vi.fn();
  vi.mocked(cookies).mockResolvedValue({ set } as unknown as Awaited<ReturnType<typeof cookies>>);
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith("/auth/refresh")) {
      await refresh;
      return Response.json({ access_token: "stale", refresh_token: "stale-refresh" });
    }
    if (url.endsWith("/auth/logout")) return new Response(null, { status: 204 });
    return new Headers(init?.headers).get("Authorization") === "Bearer bob"
      ? Response.json({ user_id: "bob" }) : new Response("expired", { status: 401 });
  });
  vi.stubGlobal("fetch", fetchMock);
  const runtime = new WebRuntimeClient(runtimeConfig("alice", "refresh"));
  const old = Promise.allSettled([runtime.get("/auth/me", { auth: "required" })]);
  await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  runtime.sdk.setTokens("bob", "bob-refresh");
  release();
  expect(await old).toMatchObject([{ status: "rejected", reason: { status: 401 } }]);
  await expect(runtime.get("/auth/me", { auth: "required" })).resolves.toEqual({ user_id: "bob" });
  expect(set).not.toHaveBeenCalled();
  await runtime.sdk.logout();
  const count = fetchMock.mock.calls.length;
  await expect(runtime.get("/auth/me", { auth: "required" })).rejects.toMatchObject({ status: 401 });
  expect(fetchMock).toHaveBeenCalledTimes(count);
});

it("does not authenticate or refresh anonymous Web calls and preserves explicit overrides", async () => {
  const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response("unauthorized", { status: 401 }));
  vi.stubGlobal("fetch", fetchMock);
  const runtime = new WebRuntimeClient(runtimeConfig("access", "refresh"));
  await runtime.fetchResponse("/auth/login", { auth: "none", method: "POST", json: { username: "alice" } });
  await runtime.fetchResponse("/auth/login", { auth: "none", headers: { Authorization: "Bearer explicit", "X-User-Id": "hint" } });
  expect(fetchMock).toHaveBeenCalledTimes(2);
  const headers = new Headers(fetchMock.mock.calls[0][1]?.headers);
  expect(headers.has("Authorization")).toBe(false);
  expect(headers.has("X-User-Id")).toBe(false);
  expect(headers.get("Content-Type")).toBe("application/json");
  expect(fetchMock.mock.calls[0][1]?.body).toBe('{"username":"alice"}');
  expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get("Authorization")).toBe("Bearer explicit");
  expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get("X-User-Id")).toBe("hint");
});

it("only retries a raw mutation when its caller opts in", async () => {
  vi.mocked(cookies).mockResolvedValue({ set: vi.fn() } as unknown as Awaited<ReturnType<typeof cookies>>);
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/auth/refresh')) return Response.json({ access_token: 'new', refresh_token: 'rotated' });
    return new Headers(init?.headers).get('Authorization') === 'Bearer new'
      ? new Response('ok') : new Response('expired', { status: 401 });
  });
  vi.stubGlobal('fetch', fetchMock);
  const runtime = new WebRuntimeClient(runtimeConfig('old', 'refresh'));
  expect((await runtime.fetchResponse('/write', { method: 'POST', json: { value: 1 } })).status).toBe(401);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  await expect(runtime.post('/write', { value: 1 }, { retryUnauthorized: false })).rejects.toMatchObject({ status: 401 });
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect((await runtime.fetchResponse('/write', { method: 'POST', json: { value: 1 }, retryUnauthorized: true })).status).toBe(200);
  expect(fetchMock).toHaveBeenCalledTimes(5);
});
