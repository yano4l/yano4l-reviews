import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { getStore } from "@netlify/blobs";
import { and, eq, gte, ne, sql } from "drizzle-orm";
import { db } from "../../db/index.ts";
import { submissions, loginAttempts } from "../../db/schema.ts";

const TIERS = {
  free: { name: "Free Review", cents: 0, rank: 3 },
  standard: { name: "Standard Review", cents: 500, rank: 2 },
  skip: { name: "Skip the Line", cents: 1500, rank: 1 },
  super: { name: "Super Skip", cents: 2500, rank: 0 },
} as const;
type TierKey = keyof typeof TIERS;

const QUEUE_STATUSES = ["in_queue", "up_next", "reviewing", "done"] as const;
const STATUS_RANK: Record<string, number> = { reviewing: 0, up_next: 1, in_queue: 2, done: 3 };

const SESSION_COOKIE = "host_session";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_FAILS_PER_IP = 5;
const MAX_FAILS_GLOBAL = 30;
const FAIL_WINDOW_MS = 15 * 60 * 1000;

// Audio uploads are sent in fixed-size chunks so each request stays well under the request body limit.
const AUDIO_CHUNK_BYTES = 960 * 1024;
const AUDIO_MAX_BYTES = 100 * 1024 * 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

type UploadMeta = { filename: string; contentType: string; size: number; chunks: number; locked?: boolean };

const audioStore = () => getStore({ name: "song-uploads", consistency: "strong" });
const settingsStore = () => getStore({ name: "site-settings", consistency: "strong" });

async function isFreeEnabled(): Promise<boolean> {
  const val = (await settingsStore().get("freeSubmissionsEnabled", { type: "json" }).catch(() => null)) as { enabled?: boolean } | null;
  return val?.enabled !== false; // default true
}
const metaKey = (id: string) => `${id}/meta`;
const chunkKey = (id: string, n: number) => `${id}/chunk/${n}`;

function expectedChunkSize(meta: UploadMeta, n: number): number {
  return n === meta.chunks - 1 ? meta.size - AUDIO_CHUNK_BYTES * (meta.chunks - 1) : AUDIO_CHUNK_BYTES;
}

const app = new Hono();

// ---------- helpers ----------

function clean(v: unknown, max: number): string {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}

function isHttpUrl(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

function sessionKey(): Buffer {
  return createHmac("sha256", "yano4l-host-session").update(process.env.HOST_PIN ?? "").digest();
}

function signSession(exp: number): string {
  const sig = createHmac("sha256", sessionKey()).update(String(exp)).digest("hex");
  return `${exp}.${sig}`;
}

function verifySession(token: string | undefined): boolean {
  if (!token || !process.env.HOST_PIN) return false;
  const [expStr, sig] = token.split(".");
  const exp = Number(expStr);
  if (!exp || !sig || exp < Date.now()) return false;
  const expected = createHmac("sha256", sessionKey()).update(String(exp)).digest("hex");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function pinMatches(input: string): boolean {
  const pin = process.env.HOST_PIN ?? "";
  if (!pin) return false;
  const a = createHmac("sha256", "cmp").update(input).digest();
  const b = createHmac("sha256", "cmp").update(pin).digest();
  return timingSafeEqual(a, b);
}

async function stripe(path: string, init?: { method?: string; form?: Record<string, string> }) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("Payments are not configured yet.");
  const res = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: init?.method ?? "GET",
    headers: {
      Authorization: `Bearer ${key}`,
      ...(init?.form ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
    },
    body: init?.form ? new URLSearchParams(init.form).toString() : undefined,
  });
  const data = await res.json();
  if (!res.ok) {
    console.error("Stripe error", data?.error?.message);
    throw new Error("The payment provider rejected the request.");
  }
  return data;
}

function clientIp(req: Request): string {
  return (
    req.headers.get("x-nf-client-connection-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

// ---------- public ----------

app.get("/api/queue", async (c) => {
  const rows = await db
    .select({
      id: submissions.id,
      artistName: submissions.artistName,
      trackTitle: submissions.trackTitle,
      genre: submissions.genre,
      tier: submissions.tier,
      status: submissions.status,
      paidAt: submissions.paidAt,
    })
    .from(submissions)
    .where(sql`${submissions.status} in ('in_queue', 'up_next', 'reviewing')`);

  rows.sort(
    (a, b) =>
      STATUS_RANK[a.status] - STATUS_RANK[b.status] ||
      TIERS[a.tier as TierKey].rank - TIERS[b.tier as TierKey].rank ||
      (a.paidAt?.getTime() ?? 0) - (b.paidAt?.getTime() ?? 0),
  );

  c.header("Cache-Control", "no-store");
  return c.json(rows.map(({ paidAt, ...r }) => r));
});

app.post("/api/uploads", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const filename = clean(body.filename, 200).replace(/[\r\n"\\]/g, "") || "track";
  const contentType = clean(body.contentType, 100).toLowerCase();
  const size = Number(body.size);

  if (!/^audio\/[a-z0-9.+-]+$/.test(contentType)) return c.json({ error: "Please choose an audio file." }, 400);
  if (!Number.isInteger(size) || size <= 0) return c.json({ error: "That audio file looks empty." }, 400);
  if (size > AUDIO_MAX_BYTES) {
    return c.json({ error: `Audio files must be ${AUDIO_MAX_BYTES / 1024 / 1024} MB or smaller.` }, 400);
  }

  const id = randomUUID();
  const meta: UploadMeta = { filename, contentType, size, chunks: Math.ceil(size / AUDIO_CHUNK_BYTES) };
  await audioStore().setJSON(metaKey(id), meta);
  return c.json({ id, chunkSize: AUDIO_CHUNK_BYTES, chunks: meta.chunks });
});

app.put("/api/uploads/:id/chunks/:n", async (c) => {
  const id = c.req.param("id");
  const n = Number(c.req.param("n"));
  if (!UUID_RE.test(id) || !Number.isInteger(n) || n < 0) return c.json({ error: "Invalid upload." }, 400);

  const declared = Number(c.req.header("content-length") ?? "0");
  if (declared > AUDIO_CHUNK_BYTES) return c.json({ error: "Chunk too large." }, 413);

  const store = audioStore();
  const meta = (await store.get(metaKey(id), { type: "json" })) as UploadMeta | null;
  if (!meta || meta.locked) return c.json({ error: "Upload not found." }, 404);
  if (n >= meta.chunks) return c.json({ error: "Invalid chunk." }, 400);

  const data = await c.req.arrayBuffer();
  if (data.byteLength !== expectedChunkSize(meta, n)) return c.json({ error: "Chunk size mismatch." }, 400);

  await store.set(chunkKey(id, n), data);
  return c.json({ ok: true });
});

app.get("/api/settings", async (c) => {
  const freeEnabled = await isFreeEnabled();
  c.header("Cache-Control", "no-store");
  return c.json({ freeEnabled });
});

app.post("/api/submit-free", async (c) => {
  if (!(await isFreeEnabled())) {
    return c.json({ error: "Free submissions are currently closed." }, 403);
  }
  const body = await c.req.json().catch(() => ({}));
  const artistName = clean(body.artistName, 80);
  const trackTitle = clean(body.trackTitle, 120);
  const trackLink = clean(body.trackLink, 500);
  const genre = clean(body.genre, 60);
  const email = clean(body.email, 200);
  const audioUploadId = clean(body.audioUploadId, 64);

  if (!artistName || !trackTitle) return c.json({ error: "Artist name and track title are required." }, 400);
  if (!trackLink && !audioUploadId) return c.json({ error: "Upload an audio file or paste a track link." }, 400);
  if (trackLink && !isHttpUrl(trackLink)) return c.json({ error: "Enter a valid track link starting with https://" }, 400);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ error: "Enter a valid email." }, 400);

  let audio: { audioUploadId: string; audioFilename: string; audioContentType: string; audioSize: number } | null = null;
  if (audioUploadId) {
    if (!UUID_RE.test(audioUploadId)) return c.json({ error: "Invalid audio upload." }, 400);
    const store = audioStore();
    const meta = (await store.get(metaKey(audioUploadId), { type: "json" })) as UploadMeta | null;
    if (!meta || meta.locked) return c.json({ error: "Audio upload not found. Please re-attach your file." }, 400);
    const { blobs } = await store.list({ prefix: `${audioUploadId}/chunk/` });
    if (blobs.length !== meta.chunks) return c.json({ error: "Your audio file didn't finish uploading. Please try again." }, 400);
    audio = {
      audioUploadId,
      audioFilename: meta.filename,
      audioContentType: meta.contentType,
      audioSize: meta.size,
    };
  }

  const [row] = await db
    .insert(submissions)
    .values({
      artistName,
      trackTitle,
      trackLink,
      genre,
      email,
      tier: "free",
      amountCents: 0,
      status: "in_queue",
      paidAt: new Date(),
      ...audio,
    })
    .returning({ id: submissions.id });

  if (audio) {
    const store = audioStore();
    const meta = (await store.get(metaKey(audio.audioUploadId), { type: "json" })) as UploadMeta;
    await store.setJSON(metaKey(audio.audioUploadId), { ...meta, locked: true });
  }

  return c.json({ ok: true, id: row.id });
});

app.post("/api/checkout", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const tier = clean(body.tier, 20) as TierKey;
  const artistName = clean(body.artistName, 80);
  const trackTitle = clean(body.trackTitle, 120);
  const trackLink = clean(body.trackLink, 500);
  const genre = clean(body.genre, 60);
  const email = clean(body.email, 200);
  const audioUploadId = clean(body.audioUploadId, 64);

  if (!TIERS[tier]) return c.json({ error: "Choose a submission tier." }, 400);
  if (!artistName || !trackTitle) return c.json({ error: "Artist name and track title are required." }, 400);
  if (!trackLink && !audioUploadId) return c.json({ error: "Upload an audio file or paste a track link." }, 400);
  if (trackLink && !isHttpUrl(trackLink)) return c.json({ error: "Enter a valid track link starting with https://" }, 400);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ error: "Enter a valid email." }, 400);
  if (!process.env.STRIPE_SECRET_KEY) return c.json({ error: "Payments are not configured yet." }, 503);

  let audio: { audioUploadId: string; audioFilename: string; audioContentType: string; audioSize: number } | null = null;
  if (audioUploadId) {
    if (!UUID_RE.test(audioUploadId)) return c.json({ error: "Invalid audio upload." }, 400);
    const store = audioStore();
    const meta = (await store.get(metaKey(audioUploadId), { type: "json" })) as UploadMeta | null;
    if (!meta || meta.locked) return c.json({ error: "Audio upload not found. Please re-attach your file." }, 400);
    const { blobs } = await store.list({ prefix: `${audioUploadId}/chunk/` });
    if (blobs.length !== meta.chunks) return c.json({ error: "Your audio file didn't finish uploading. Please try again." }, 400);
    audio = {
      audioUploadId,
      audioFilename: meta.filename,
      audioContentType: meta.contentType,
      audioSize: meta.size,
    };
  }

  const t = TIERS[tier];
  const [row] = await db
    .insert(submissions)
    .values({ artistName, trackTitle, trackLink, genre, email, tier, amountCents: t.cents, ...audio })
    .returning({ id: submissions.id });
  if (audio) {
    // Lock the upload so its chunks can no longer be overwritten once attached to a submission.
    const store = audioStore();
    const meta = (await store.get(metaKey(audio.audioUploadId), { type: "json" })) as UploadMeta;
    await store.setJSON(metaKey(audio.audioUploadId), { ...meta, locked: true });
  }

  const origin = new URL(c.req.url).origin;
  try {
    const form: Record<string, string> = {
      mode: "payment",
      "line_items[0][quantity]": "1",
      "line_items[0][price_data][currency]": "usd",
      "line_items[0][price_data][unit_amount]": String(t.cents),
      "line_items[0][price_data][product_data][name]": `Yano4l ${t.name}`,
      "line_items[0][price_data][product_data][description]": `${artistName} â ${trackTitle}`.slice(0, 200),
      client_reference_id: String(row.id),
      "metadata[submission_id]": String(row.id),
      success_url: `${origin}/?checkout=success&session_id={CHECKOUT_SESSION_ID}#queue`,
      cancel_url: `${origin}/?checkout=cancelled#submit`,
    };
    if (email) form.customer_email = email;
    const session = await stripe("checkout/sessions", { method: "POST", form });
    await db.update(submissions).set({ stripeSessionId: session.id }).where(eq(submissions.id, row.id));
    return c.json({ url: session.url });
  } catch (err) {
    await db.delete(submissions).where(eq(submissions.id, row.id));
    if (audio) {
      // Release the upload so the artist can retry checkout without re-uploading.
      const store = audioStore();
      const meta = (await store.get(metaKey(audio.audioUploadId), { type: "json" })) as UploadMeta | null;
      if (meta) await store.setJSON(metaKey(audio.audioUploadId), { ...meta, locked: false });
    }
    return c.json({ error: (err as Error).message }, 502);
  }
});

app.post("/api/checkout/confirm", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const sessionId = clean(body.sessionId, 200);
  if (!/^cs_[A-Za-z0-9_]+$/.test(sessionId)) return c.json({ error: "Invalid session." }, 400);

  const [sub] = await db.select().from(submissions).where(eq(submissions.stripeSessionId, sessionId));
  if (!sub) return c.json({ error: "Submission not found." }, 404);

  if (sub.status === "pending_payment") {
    const session = await stripe(`checkout/sessions/${encodeURIComponent(sessionId)}`).catch(() => null);
    if (!session || session.payment_status !== "paid" || session.metadata?.submission_id !== String(sub.id)) {
      return c.json({ paid: false });
    }
    await db
      .update(submissions)
      .set({ status: "in_queue", paidAt: new Date() })
      .where(and(eq(submissions.id, sub.id), eq(submissions.status, "pending_payment")));
  }
  return c.json({ paid: true, artistName: sub.artistName, trackTitle: sub.trackTitle, tier: sub.tier });
});

// ---------- host ----------

app.post("/api/host/login", async (c) => {
  if (!process.env.HOST_PIN) return c.json({ error: "Host login is not configured." }, 503);
  const ip = clientIp(c.req.raw);
  const since = new Date(Date.now() - FAIL_WINDOW_MS);

  const [{ ipFails }] = await db
    .select({ ipFails: sql<number>`count(*)::int` })
    .from(loginAttempts)
    .where(and(eq(loginAttempts.ip, ip), gte(loginAttempts.createdAt, since)));
  const [{ allFails }] = await db
    .select({ allFails: sql<number>`count(*)::int` })
    .from(loginAttempts)
    .where(gte(loginAttempts.createdAt, since));
  if (ipFails >= MAX_FAILS_PER_IP || allFails >= MAX_FAILS_GLOBAL) {
    return c.json({ error: "Too many attempts. Try again in 15 minutes." }, 429);
  }

  const body = await c.req.json().catch(() => ({}));
  const pin = clean(body.pin, 64);
  if (!pinMatches(pin)) {
    await db.insert(loginAttempts).values({ ip });
    return c.json({ error: "Incorrect PIN." }, 401);
  }

  await db.delete(loginAttempts).where(eq(loginAttempts.ip, ip));
  setCookie(c, SESSION_COOKIE, signSession(Date.now() + SESSION_TTL_MS), {
    httpOnly: true,
    secure: new URL(c.req.url).protocol === "https:",
    sameSite: "Strict",
    path: "/api",
    maxAge: SESSION_TTL_MS / 1000,
  });
  return c.json({ ok: true });
});

app.post("/api/host/logout", (c) => {
  deleteCookie(c, SESSION_COOKIE, { path: "/api" });
  return c.json({ ok: true });
});

app.use("/api/host/*", async (c, next) => {
  if (!verifySession(getCookie(c, SESSION_COOKIE))) return c.json({ error: "Not signed in." }, 401);
  await next();
});

app.post("/api/host/settings/free", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const enabled = Boolean(body.enabled);
  await settingsStore().setJSON("freeSubmissionsEnabled", { enabled });
  return c.json({ freeEnabled: enabled });
});

app.get("/api/host/submissions", async (c) => {
  const rows = await db.select().from(submissions).where(ne(submissions.status, "pending_payment"));
  rows.sort(
    (a, b) =>
      STATUS_RANK[a.status] - STATUS_RANK[b.status] ||
      TIERS[a.tier as TierKey].rank - TIERS[b.tier as TierKey].rank ||
      (a.paidAt?.getTime() ?? 0) - (b.paidAt?.getTime() ?? 0),
  );
  c.header("Cache-Control", "no-store");
  return c.json(rows.map(({ stripeSessionId, ...r }) => r));
});

app.get("/api/host/submissions/:id/audio", async (c) => {
  const id = Number(c.req.param("id"));
  if (!Number.isInteger(id)) return c.json({ error: "Invalid submission." }, 400);
  const [sub] = await db.select().from(submissions).where(eq(submissions.id, id));
  if (!sub?.audioUploadId || !sub.audioSize) return c.json({ error: "No audio file for this submission." }, 404);

  const size = sub.audioSize;
  let start = 0;
  let end = size - 1;
  let status = 200;
  const range = c.req.header("range")?.match(/^bytes=(\d*)-(\d*)$/);
  if (range && (range[1] || range[2])) {
    if (range[1]) {
      start = Number(range[1]);
      if (range[2]) end = Math.min(Number(range[2]), size - 1);
    } else {
      start = Math.max(0, size - Number(range[2]));
    }
    if (start > end || start >= size) {
      return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${size}` } });
    }
    status = 206;
  }

  const store = audioStore();
  const uploadId = sub.audioUploadId;
  const firstChunk = Math.floor(start / AUDIO_CHUNK_BYTES);
  const lastChunk = Math.floor(end / AUDIO_CHUNK_BYTES);
  let n = firstChunk;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (n > lastChunk) return controller.close();
      const buf = (await store.get(chunkKey(uploadId, n), { type: "arrayBuffer" })) as ArrayBuffer | null;
      if (!buf) return controller.error(new Error("Missing audio chunk"));
      const chunkStart = n * AUDIO_CHUNK_BYTES;
      const from = Math.max(0, start - chunkStart);
      const to = Math.min(buf.byteLength, end - chunkStart + 1);
      controller.enqueue(new Uint8Array(buf, from, to - from));
      n++;
    },
  });

  const headers: Record<string, string> = {
    "Content-Type": sub.audioContentType || "application/octet-stream",
    "Content-Length": String(end - start + 1),
    "Accept-Ranges": "bytes",
    "Cache-Control": "private, no-store",
    "Content-Disposition": `${c.req.query("download") ? "attachment" : "inline"}; filename*=UTF-8''${encodeURIComponent(sub.audioFilename || "track")}`,
    "X-Content-Type-Options": "nosniff",
  };
  if (status === 206) headers["Content-Range"] = `bytes ${start}-${end}/${size}`;
  return new Response(stream, { status, headers });
});

app.patch("/api/host/submissions/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.json().catch(() => ({}));
  const status = clean(body.status, 20);
  if (!Number.isInteger(id) || !(QUEUE_STATUSES as readonly string[]).includes(status)) {
    return c.json({ error: "Invalid update." }, 400);
  }
  const [row] = await db
    .update(submissions)
    .set({ status })
    .where(and(eq(submissions.id, id), ne(submissions.status, "pending_payment")))
    .returning({ id: submissions.id, status: submissions.status });
  if (!row) return c.json({ error: "Submission not found." }, 404);
  return c.json(row);
});

app.notFound((c) => c.json({ error: "Not found" }, 404));
app.onError((err, c) => {
  console.error(err);
  return c.json({ error: "Something went wrong." }, 500);
});

export const config = { path: "/api/*" };

export default app;

