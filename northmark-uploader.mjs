// Northmark - YouTube automation via the official YouTube Data API v3 (free, quota-based).
// No extra npm packages: plain fetch + Node built-ins.
//
// Secrets live OUTSIDE the project (never commit, never print):
//   %USERPROFILE%\.northmark\youtube-client.json   OAuth client (type "Desktop app") downloaded from Google Cloud
//   %USERPROFILE%\.northmark\youtube-token.json    refresh token written by "auth"
//   (override the folder with env NORTHMARK_SECRETS)
//
// Commands:
//   node automation/youtube.mjs auth                         one-time Google sign-in in the browser (loopback + PKCE)
//   node automation/youtube.mjs whoami                       show the authorised channel (name, handle)
//   node automation/youtube.mjs upload  <upload.json>        upload video as PRIVATE + thumbnail + captions
//   node automation/youtube.mjs update  <videoId> <upload.json>  set title/description/tags/thumbnail/captions
//                                                            on an existing video (e.g. one uploaded in Studio)
//   node automation/youtube.mjs status  <videoId>            privacy / upload / processing status
//   node automation/youtube.mjs publish <videoId> --confirm=<videoId> [--at=2026-11-20T17:00:00+01:00]
//        makes the video public now, or schedules it (private + publishAt). ONLY run after the user's explicit
//        approval in chat for this specific video (CLAUDE.md). --confirm must repeat the id to avoid accidents.
//
// Note: videos uploaded with videos.insert from an UNAUDITED API project (created after 28.07.2020) stay
// "private (locked)" and cannot be made public, not even in Studio. Until the project passes Google's audit,
// upload in Studio (private) and use "update" + "publish" from here.
//
// upload.json: { "video": "...mp4", "thumbnail": "...png|jpg", "captions": { "file": "...srt", "language": "en", "name": "English" },
//   "title": "...", "description": "...", "tags": [...], "categoryId": "27", "defaultLanguage": "en",
//   "defaultAudioLanguage": "en", "madeForKids": false, "containsSyntheticMedia": false }
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";

const DIR = process.env.NORTHMARK_SECRETS || path.join(os.homedir(), ".northmark");
const CLIENT_FILE = path.join(DIR, "youtube-client.json");
const TOKEN_FILE = path.join(DIR, "youtube-token.json");
const SCOPES = ["https://www.googleapis.com/auth/youtube.upload", "https://www.googleapis.com/auth/youtube.force-ssl"];
const API = "https://www.googleapis.com/youtube/v3";
const UPLOAD = "https://www.googleapis.com/upload/youtube/v3";
const log = (...a) => console.log(new Date().toLocaleTimeString("de-DE"), ...a);
const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8").replace(/^﻿/, ""));

function client() {
  if (!fs.existsSync(CLIENT_FILE)) throw new Error(`OAuth client file missing: ${CLIENT_FILE} (see CLAUDE.md, YouTube setup)`);
  const j = readJson(CLIENT_FILE);
  const c = j.installed || j.web;
  if (!c?.client_id || !c?.client_secret) throw new Error("youtube-client.json has no installed.client_id / client_secret (use type 'Desktop app')");
  return c;
}

async function auth() {
  const c = client();
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const state = crypto.randomBytes(16).toString("hex");
  const server = http.createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const redirect = `http://127.0.0.1:${server.address().port}`;
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  Object.entries({
    client_id: c.client_id, redirect_uri: redirect, response_type: "code", scope: SCOPES.join(" "),
    access_type: "offline", prompt: "consent", code_challenge: challenge, code_challenge_method: "S256", state,
  }).forEach(([k, v]) => url.searchParams.set(k, v));
  const code = await new Promise((resolve, reject) => {
    server.on("request", (req, res) => {
      const u = new URL(req.url, redirect);
      if (u.searchParams.get("state") !== state) { res.end("State mismatch."); return; }
      const err = u.searchParams.get("error");
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(err ? "<h2>Anmeldung abgebrochen.</h2>" : "<h2>Northmark: Anmeldung erfolgreich. Dieses Fenster kann geschlossen werden.</h2>");
      server.close();
      err ? reject(new Error(`Google sign-in: ${err}`)) : resolve(u.searchParams.get("code"));
    });
    log("Opening the Google sign-in page in your browser ...");
    spawn("cmd", ["/c", "start", "", url.toString().replace(/&/g, "^&")], { stdio: "ignore", detached: true }).unref();
  });
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: c.client_id, client_secret: c.client_secret, redirect_uri: redirect, grant_type: "authorization_code", code_verifier: verifier }),
  });
  const t = await r.json();
  if (!t.refresh_token) throw new Error(`No refresh token received: ${t.error || r.status} ${t.error_description || ""}`);
  fs.mkdirSync(DIR, { recursive: true });
  fs.writeFileSync(TOKEN_FILE, JSON.stringify({ refresh_token: t.refresh_token, scope: t.scope, created: new Date().toISOString() }, null, 2));
  log(`Signed in. Token stored in ${TOKEN_FILE} (not printed).`);
}

let cached;
async function accessToken() {
  if (cached && cached.exp > Date.now() + 60_000) return cached.token;
  if (!fs.existsSync(TOKEN_FILE)) throw new Error("Not signed in: run  node automation/youtube.mjs auth");
  const c = client();
  const { refresh_token } = readJson(TOKEN_FILE);
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ refresh_token, client_id: c.client_id, client_secret: c.client_secret, grant_type: "refresh_token" }),
  });
  const t = await r.json();
  if (!t.access_token) throw new Error(`Token refresh failed (${t.error || r.status}). If the app is in "Testing" mode, tokens expire after 7 days: run auth again.`);
  cached = { token: t.access_token, exp: Date.now() + t.expires_in * 1000 };
  return cached.token;
}

async function api(method, url, { json, body, headers = {}, raw = false } = {}) {
  const r = await fetch(url, {
    method,
    headers: { Authorization: `Bearer ${await accessToken()}`, ...(json ? { "Content-Type": "application/json" } : {}), ...headers },
    body: json ? JSON.stringify(json) : body,
  });
  if (raw) return r;
  const text = await r.text();
  if (!r.ok) throw new Error(`${method} ${url.split("?")[0]} -> ${r.status}: ${text.slice(0, 600)}`);
  return text ? JSON.parse(text) : {};
}

const snippetOf = (p) => ({
  title: p.title, description: p.description, tags: p.tags || [], categoryId: String(p.categoryId || "27"),
  defaultLanguage: p.defaultLanguage || "en", defaultAudioLanguage: p.defaultAudioLanguage || "en",
});

async function setThumbnail(videoId, file) {
  const size = fs.statSync(file).size;
  if (size > 2 * 1024 * 1024) throw new Error(`Thumbnail ${path.basename(file)} is ${(size / 1048576).toFixed(1)} MB; YouTube allows max 2 MB (convert to JPG first)`);
  const type = /\.png$/i.test(file) ? "image/png" : "image/jpeg";
  await api("POST", `${UPLOAD}/thumbnails/set?videoId=${videoId}&uploadType=media`, { body: fs.readFileSync(file), headers: { "Content-Type": type } });
  log(`thumbnail set (${path.basename(file)})`);
}

async function addCaptions(videoId, cap) {
  const boundary = "nm" + crypto.randomBytes(8).toString("hex");
  const meta = { snippet: { videoId, language: cap.language || "en", name: cap.name || "English", isDraft: false } };
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`),
    fs.readFileSync(cap.file),
    Buffer.from(`\r\n--${boundary}--`),
  ]);
  await api("POST", `${UPLOAD}/captions?part=snippet&uploadType=multipart`, { body, headers: { "Content-Type": `multipart/related; boundary=${boundary}` } });
  log(`captions uploaded (${cap.language || "en"})`);
}

async function upload(pkgFile) {
  const base = path.dirname(path.resolve(pkgFile));
  const p = readJson(pkgFile);
  const rel = (f) => path.resolve(base, f);
  const video = rel(p.video);
  const size = fs.statSync(video).size;
  const meta = {
    snippet: snippetOf(p),
    status: { privacyStatus: "private", selfDeclaredMadeForKids: !!p.madeForKids, containsSyntheticMedia: !!p.containsSyntheticMedia },
  };
  const init = await api("POST", `${UPLOAD}/videos?uploadType=resumable&part=snippet,status`, {
    json: meta, raw: true, headers: { "X-Upload-Content-Length": String(size), "X-Upload-Content-Type": "video/mp4" },
  });
  if (!init.ok) throw new Error(`upload init -> ${init.status}: ${(await init.text()).slice(0, 600)}`);
  const session = init.headers.get("location");
  const CHUNK = 32 * 1024 * 1024;
  const fd = fs.openSync(video, "r");
  let offset = 0, result;
  log(`uploading ${path.basename(video)} (${(size / 1048576).toFixed(0)} MB) as PRIVATE ...`);
  while (offset < size) {
    const len = Math.min(CHUNK, size - offset);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, offset);
    const r = await fetch(session, {
      method: "PUT",
      headers: { Authorization: `Bearer ${await accessToken()}`, "Content-Length": String(len), "Content-Range": `bytes ${offset}-${offset + len - 1}/${size}` },
      body: buf,
    });
    if (r.status === 308) {
      const range = r.headers.get("range");
      offset = range ? Number(range.split("-")[1]) + 1 : offset + len;
      log(`  ${((offset / size) * 100).toFixed(0)} %`);
    } else if (r.ok) { result = await r.json(); offset = size; }
    else throw new Error(`upload chunk -> ${r.status}: ${(await r.text()).slice(0, 600)}`);
  }
  fs.closeSync(fd);
  log(`uploaded: videoId ${result.id} (privacy: ${result.status?.privacyStatus})`);
  if (p.thumbnail) await setThumbnail(result.id, rel(p.thumbnail));
  if (p.captions?.file) await addCaptions(result.id, { ...p.captions, file: rel(p.captions.file) });
  console.log(`VIDEO_ID=${result.id}`);
}

async function getVideo(id) {
  const r = await api("GET", `${API}/videos?part=snippet,status,processingDetails&id=${id}`);
  if (!r.items?.length) throw new Error(`Video ${id} not found on the authorised channel`);
  return r.items[0];
}

async function update(id, pkgFile) {
  const base = path.dirname(path.resolve(pkgFile));
  const p = readJson(pkgFile);
  const v = await getVideo(id);
  await api("PUT", `${API}/videos?part=snippet,status`, {
    json: {
      id, snippet: snippetOf(p),
      status: { privacyStatus: v.status.privacyStatus, ...(v.status.publishAt ? { publishAt: v.status.publishAt } : {}), selfDeclaredMadeForKids: !!p.madeForKids, containsSyntheticMedia: !!p.containsSyntheticMedia },
    },
  });
  log(`metadata updated for ${id} (privacy unchanged: ${v.status.privacyStatus})`);
  if (p.thumbnail) await setThumbnail(id, path.resolve(base, p.thumbnail));
  if (p.captions?.file) {
    const caps = await api("GET", `${API}/captions?part=snippet&videoId=${id}`);
    const lang = p.captions.language || "en";
    if (caps.items?.some((c) => c.snippet.language === lang && c.snippet.trackKind !== "asr")) log(`captions (${lang}) already present - skipped`);
    else await addCaptions(id, { ...p.captions, file: path.resolve(base, p.captions.file) });
  }
}

async function status(id) {
  const v = await getVideo(id);
  console.log(JSON.stringify({ id, title: v.snippet.title, privacy: v.status.privacyStatus, publishAt: v.status.publishAt || null, upload: v.status.uploadStatus, processing: v.processingDetails?.processingStatus || null, madeForKids: v.status.madeForKids }, null, 2));
}

async function publish(id, args) {
  const confirm = (args.find((a) => a.startsWith("--confirm=")) || "").slice(10);
  if (confirm !== id) throw new Error("Refusing: --confirm=<videoId> must repeat the video id (publish only after explicit user approval).");
  const at = (args.find((a) => a.startsWith("--at=")) || "").slice(5);
  const v = await getVideo(id);
  const statusBody = at
    ? { privacyStatus: "private", publishAt: new Date(at).toISOString(), selfDeclaredMadeForKids: v.status.madeForKids ?? false }
    : { privacyStatus: "public", selfDeclaredMadeForKids: v.status.madeForKids ?? false };
  await api("PUT", `${API}/videos?part=status`, { json: { id, status: statusBody } });
  const after = await getVideo(id);
  log(at ? `scheduled: ${id} goes public at ${after.status.publishAt || statusBody.publishAt}` : `published: ${id} is now ${after.status.privacyStatus}`);
  if (!at && after.status.privacyStatus !== "public") log("WARNING: still not public - probably locked (uploaded via an unaudited API project).");
}

async function list() {
  const ch = await api("GET", `${API}/channels?part=contentDetails&mine=true`);
  const uploads = ch.items?.[0]?.contentDetails?.relatedPlaylists?.uploads;
  if (!uploads) throw new Error("no uploads playlist");
  const pl = await api("GET", `${API}/playlistItems?part=contentDetails&maxResults=25&playlistId=${uploads}`);
  const ids = (pl.items || []).map((i) => i.contentDetails.videoId);
  if (!ids.length) { console.log("no videos"); return; }
  const v = await api("GET", `${API}/videos?part=snippet,status&id=${ids.join(",")}`);
  for (const x of v.items) console.log(`${x.id}  ${x.status.privacyStatus.padEnd(8)}  ${x.snippet.publishedAt.slice(0, 10)}  ${x.snippet.title}`);
}

async function whoami() {
  const r = await api("GET", `${API}/channels?part=snippet&mine=true`);
  const c = r.items?.[0];
  console.log(c ? `${c.snippet.title} (${c.snippet.customUrl || c.id})` : "no channel");
}

const [cmd, ...rest] = process.argv.slice(2);
const run = { auth, whoami, list, upload: () => upload(rest[0]), update: () => update(rest[0], rest[1]), status: () => status(rest[0]), publish: () => publish(rest[0], rest.slice(1)) }[cmd];
if (!run) { console.log("Usage: node automation/youtube.mjs auth | whoami | upload <upload.json> | update <id> <upload.json> | status <id> | publish <id> --confirm=<id> [--at=ISO]"); process.exit(1); }
run().catch((e) => { console.error("ERROR:", e.message); process.exit(1); });
