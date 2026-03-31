/**
 * dropshield-client.js
 * Client-side encrypt → chunk upload / chunk download → merge → decrypt
 * + Owner dashboard API (list files, set expiry, delete)
 */

export const SERVER     = "https://file-share-unique.onrender.com";
const CHUNK_SIZE = 9 * 1024 * 1024;  // 9 MB — under Cloudinary 10 MB limit

// ─────────────────────────────────────────────
// OWNER KEY — persistent identity stored in localStorage
// Generated once per browser. Sent with every upload so the server
// can associate files with this owner. Never exposed publicly.
// ─────────────────────────────────────────────

export function getOrCreateOwnerKey() {
  let key = localStorage.getItem("ds_owner_key");
  if (!key) {
    key = Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2, "0")).join("");
    localStorage.setItem("ds_owner_key", key);
  }
  return key;
}

// Store per-file ownerToken (for individual file ops without the session key)
export function saveOwnerToken(fileId, token) {
  const map = JSON.parse(localStorage.getItem("ds_owner_tokens") || "{}");
  map[fileId] = token;
  localStorage.setItem("ds_owner_tokens", JSON.stringify(map));
}
export function getOwnerToken(fileId) {
  const map = JSON.parse(localStorage.getItem("ds_owner_tokens") || "{}");
  return map[fileId] || null;
}

// ─────────────────────────────────────────────
// CRYPTO HELPERS
// ─────────────────────────────────────────────

async function generateKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}
async function exportKey(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bufToBase64(raw);
}
async function importKey(b64) {
  return crypto.subtle.importKey(
    "raw", base64ToBuf(b64),
    { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
}
async function encryptBuffer(key, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
  return { ciphertext: ct, iv };
}
async function decryptBuffer(key, cipher, iv) {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: typeof iv === "string" ? base64ToBuf(iv) : iv },
    key, cipher
  );
}

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function splitBuffer(buf, size) {
  const chunks = [];
  for (let o = 0; o < buf.byteLength; o += size) chunks.push(buf.slice(o, o + size));
  return chunks;
}
function mergeBuffers(bufs) {
  const total = bufs.reduce((s, b) => s + b.byteLength, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const b of bufs) { out.set(new Uint8Array(b), offset); offset += b.byteLength; }
  return out.buffer;
}

// ─────────────────────────────────────────────
// UPLOAD
// ─────────────────────────────────────────────

/**
 * @param {File} file
 * @param {{ onProgress?, expiryMs? }} opts
 * @returns {{ shareUrl, ownerToken, fileId, expiresAt }}
 */
export async function uploadFile(file, { onProgress, expiryMs } = {}) {
  const report = (p, ph) => onProgress?.(p, ph);
  const ownerKey = getOrCreateOwnerKey();

  report(0, "reading");
  const plain = await file.arrayBuffer();

  report(2, "encrypting");
  const key              = await generateKey();
  const { ciphertext, iv } = await encryptBuffer(key, plain);

  const chunks      = splitBuffer(ciphertext, CHUNK_SIZE);
  const fileId      = crypto.randomUUID();
  const totalChunks = chunks.length;

  report(5, "uploading");
  const chunkIds = [];

  for (let i = 0; i < totalChunks; i++) {
    const form = new FormData();
    form.append("chunk", new Blob([chunks[i]], { type: "application/octet-stream" }), `chunk_${i}.enc`);

    const res = await fetch(`${SERVER}/upload/chunk-single`, {
      method: "POST",
      headers: { "x-file-id": fileId, "x-chunk-index": String(i) },
      body: form,
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(`Chunk ${i} failed: ${e.error || res.status}`);
    }
    chunkIds.push((await res.json()).chunkId);
    report(5 + Math.round(((i + 1) / totalChunks) * 85), "uploading");
  }

  report(92, "finalizing");
  const keyB64 = await exportKey(key);
  const ivB64  = bufToBase64(iv);

  const finalRes = await fetch(`${SERVER}/upload/finalize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      fileId, fileName: file.name,
      mimeType: file.type || "application/octet-stream",
      size: file.size, chunkIds, iv: ivB64,
      ownerKey,
      expiryMs: expiryMs || undefined,
    }),
  });
  if (!finalRes.ok) {
    const e = await finalRes.json().catch(() => ({}));
    throw new Error(`Finalize failed: ${e.error || finalRes.status}`);
  }

  const result = await finalRes.json();
  report(100, "done");

  // Persist ownerToken for this file
  saveOwnerToken(fileId, result.ownerToken);

  const shareUrl = `${result.url}#key=${encodeURIComponent(keyB64)}`;
  return { shareUrl, ownerToken: result.ownerToken, fileId: result.fileId, expiresAt: result.expiresAt };
}

// ─────────────────────────────────────────────
// DOWNLOAD
// ─────────────────────────────────────────────

/**
 * @param {string} fileId
 * @param {string} keyB64
 * @param {{ onProgress? }} opts
 */
export async function downloadFile(fileId, keyB64, { onProgress } = {}) {
  const report = (p, ph) => onProgress?.(p, ph);

  report(0, "preparing");
  const key = await importKey(keyB64);

  report(2, "fetching manifest");
  const infoRes = await fetch(`${SERVER}/file-info/${fileId}`);
  if (!infoRes.ok) throw new Error(infoRes.status === 410 ? "File has expired" : "File not found");
  const { chunkIds, iv, name, mimeType, totalChunks } = await infoRes.json();

  const chunkBufs = [];
  for (let i = 0; i < totalChunks; i++) {
    const cid      = encodeURIComponent(chunkIds[i]);
    const chunkRes = await fetch(`${SERVER}/chunk/${cid}`);
    if (!chunkRes.ok) throw new Error(`Chunk ${i} failed (${chunkRes.status})`);
    chunkBufs.push(await chunkRes.arrayBuffer());
    report(5 + Math.round(((i + 1) / totalChunks) * 75), "downloading");
  }

  report(82, "merging");
  const merged = mergeBuffers(chunkBufs);

  report(88, "decrypting");
  let plain;
  try { plain = await decryptBuffer(key, merged, iv); }
  catch { throw new Error("Decryption failed — wrong key or corrupted file"); }

  report(98, "saving");
  const blob = new Blob([plain], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 5000);

  report(100, "done");
  return { name, size: plain.byteLength, mimeType };
}

// ─────────────────────────────────────────────
// OWNER DASHBOARD API
// ─────────────────────────────────────────────

/** Fetch all files uploaded by this browser session */
export async function fetchMyFiles() {
  const ownerKey = getOrCreateOwnerKey();
  const res = await fetch(`${SERVER}/owner/files`, {
    headers: { "x-owner-key": ownerKey },
  });
  if (!res.ok) throw new Error("Failed to fetch file list");
  return res.json();   // array of file objects
}

/**
 * Set a new absolute expiry for a file.
 * @param {string} fileId
 * @param {number} expiresAt  — unix ms timestamp
 */
export async function setExpiry(fileId, expiresAt) {
  const ownerKey   = getOrCreateOwnerKey();
  const ownerToken = getOwnerToken(fileId);

  const res = await fetch(`${SERVER}/file/${fileId}/expiry`, {
    method:  "PATCH",
    headers: {
      "Content-Type":  "application/json",
      "x-owner-key":   ownerKey,
      ...(ownerToken ? { "x-owner-token": ownerToken } : {}),
    },
    body: JSON.stringify({ expiresAt }),
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.error || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Permanently delete a file and all its Cloudinary chunks.
 * @param {string} fileId
 */
export async function deleteFile(fileId) {
  const ownerKey   = getOrCreateOwnerKey();
  const ownerToken = getOwnerToken(fileId);

  const res = await fetch(`${SERVER}/file/${fileId}`, {
    method:  "DELETE",
    headers: {
      "x-owner-key": ownerKey,
      ...(ownerToken ? { "x-owner-token": ownerToken } : {}),
    },
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.error || `HTTP ${res.status}`);
  }
  return res.json();
}

// ─────────────────────────────────────────────
// AUTO-DOWNLOAD helper
// ─────────────────────────────────────────────
export function autoDownloadIfSharePage(onProgress) {
  const match  = location.pathname.match(/\/file\/([a-f0-9-]{36})/i);
  const keyB64 = new URLSearchParams(location.hash.slice(1)).get("key");
  if (match && keyB64) {
    downloadFile(match[1], keyB64, { onProgress }).catch(console.error);
  }
}
