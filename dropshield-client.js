/**
 *dropshield-client.js
 *
 * Client-side encrypt → chunk upload  /  chunk download → merge → decrypt
 *
 * Usage (upload):
 *   import { uploadFile } from "./dropshield-client.js";
 *   const { shareUrl, ownerToken } = await uploadFile(file, { onProgress });
 *
 * Usage (download):
 *   import { downloadFile } from "./dropshield-client.js";
 *   await downloadFile(fileId, keyB64, { onProgress });
 *
 * The encryption key is embedded in the URL fragment (#key=…) so it is
 * never sent to the server.
 */

const SERVER     = "https://file-share-unique.onrender.com";
const CHUNK_SIZE = 9 * 1024 * 1024;   // 9 MB — safely under Cloudinary's 10 MB limit

// ─────────────────────────────────────────────
// WEB CRYPTO HELPERS
// ─────────────────────────────────────────────

/** Generate a fresh AES-256-GCM key */
async function generateKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,          // extractable — we need to export it for the share URL
    ["encrypt", "decrypt"]
  );
}

/** Export CryptoKey → base64 string */
async function exportKey(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bufToBase64(raw);
}

/** Import base64 string → CryptoKey */
async function importKey(b64) {
  const raw = base64ToBuf(b64);
  return crypto.subtle.importKey(
    "raw", raw,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

/** Encrypt an ArrayBuffer, returns { ciphertext: ArrayBuffer, iv: Uint8Array } */
async function encryptBuffer(key, plainBuffer) {
  const iv = crypto.getRandomValues(new Uint8Array(12));   // 96-bit IV for AES-GCM
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plainBuffer
  );
  return { ciphertext, iv };
}

/** Decrypt an ArrayBuffer using AES-GCM */
async function decryptBuffer(key, cipherBuffer, iv) {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: typeof iv === "string" ? base64ToBuf(iv) : iv },
    key,
    cipherBuffer
  );
}

// ─────────────────────────────────────────────
// BINARY / BASE64 HELPERS
// ─────────────────────────────────────────────

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

/** Split an ArrayBuffer into ≤chunkSize pieces */
function splitBuffer(buf, chunkSize) {
  const chunks = [];
  let offset = 0;
  while (offset < buf.byteLength) {
    chunks.push(buf.slice(offset, offset + chunkSize));
    offset += chunkSize;
  }
  return chunks;
}

/** Merge an array of ArrayBuffers into one */
function mergeBuffers(buffers) {
  const total = buffers.reduce((s, b) => s + b.byteLength, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const b of buffers) {
    out.set(new Uint8Array(b), offset);
    offset += b.byteLength;
  }
  return out.buffer;
}

// ─────────────────────────────────────────────
// UPLOAD
// ─────────────────────────────────────────────

/**
 * Upload a File with client-side encryption.
 *
 * @param {File} file
 * @param {{ onProgress?: (pct: number, phase: string) => void }} opts
 * @returns {{ shareUrl: string, ownerToken: string, fileId: string }}
 */
export async function uploadFile(file, { onProgress } = {}) {
  const report = (pct, phase) => onProgress?.(pct, phase);

  // 1. Read file
  report(0, "reading");
  const plainBuffer = await file.arrayBuffer();

  // 2. Encrypt
  report(2, "encrypting");
  const key = await generateKey();
  const { ciphertext, iv } = await encryptBuffer(key, plainBuffer);

  // 3. Split into chunks
  const chunks      = splitBuffer(ciphertext, CHUNK_SIZE);
  const fileId      = crypto.randomUUID();
  const totalChunks = chunks.length;

  report(5, "uploading");

  // 4. Upload each chunk
  const chunkIds = [];
  for (let i = 0; i < totalChunks; i++) {
    const blob    = new Blob([chunks[i]], { type: "application/octet-stream" });
    const form    = new FormData();
    form.append("chunk", blob, `chunk_${i}.enc`);

    const res = await fetch(`${SERVER}/upload/chunk-single`, {
      method:  "POST",
      headers: {
        "x-file-id":     fileId,
        "x-chunk-index": String(i),
      },
      body: form,
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(`Chunk ${i} upload failed: ${err.error || res.status}`);
    }

    const { chunkId } = await res.json();
    chunkIds.push(chunkId);

    // 5% – 90% for uploads
    report(5 + Math.round(((i + 1) / totalChunks) * 85), "uploading");
  }

  // 5. Finalize — send manifest
  report(92, "finalizing");
  const keyB64 = await exportKey(key);
  const ivB64  = bufToBase64(iv);

  const finalRes = await fetch(`${SERVER}/upload/finalize`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      fileId,
      fileName:    file.name,
      mimeType:    file.type || "application/octet-stream",
      size:        file.size,
      chunkIds,
      iv:          ivB64,
    }),
  });

  if (!finalRes.ok) {
    const err = await finalRes.json().catch(() => ({}));
    throw new Error(`Finalize failed: ${err.error || finalRes.status}`);
  }

  const result = await finalRes.json();
  report(100, "done");

  // 6. Build share URL — key goes in fragment, never sent to server
  const shareUrl = `${result.url}#key=${encodeURIComponent(keyB64)}`;

  return {
    shareUrl,
    ownerToken: result.ownerToken,
    fileId:     result.fileId,
    expiresAt:  result.expiresAt,
  };
}

// ─────────────────────────────────────────────
// DOWNLOAD
// ─────────────────────────────────────────────

/**
 * Download, decrypt and save a file.
 *
 * @param {string} fileId
 * @param {string} keyB64  — base64 AES-GCM key (from URL fragment)
 * @param {{ onProgress?: (pct: number, phase: string) => void }} opts
 */
export async function downloadFile(fileId, keyB64, { onProgress } = {}) {
  const report = (pct, phase) => onProgress?.(pct, phase);

  // 1. Import key
  report(0, "preparing");
  const key = await importKey(keyB64);

  // 2. Fetch manifest
  report(2, "fetching manifest");
  const infoRes = await fetch(`${SERVER}/file-info/${fileId}`);
  if (!infoRes.ok) throw new Error(infoRes.status === 410 ? "File has expired" : "File not found");
  const info = await infoRes.json();   // { chunkIds, iv, name, mimeType, totalChunks, … }

  const { chunkIds, iv, name, mimeType, totalChunks } = info;

  // 3. Fetch chunks one by one
  const chunkBuffers = [];
  for (let i = 0; i < totalChunks; i++) {
    const cid     = encodeURIComponent(chunkIds[i]);
    const chunkRes = await fetch(`${SERVER}/chunk/${cid}`);
    if (!chunkRes.ok) throw new Error(`Chunk ${i} fetch failed (${chunkRes.status})`);

    chunkBuffers.push(await chunkRes.arrayBuffer());

    // 5% – 80% for fetching
    report(5 + Math.round(((i + 1) / totalChunks) * 75), "downloading");
  }

  // 4. Merge
  report(82, "merging");
  const merged = mergeBuffers(chunkBuffers);

  // 5. Decrypt
  report(88, "decrypting");
  let plainBuffer;
  try {
    plainBuffer = await decryptBuffer(key, merged, iv);
  } catch {
    throw new Error("Decryption failed — wrong key or corrupted file");
  }

  // 6. Trigger browser download
  report(98, "saving");
  const blob    = new Blob([plainBuffer], { type: mimeType });
  const url     = URL.createObjectURL(blob);
  const a       = document.createElement("a");
  a.href        = url;
  a.download    = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 5000);

  report(100, "done");
  return { name, size: plainBuffer.byteLength, mimeType };
}

// ─────────────────────────────────────────────
// AUTO-DOWNLOAD on page load (for /file/:id pages)
//
// If this script is loaded on a page whose URL contains both:
//   - a fileId path segment  (/file/UUID)
//   - a #key= fragment
// it automatically starts the download.
// ─────────────────────────────────────────────
export function autoDownloadIfSharePage(onProgress) {
  const match  = location.pathname.match(/\/file\/([a-f0-9-]{36})/i);
  const keyB64 = new URLSearchParams(location.hash.slice(1)).get("key");

  if (match && keyB64) {
    downloadFile(match[1], keyB64, { onProgress }).catch(err => {
      console.error("Auto-download failed:", err.message);
    });
  }
}
