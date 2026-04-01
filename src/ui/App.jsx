import { useState, useEffect, useRef, createContext, useContext, useCallback } from "react";

// ============================================================================
// Theme
// ============================================================================
const T = {
  bg: "#0f0f0f", bgCard: "#1a1a1a", bgHover: "#242424", bgInput: "#1e1e1e",
  border: "#2a2a2a", borderFocus: "#4a9eff", text: "#e8e8e8", textMuted: "#888",
  textDim: "#555", accent: "#4a9eff", accentDim: "rgba(74,158,255,0.1)",
  danger: "#ff4a4a", success: "#4aff8b", warn: "#ffb84a",
};

// ============================================================================
// Linkify — converts URLs in text to clickable links
// ============================================================================
const URL_RE = /(https?:\/\/[^\s<>"{}|\\^`[\]]+|www\.[^\s<>"{}|\\^`[\]]+)/gi;
function Linkify({ text, color }) {
  if (!text) return null;
  const parts = [];
  let last = 0;
  for (const match of text.matchAll(URL_RE)) {
    if (match.index > last) parts.push(text.slice(last, match.index));
    let url = match[0];
    const href = url.startsWith("www.") ? "https://" + url : url;
    // Strip trailing punctuation that's likely not part of the URL
    const trailingMatch = url.match(/[).,;:!?]+$/);
    let trailing = "";
    if (trailingMatch) { trailing = trailingMatch[0]; url = url.slice(0, -trailing.length); }
    const cleanHref = url.startsWith("www.") ? "https://" + url : url;
    parts.push(
      <a key={match.index} href={cleanHref} target="_blank" rel="noopener noreferrer"
        style={{ color: color || T.accent, textDecoration: "underline", wordBreak: "break-all" }}>{url}</a>
    );
    if (trailing) parts.push(trailing);
    last = match.index + match[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts.length > 0 ? parts : text;
}

// ============================================================================
// Responsive hook
// ============================================================================
function useIsMobile(breakpoint = 768) {
  const [isMobile, setIsMobile] = useState(() => typeof window !== "undefined" && window.innerWidth < breakpoint);
  useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${breakpoint - 1}px)`);
    const handler = (e) => setIsMobile(e.matches);
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }, [breakpoint]);
  return isMobile;
}

// ============================================================================
// Crypto helpers
// ============================================================================
const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const enc = new TextEncoder();
const dec = new TextDecoder();

// ============================================================================
// Bloom filter (client-side)
// ============================================================================
function murmurhash3(key, seed) {
  let h = seed >>> 0;
  const len = key.length;
  const nblocks = len >> 2;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  for (let i = 0; i < nblocks; i++) {
    let k = (key.charCodeAt(i*4)&0xff)|((key.charCodeAt(i*4+1)&0xff)<<8)|((key.charCodeAt(i*4+2)&0xff)<<16)|((key.charCodeAt(i*4+3)&0xff)<<24);
    k = Math.imul(k,c1); k = (k<<15)|(k>>>17); k = Math.imul(k,c2);
    h ^= k; h = (h<<13)|(h>>>19); h = Math.imul(h,5)+0xe6546b64;
  }
  let k = 0; const tail = nblocks*4;
  switch(len&3){
    case 3: k ^= (key.charCodeAt(tail+2)&0xff)<<16;
    case 2: k ^= (key.charCodeAt(tail+1)&0xff)<<8;
    case 1: k ^= (key.charCodeAt(tail)&0xff);
      k = Math.imul(k,c1); k = (k<<15)|(k>>>17); k = Math.imul(k,c2); h ^= k;
  }
  h ^= len; h ^= h>>>16; h = Math.imul(h,0x85ebca6b);
  h ^= h>>>13; h = Math.imul(h,0xc2b2ae35); h ^= h>>>16;
  return h >>> 0;
}

const BLOOM_HASH_COUNT = 3;
const BLOOM_MIN_BITS = 16;
const BLOOM_MAX_BITS = 8192;
const BLOOM_DEFAULT_BITS = 512;
const BLOOM_TARGET_NOISE_RATIO = 10;
let cachedUserCount = 0;

// Compute optimal bloom filter size for a target noise-to-signal ratio.
// With k hash functions, n items, and m bits: FPR ≈ (1 - e^(-kn/m))^k
// We want (totalUsers - n) * FPR / n = TARGET_NOISE_RATIO, so solve for m.
function computeBloomBits(friendCount, totalUsers) {
  const n = Math.max(friendCount, 1);
  const N = Math.max(totalUsers, n);
  if (N <= 0) return BLOOM_DEFAULT_BITS;
  const nonFriends = N - n;
  if (nonFriends <= 0) return BLOOM_MIN_BITS;
  const targetFpr = BLOOM_TARGET_NOISE_RATIO * n / nonFriends;
  if (targetFpr >= 1) return BLOOM_MIN_BITS;
  const k = BLOOM_HASH_COUNT;
  const m = -k * n / Math.log(1 - Math.pow(targetFpr, 1 / k));
  return Math.max(BLOOM_MIN_BITS, Math.min(BLOOM_MAX_BITS, Math.ceil(m / 8) * 8));
}

function createBloomFilter(usernames, totalUsers) {
  const bloomBits = totalUsers > 0 ? computeBloomBits(usernames.length, totalUsers) : BLOOM_DEFAULT_BITS;
  const bits = new Uint8Array(bloomBits / 8);
  for (const u of usernames) {
    for (let i = 0; i < BLOOM_HASH_COUNT; i++) {
      const hash = murmurhash3(u, i) % bloomBits;
      bits[hash >> 3] |= (1 << (hash & 7));
    }
  }
  return toB64(bits);
}

// ============================================================================
// Deterministic key derivation from password
// ============================================================================
async function deriveAllKeys(username, password, domain, feedKeyVersion = 1) {
  const saltInput = enc.encode(`${domain}:${username}:friendsforum-v2`);
  const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", saltInput));
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const masterBits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, baseKey, 512
  ));
  const hkdfKey = await crypto.subtle.importKey("raw", masterBits, "HKDF", false, ["deriveBits", "deriveKey"]);
  const sigBits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("identity-signing"), info: enc.encode("p256-key") }, hkdfKey, 256
  ));
  const sigKeyPair = await importP256Private(sigBits, "ECDSA");
  const encBits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("identity-encryption"), info: enc.encode("p256-key") }, hkdfKey, 256
  ));
  const encKeyPair = await importP256Private(encBits, "ECDH");
  const feedKeyBits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(`feed-key-v${feedKeyVersion}`), info: enc.encode("aes256") }, hkdfKey, 256
  ));
  const feedKey = await crypto.subtle.importKey("raw", feedKeyBits, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const vaultKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("vault-key"), info: enc.encode("aes256") },
    hkdfKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
  const sigPubRaw = await crypto.subtle.exportKey("raw", sigKeyPair.publicKey);
  const encPubRaw = await crypto.subtle.exportKey("raw", encKeyPair.publicKey);
  const fpHash = await crypto.subtle.digest("SHA-256", sigPubRaw);
  const fingerprint = Array.from(new Uint8Array(fpHash).slice(0, 8))
    .map(b => b.toString(16).padStart(2, "0")).join("")
    .match(/.{4}/g).join("-");
  return {
    signing: sigKeyPair, encryption: encKeyPair, feedKey, feedKeyVersion,
    feedKeyB64: toB64(feedKeyBits), vaultKey, fingerprint,
    signingPublicKeyB64: toB64(new Uint8Array(sigPubRaw)),
    encryptionPublicKeyB64: toB64(new Uint8Array(encPubRaw)),
  };
}

// ============================================================================
// Deterministic P-256 keypair from seed bytes
// ============================================================================
const P256 = {
  p: BigInt("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
  a: BigInt("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
  b: BigInt("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
  n: BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
  Gx: BigInt("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
  Gy: BigInt("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
  mod(a, m) { return ((a % m) + m) % m; },
  modInv(a, m) {
    let [old_r, r] = [this.mod(a, m), m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) { const q = old_r / r; [old_r, r] = [r, old_r - q * r]; [old_s, s] = [s, old_s - q * s]; }
    return this.mod(old_s, m);
  },
  pointAdd(x1, y1, x2, y2) {
    if (x1 === null) return [x2, y2];
    if (x2 === null) return [x1, y1];
    const p = this.p;
    if (x1 === x2 && y1 === y2) {
      const s = this.mod((3n * x1 * x1 + this.a) * this.modInv(2n * y1, p), p);
      const x3 = this.mod(s * s - 2n * x1, p); const y3 = this.mod(s * (x1 - x3) - y1, p); return [x3, y3];
    }
    if (x1 === x2) return [null, null];
    const s = this.mod((y2 - y1) * this.modInv(x2 - x1, p), p);
    const x3 = this.mod(s * s - x1 - x2, p); const y3 = this.mod(s * (x1 - x3) - y1, p); return [x3, y3];
  },
  scalarMul(k, x, y) {
    let [rx, ry] = [null, null]; let [qx, qy] = [x, y]; k = this.mod(k, this.n);
    while (k > 0n) { if (k & 1n) [rx, ry] = this.pointAdd(rx, ry, qx, qy); [qx, qy] = this.pointAdd(qx, qy, qx, qy); k >>= 1n; }
    return [rx, ry];
  },
  publicFromScalar(d) { return this.scalarMul(d, this.Gx, this.Gy); },
  toBytes32(n) { const b = new Uint8Array(32); let t = n; for (let i = 31; i >= 0; i--) { b[i] = Number(t & 0xFFn); t >>= 8n; } return b; },
  bytesToBigInt(bytes) { let r = 0n; for (const b of bytes) r = (r << 8n) | BigInt(b); return r; },
};

async function importP256Private(seedBytes, algorithm) {
  const scalar = (P256.bytesToBigInt(seedBytes) % (P256.n - 1n)) + 1n;
  const [pubX, pubY] = P256.publicFromScalar(scalar);
  const dB64url = uint8ToB64url(P256.toBytes32(scalar));
  const xB64url = uint8ToB64url(P256.toBytes32(pubX));
  const yB64url = uint8ToB64url(P256.toBytes32(pubY));
  const alg = algorithm === "ECDSA" ? { name: "ECDSA", namedCurve: "P-256" } : { name: "ECDH", namedCurve: "P-256" };
  const privUsages = algorithm === "ECDSA" ? ["sign"] : ["deriveKey", "deriveBits"];
  const pubUsages = algorithm === "ECDSA" ? ["verify"] : [];
  const privJwk = { kty: "EC", crv: "P-256", d: dB64url, x: xB64url, y: yB64url };
  const pubJwk = { kty: "EC", crv: "P-256", x: xB64url, y: yB64url };
  const privateKey = await crypto.subtle.importKey("jwk", privJwk, alg, true, privUsages);
  const publicKey = await crypto.subtle.importKey("jwk", pubJwk, alg, true, pubUsages);
  return { privateKey, publicKey };
}

function uint8ToB64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ============================================================================
// Feed key encryption
// ============================================================================
async function encryptWithFeedKey(plaintext, feedKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, feedKey, enc.encode(plaintext));
  return { ciphertext: toB64(new Uint8Array(ct)), iv: toB64(iv) };
}

async function decryptWithFeedKey(ciphertext, iv, feedKey) {
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, feedKey, fromB64(ciphertext));
    return dec.decode(plain);
  } catch { return null; }
}

async function encryptBlob(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { ciphertext: new Uint8Array(ct), iv };
}

async function computeHashClient(uint8arr) {
  const hash = await crypto.subtle.digest("SHA-256", uint8arr);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashUsername(username) {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(username));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function truncateHash(hash, len = 12) {
  if (!hash) return "???";
  return hash.slice(0, len) + "...";
}

// ============================================================================
// Vault
// ============================================================================
async function encryptVault(vaultData, vaultKey) {
  const json = JSON.stringify(vaultData);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vaultKey, enc.encode(json));
  return JSON.stringify({ ct: toB64(new Uint8Array(ct)), iv: toB64(iv) });
}

async function decryptVault(vaultStr, vaultKey) {
  try {
    const { ct, iv } = JSON.parse(vaultStr);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, vaultKey, fromB64(ct));
    return JSON.parse(dec.decode(plain));
  } catch { return null; }
}

// ============================================================================
// Vault friend lookup by hash (caches hash→addr mappings)
// ============================================================================
const vaultHashCache = new Map();

function findFriendByHashSync(hash) {
  if (!vault?.friends || !/^[a-f0-9]{64}$/.test(hash)) return null;
  // Collect all entries that match this hash and merge them
  let merged = null;
  // Direct hash@domain entry
  for (const [k, v] of Object.entries(vault.friends)) {
    if (k.startsWith(hash + "@")) { merged = { ...v }; break; }
  }
  // Cached plaintext@domain entry
  if (vaultHashCache.has(hash)) {
    const addr = vaultHashCache.get(hash);
    const v = vault.friends[addr];
    if (v) {
      if (merged) {
        // Merge: prefer existing values, fill in missing from old entry
        for (const [pk, pv] of Object.entries(v)) {
          if (merged[pk] === undefined || merged[pk] === null) merged[pk] = pv;
        }
      } else {
        merged = { ...v };
      }
    }
  }
  return merged;
}

// Find a friend by plaintext username — scans plaintextUsername fields and checks direct addr
function findFriendByPlaintextSync(username) {
  if (!vault?.friends || /^[a-f0-9]{64}$/.test(username)) return null;
  // Check direct plaintext@domain entry
  for (const [k, v] of Object.entries(vault.friends)) {
    if (k.split("@")[0] === username) return v;
  }
  // Check plaintextUsername field on hash-keyed entries
  for (const [, v] of Object.entries(vault.friends)) {
    if (v.plaintextUsername === username) return v;
  }
  return null;
}

async function findFriend(username) {
  if (!vault?.friends) return null;
  // If it's a hash, use hash-based lookup
  if (/^[a-f0-9]{64}$/.test(username)) {
    // Ensure all plaintext entries are cached
    for (const [k] of Object.entries(vault.friends)) {
      const friendUser = k.split("@")[0];
      if (/^[a-f0-9]{64}$/.test(friendUser)) continue;
      const friendHash = await hashUsername(friendUser);
      vaultHashCache.set(friendHash, k);
    }
    return findFriendByHashSync(username);
  }
  // It's a plaintext username — check direct entry first
  let result = findFriendByPlaintextSync(username);
  if (result) return result;
  // Hash it and try hash-based lookup
  const hash = await hashUsername(username);
  return findFriendByHashSync(hash);
}

// Sync version: tries plaintext scan, then hash cache lookup
function findFriendSync(username) {
  if (!vault?.friends) return null;
  if (/^[a-f0-9]{64}$/.test(username)) return findFriendByHashSync(username);
  return findFriendByPlaintextSync(username);
}

async function buildVaultHashCache() {
  if (!vault?.friends) return;
  for (const [k] of Object.entries(vault.friends)) {
    const friendUser = k.split("@")[0];
    if (/^[a-f0-9]{64}$/.test(friendUser)) continue;
    const friendHash = await hashUsername(friendUser);
    vaultHashCache.set(friendHash, k);
  }
}

// ============================================================================
// ECDH feed key exchange
// ============================================================================
async function encryptFeedKeyForFriend(myFeedKeyB64, myEncPrivateKey, friendEncPubKeyB64, displayName, photoHash, fullPhotoHash, username) {
  const friendPub = await crypto.subtle.importKey("raw", fromB64(friendEncPubKeyB64), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await crypto.subtle.deriveKey({ name: "ECDH", public: friendPub }, myEncPrivateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = JSON.stringify({ feedKey: myFeedKeyB64, displayName: displayName || null, photoHash: photoHash || null, fullPhotoHash: fullPhotoHash || null, username: username || null });
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, shared, enc.encode(payload));
  return JSON.stringify({ ct: toB64(new Uint8Array(ct)), iv: toB64(iv) });
}

async function decryptFeedKeyFromFriend(encryptedPayload, myEncPrivateKey, friendEncPubKeyB64) {
  try {
    const { ct, iv } = JSON.parse(encryptedPayload);
    const friendPub = await crypto.subtle.importKey("raw", fromB64(friendEncPubKeyB64), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = await crypto.subtle.deriveKey({ name: "ECDH", public: friendPub }, myEncPrivateKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, shared, fromB64(ct));
    const decoded = dec.decode(plain);
    try {
      const parsed = JSON.parse(decoded);
      if (parsed.feedKey) return { feedKeyB64: parsed.feedKey, displayName: parsed.displayName || null, photoHash: parsed.photoHash || null, fullPhotoHash: parsed.fullPhotoHash || null, username: parsed.username || null };
    } catch {}
    return { feedKeyB64: toB64(new Uint8Array(plain)), displayName: null, photoHash: null, fullPhotoHash: null, username: null };
  } catch (err) { console.error("[key-exchange] Decrypt failed:", err); return null; }
}

async function importFeedKeyFromB64(b64) {
  return crypto.subtle.importKey("raw", fromB64(b64), { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

// ============================================================================
// Password validation
// ============================================================================
const COMMON_PASSWORDS = new Set(["password123456789", "qwertyuiopasdfg", "passwordpassword", "1234567890123456", "aaaaaaaaaaaaaaaa", "abcdefghijklmnop", "1111111111111111"]);

function validatePassword(pw) {
  const issues = [];
  if (pw.length < 15) issues.push({ type: "error", text: `${15 - pw.length} more characters needed (minimum 15)` });
  if (pw.length > 64) issues.push({ type: "error", text: "Maximum 64 characters" });
  if (COMMON_PASSWORDS.has(pw.toLowerCase().replace(/\s+/g, ""))) issues.push({ type: "error", text: "Commonly compromised password" });
  if (/^(.)\1+$/.test(pw)) issues.push({ type: "error", text: "Cannot be a single repeated character" });
  const seq = "abcdefghijklmnopqrstuvwxyz0123456789"; const lp = pw.toLowerCase();
  for (let i = 0; i <= seq.length - 15; i++) { if (lp.includes(seq.slice(i, i + 15))) { issues.push({ type: "error", text: "Cannot be a sequential pattern" }); break; } }
  let cs = 0;
  if (/[a-z]/.test(pw)) cs += 26; if (/[A-Z]/.test(pw)) cs += 26; if (/[0-9]/.test(pw)) cs += 10; if (/[^a-zA-Z0-9]/.test(pw)) cs += 32;
  const entropy = pw.length * Math.log2(cs || 1);
  let strength = "weak";
  if (!issues.some(i => i.type === "error")) { strength = entropy >= 80 ? "very strong" : entropy >= 60 ? "strong" : entropy >= 45 ? "good" : "acceptable"; }
  return { valid: !issues.some(i => i.type === "error"), issues, strength, entropy };
}

function PasswordStrengthMeter({ password }) {
  if (!password) return null;
  const { issues, strength } = validatePassword(password);
  const colors = { weak: T.danger, acceptable: T.warn, good: "#8aff4a", strong: T.success, "very strong": T.accent };
  const widths = { weak: "15%", acceptable: "35%", good: "55%", strong: "75%", "very strong": "100%" };
  const color = colors[strength] || T.danger;
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ background: T.bgHover, borderRadius: 3, height: 4, overflow: "hidden", marginBottom: 6 }}>
        <div style={{ background: color, height: "100%", width: widths[strength], borderRadius: 3, transition: "all 0.3s" }} />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <span style={{ fontSize: 12, color, fontWeight: 600, textTransform: "capitalize" }}>{strength}</span>
        <span style={{ fontSize: 11, color: T.textDim }}>{password.length}/64</span>
      </div>
      {issues.map((is, i) => <div key={i} style={{ fontSize: 12, color: T.danger, marginTop: 4 }}>✕ {is.text}</div>)}
    </div>
  );
}

// ============================================================================
// Avatar photo cache
// ============================================================================
const avatarCache = new Map();
const avatarLoading = new Map();

async function reEncryptContent(hash, oldFeedKey, newFeedKey) {
  const res = await fetch(`/content/${hash}`);
  if (!res.ok) return null;
  const encrypted = new Uint8Array(await res.arrayBuffer());
  const iv = encrypted.slice(0, 12); const ct = encrypted.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, oldFeedKey, ct);
  const newIv = crypto.getRandomValues(new Uint8Array(12));
  const newCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: newIv }, newFeedKey, plain));
  const combined = new Uint8Array(newIv.length + newCt.length);
  combined.set(newIv); combined.set(newCt, 12);
  const form = new FormData();
  form.append("file", new Blob([combined], { type: "application/octet-stream" }), "re-encrypted.enc");
  const uploadRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: form });
  if (!uploadRes.ok) return null;
  const data = await uploadRes.json();
  return data.hash;
}

async function loadAvatar(username, domain) {
  const addr = `${username}@${domain}`;
  if (avatarCache.has(addr)) return avatarCache.get(addr);
  if (avatarLoading.has(addr)) return avatarLoading.get(addr);
  const promise = (async () => {
    let photoHash = null; let feedKey = null;
    if ((username === window._currentUser || username === identity?.usernameHash) && vault?.photoHash && identity) {
      photoHash = vault.photoHash; feedKey = identity.feedKey;
    } else {
      let friendInfo = vault?.friends?.[addr];
      if (!friendInfo?.photoHash) {
        const merged = await findFriend(username);
        if (merged) friendInfo = friendInfo ? { ...merged, ...friendInfo, photoHash: friendInfo.photoHash || merged.photoHash, fullPhotoHash: friendInfo.fullPhotoHash || merged.fullPhotoHash, feedKeyB64: friendInfo.feedKeyB64 || merged.feedKeyB64 } : merged;
      }
      if (friendInfo?.photoHash && friendInfo?.feedKeyB64) {
        photoHash = friendInfo.photoHash;
        try { feedKey = await importFeedKeyFromB64(friendInfo.feedKeyB64); } catch { return null; }
      }
    }
    if (!photoHash || !feedKey) return null;
    try {
      const res = await fetch(`/content/${photoHash}`);
      if (!res.ok) return null;
      const encrypted = new Uint8Array(await res.arrayBuffer());
      const iv = encrypted.slice(0, 12); const ct = encrypted.slice(12);
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, feedKey, ct);
      const blob = new Blob([plain], { type: "image/jpeg" });
      const url = URL.createObjectURL(blob);
      avatarCache.set(addr, url);
      return url;
    } catch (err) { console.warn("[avatar] Load failed:", err); return null; }
  })();
  avatarLoading.set(addr, promise);
  try { return await promise; } finally { avatarLoading.delete(addr); }
}

async function uploadAvatar(thumbBlob, originalFile, feedKey) {
  const thumbRaw = new Uint8Array(await thumbBlob.arrayBuffer());
  const thumbIv = crypto.getRandomValues(new Uint8Array(12));
  const thumbCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: thumbIv }, feedKey, thumbRaw));
  const thumbCombined = new Uint8Array(thumbIv.length + thumbCt.length);
  thumbCombined.set(thumbIv); thumbCombined.set(thumbCt, 12);
  const fullRaw = new Uint8Array(await originalFile.arrayBuffer());
  const fullIv = crypto.getRandomValues(new Uint8Array(12));
  const fullCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: fullIv }, feedKey, fullRaw));
  const fullCombined = new Uint8Array(fullIv.length + fullCt.length);
  fullCombined.set(fullIv); fullCombined.set(fullCt, 12);
  const thumbForm = new FormData();
  thumbForm.append("file", new Blob([thumbCombined], { type: "application/octet-stream" }), "avatar-thumb.enc");
  const thumbRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: thumbForm });
  if (!thumbRes.ok) throw new Error("Thumbnail upload failed");
  const thumbData = await thumbRes.json();
  const fullForm = new FormData();
  fullForm.append("file", new Blob([fullCombined], { type: "application/octet-stream" }), "avatar-full.enc");
  const fullRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: fullForm });
  if (!fullRes.ok) throw new Error("Full photo upload failed");
  const fullData = await fullRes.json();
  return { thumbHash: thumbData.hash, fullHash: fullData.hash };
}

async function loadFullPhoto(hash, feedKey) {
  try {
    const res = await fetch(`/content/${hash}`);
    if (!res.ok) return null;
    const encrypted = new Uint8Array(await res.arrayBuffer());
    const iv = encrypted.slice(0, 12); const ct = encrypted.slice(12);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, feedKey, ct);
    return URL.createObjectURL(new Blob([plain]));
  } catch { return null; }
}

// ============================================================================
// Photo lightbox
// ============================================================================
function PhotoLightbox({ url, onClose }) {
  if (!url) return null;
  return (
    <div onClick={onClose} style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, zIndex: 9999, background: "rgba(0,0,0,0.9)", display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer" }}>
      <img src={url} alt="Full size" style={{ maxWidth: "90vw", maxHeight: "90vh", borderRadius: 8, objectFit: "contain" }} />
      <div style={{ position: "absolute", top: 20, right: 20, color: "#fff", fontSize: 24, cursor: "pointer" }}>✕</div>
    </div>
  );
}

// ============================================================================
// Photo crop modal
// ============================================================================
function PhotoCropModal({ file, onCrop, onCancel }) {
  const [imgUrl, setImgUrl] = useState(null);
  const [imgSize, setImgSize] = useState({ w: 0, h: 0 });
  const [crop, setCrop] = useState({ x: 0, y: 0, size: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ mx: 0, my: 0, cx: 0, cy: 0 });
  const containerRef = useRef(null);
  const displayMax = 300;
  useEffect(() => {
    const url = URL.createObjectURL(file); setImgUrl(url);
    const img = new Image();
    img.onload = () => { setImgSize({ w: img.width, h: img.height }); const s = Math.min(img.width, img.height); setCrop({ x: (img.width - s) / 2, y: (img.height - s) / 2, size: s }); };
    img.src = url; return () => URL.revokeObjectURL(url);
  }, [file]);
  if (!imgUrl || !imgSize.w) return null;
  const scale = displayMax / Math.max(imgSize.w, imgSize.h);
  const dw = imgSize.w * scale, dh = imgSize.h * scale;
  const handleMouseDown = (e) => { e.preventDefault(); setDragging(true); setDragStart({ mx: e.clientX, my: e.clientY, cx: crop.x, cy: crop.y }); };
  const handleMouseMove = (e) => { if (!dragging) return; const dx = (e.clientX - dragStart.mx) / scale; const dy = (e.clientY - dragStart.my) / scale; setCrop(c => ({ ...c, x: Math.max(0, Math.min(imgSize.w - c.size, dragStart.cx + dx)), y: Math.max(0, Math.min(imgSize.h - c.size, dragStart.cy + dy)) })); };
  const handleMouseUp = () => setDragging(false);
  const handleSizeChange = (e) => {
    const pct = parseInt(e.target.value); const maxSize = Math.min(imgSize.w, imgSize.h); const minSize = Math.max(50, maxSize * 0.1);
    const newSize = minSize + (maxSize - minSize) * (pct / 100);
    const cx = crop.x + crop.size / 2, cy = crop.y + crop.size / 2;
    setCrop({ x: Math.max(0, Math.min(imgSize.w - newSize, cx - newSize / 2)), y: Math.max(0, Math.min(imgSize.h - newSize, cy - newSize / 2)), size: newSize });
  };
  const sizePercent = (() => { const maxSize = Math.min(imgSize.w, imgSize.h); const minSize = Math.max(50, maxSize * 0.1); return Math.round(((crop.size - minSize) / (maxSize - minSize)) * 100); })();
  const doCrop = async () => {
    const img = await createImageBitmap(file);
    const thumbCanvas = new OffscreenCanvas(200, 200); const tCtx = thumbCanvas.getContext("2d");
    tCtx.drawImage(img, crop.x, crop.y, crop.size, crop.size, 0, 0, 200, 200);
    const thumbBlob = await thumbCanvas.convertToBlob({ type: "image/jpeg", quality: 0.85 });
    onCrop(thumbBlob, file);
  };
  return (
    <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, zIndex: 9999, background: "rgba(0,0,0,0.85)", display: "flex", alignItems: "center", justifyContent: "center" }} onMouseMove={handleMouseMove} onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}>
      <div style={{ background: T.bgCard, borderRadius: 16, padding: 24, maxWidth: 400, width: "90%" }} onClick={e => e.stopPropagation()}>
        <h3 style={{ margin: "0 0 16px", color: T.text, fontSize: 16 }}>Crop profile photo</h3>
        <div ref={containerRef} style={{ position: "relative", width: dw, height: dh, margin: "0 auto", overflow: "hidden", borderRadius: 8, userSelect: "none" }}>
          <img src={imgUrl} alt="crop" style={{ width: dw, height: dh, display: "block" }} draggable={false} />
          <div style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.5)", pointerEvents: "none" }} />
          <div onMouseDown={handleMouseDown} style={{ position: "absolute", left: crop.x * scale, top: crop.y * scale, width: crop.size * scale, height: crop.size * scale, borderRadius: "50%", border: "2px solid #fff", cursor: "move", boxShadow: "0 0 0 9999px rgba(0,0,0,0.5)", background: "transparent" }} />
        </div>
        <div style={{ marginTop: 16, display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ color: T.textDim, fontSize: 12 }}>Zoom</span>
          <input type="range" min="0" max="100" value={sizePercent} onChange={handleSizeChange} style={{ flex: 1, accentColor: T.accent }} />
        </div>
        <div style={{ display: "flex", gap: 8, marginTop: 16, justifyContent: "flex-end" }}>
          <Btn variant="ghost" small onClick={onCancel}>Cancel</Btn>
          <Btn small onClick={doCrop}>Save</Btn>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Trusted device storage (IndexedDB)
// ============================================================================
const deviceStore = {
  _db: null,
  async open() {
    if (this._db) return this._db;
    return new Promise((res, rej) => { const r = indexedDB.open("ls-device-trust", 1); r.onupgradeneeded = () => r.result.createObjectStore("session", { keyPath: "id" }); r.onsuccess = () => { this._db = r.result; res(this._db); }; r.onerror = () => rej(r.error); });
  },
  async save(data) { const db = await this.open(); return new Promise((res, rej) => { const tx = db.transaction("session", "readwrite"); tx.objectStore("session").put({ id: "current", ...data, savedAt: Date.now() }); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); }); },
  async get() { const db = await this.open(); return new Promise((res, rej) => { const tx = db.transaction("session", "readonly"); const r = tx.objectStore("session").get("current"); r.onsuccess = () => res(r.result || null); r.onerror = () => rej(r.error); }); },
  async clear() { const db = await this.open(); return new Promise((res, rej) => { const tx = db.transaction("session", "readwrite"); tx.objectStore("session").clear(); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); }); },
};

async function saveTrustedSession(username, keys) {
  try {
    const sigPrivJwk = await crypto.subtle.exportKey("jwk", keys.signing.privateKey);
    const sigPubJwk = await crypto.subtle.exportKey("jwk", keys.signing.publicKey);
    const encPrivJwk = await crypto.subtle.exportKey("jwk", keys.encryption.privateKey);
    const encPubJwk = await crypto.subtle.exportKey("jwk", keys.encryption.publicKey);
    const feedKeyRaw = toB64(new Uint8Array(await crypto.subtle.exportKey("raw", keys.feedKey)));
    const vaultKeyRaw = toB64(new Uint8Array(await crypto.subtle.exportKey("raw", keys.vaultKey)));
    await deviceStore.save({ username, usernameHash: keys.usernameHash || null, token: api.token, fingerprint: keys.fingerprint, feedKeyVersion: keys.feedKeyVersion, signingPublicKeyB64: keys.signingPublicKeyB64, encryptionPublicKeyB64: keys.encryptionPublicKeyB64, feedKeyB64: keys.feedKeyB64, sigPrivJwk, sigPubJwk, encPrivJwk, encPubJwk, feedKeyRaw, vaultKeyRaw });
  } catch (err) { console.warn("[trust] Save failed:", err); }
}

async function restoreTrustedSession() {
  try {
    const s = await deviceStore.get(); if (!s) return null;
    const sigPriv = await crypto.subtle.importKey("jwk", s.sigPrivJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const sigPub = await crypto.subtle.importKey("jwk", s.sigPubJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const encPriv = await crypto.subtle.importKey("jwk", s.encPrivJwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    const encPub = await crypto.subtle.importKey("jwk", s.encPubJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
    const feedKey = await crypto.subtle.importKey("raw", fromB64(s.feedKeyRaw), { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const vaultKey = await crypto.subtle.importKey("raw", fromB64(s.vaultKeyRaw), { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    return { username: s.username, token: s.token, keys: { signing: { privateKey: sigPriv, publicKey: sigPub }, encryption: { privateKey: encPriv, publicKey: encPub }, feedKey, vaultKey, feedKeyVersion: s.feedKeyVersion, feedKeyB64: s.feedKeyB64, fingerprint: s.fingerprint, signingPublicKeyB64: s.signingPublicKeyB64, encryptionPublicKeyB64: s.encryptionPublicKeyB64, usernameHash: s.usernameHash || null } };
  } catch (err) { console.warn("[trust] Restore failed:", err); await deviceStore.clear(); return null; }
}

async function reAuthWithCachedKeys(username, signingPrivateKey) {
  const { nonce } = await api.request("/api/auth/challenge", { method: "POST", body: JSON.stringify({ username }) });
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingPrivateKey, enc.encode(nonce));
  const res = await api.request("/api/auth/verify", { method: "POST", body: JSON.stringify({ username, signature: toB64(new Uint8Array(sig)) }) });
  return res.token;
}

// ============================================================================
// State
// ============================================================================
let identity = null;
let vault = null;

// ============================================================================
// API
// ============================================================================
const api = {
  token: null,
  async request(path, opts = {}) {
    const h = { "Content-Type": "application/json", ...opts.headers };
    if (this.token) h["Authorization"] = `Bearer ${this.token}`;
    const r = await fetch(path, { ...opts, headers: h });
    if (!r.ok) { const e = await r.json().catch(() => ({ error: r.statusText })); throw new Error(e.error || r.statusText); }
    return r.json();
  },
};

async function loadVault() {
  try {
    const { vault: vaultStr } = await api.request("/api/vault");
    if (vaultStr && identity) vault = await decryptVault(vaultStr, identity.vaultKey);
  } catch {}
  if (!vault) vault = { friends: {}, feedKeyVersion: identity?.feedKeyVersion || 1 };
}

async function saveVault() {
  if (!identity || !vault) return;
  const vaultStr = await encryptVault(vault, identity.vaultKey);
  await api.request("/api/vault", { method: "PUT", body: JSON.stringify({ vault: vaultStr }) });
}

async function processKeyExchanges() {
  if (!identity) return false;
  await buildVaultHashCache();
  let updated = false;
  try {
    const { exchanges } = await api.request("/api/key-exchange");
    for (const ex of exchanges) {
      try {
        const profile = await api.request(`/api/profile/${ex.fromUser}`);
        if (!profile.encryptionPublicKey) continue;
        const addr = `${ex.fromUser}@${ex.fromDomain}`;
        const existing = vault.friends[addr];
        let result = await decryptFeedKeyFromFriend(ex.encryptedPayload, identity.encryption.privateKey, profile.encryptionPublicKey);
        if (!result) {
          try {
            const keysRes = await api.request(`/api/profile/${ex.fromUser}/keys`);
            for (const prev of (keysRes.previous || [])) {
              result = await decryptFeedKeyFromFriend(ex.encryptedPayload, identity.encryption.privateKey, prev.encryptionPublicKey);
              if (result) break;
            }
          } catch {}
        }
        if (result) {
          if (!vault.friends[addr]) vault.friends[addr] = {};
          if (existing?.feedKeyB64 && existing.feedKeyB64 !== result.feedKeyB64) {
            // Store ALL previous keys, not just one
            if (!vault.friends[addr].previousFeedKeys) vault.friends[addr].previousFeedKeys = [];
            if (!vault.friends[addr].previousFeedKeys.includes(existing.feedKeyB64)) {
              vault.friends[addr].previousFeedKeys.push(existing.feedKeyB64);
            }
            vault.friends[addr].previousFeedKeyB64 = existing.feedKeyB64;
            vault.friends[addr].keyChangedAt = Date.now();
          }
          vault.friends[addr].feedKeyB64 = result.feedKeyB64;
          vault.friends[addr].encPubKey = profile.encryptionPublicKey;
          vault.friends[addr].expired = false;
          if (result.displayName) vault.friends[addr].displayName = result.displayName;
          if (result.photoHash) vault.friends[addr].photoHash = result.photoHash;
          if (result.fullPhotoHash) vault.friends[addr].fullPhotoHash = result.fullPhotoHash;
          if (result.username) vault.friends[addr].plaintextUsername = result.username;
          // Also update any plaintext-keyed entry for the same friend
          const fromHash = addr.split("@")[0];
          if (/^[a-f0-9]{64}$/.test(fromHash) && vaultHashCache.has(fromHash)) {
            const ptAddr = vaultHashCache.get(fromHash);
            if (ptAddr !== addr && vault.friends[ptAddr]) {
              vault.friends[ptAddr].feedKeyB64 = result.feedKeyB64;
              vault.friends[ptAddr].encPubKey = profile.encryptionPublicKey;
              if (result.displayName) vault.friends[ptAddr].displayName = result.displayName;
              if (result.photoHash) vault.friends[ptAddr].photoHash = result.photoHash;
              if (result.fullPhotoHash) vault.friends[ptAddr].fullPhotoHash = result.fullPhotoHash;
            }
          }
          await saveVault();
          updated = true;
          // Only delete exchange after successful processing
          await api.request(`/api/key-exchange/${ex.id}`, { method: "DELETE" });
        }
      } catch (err) { console.warn("[key-exchange] Processing failed:", err); }
    }
  } catch {}
  if (vault?.friends) {
    const ONE_MONTH = 30 * 24 * 60 * 60 * 1000;
    let changed = false;
    for (const [addr, info] of Object.entries(vault.friends)) {
      if (info.keyChangedAt && Date.now() - info.keyChangedAt > ONE_MONTH) {
        info.previousFeedKeyB64 = null; info.keyChangedAt = null; changed = true;
      }
    }
    if (changed) await saveVault();
  }
  return updated;
}

async function retryPendingKeyRotations() {
  if (!identity || !vault || !vault.pendingKeyRotations?.length) return;
  const remaining = [];
  const sentToHashes = new Set();
  for (const entry of vault.pendingKeyRotations) {
    const addr = entry.addr;
    // Drop entries older than 30 days
    if (Date.now() - entry.createdAt > 30 * 24 * 60 * 60 * 1000) continue;
    const friendInfo = vault.friends[addr];
    if (!friendInfo) continue;
    const friendUser = addr.split("@")[0];
    const friendHash = /^[a-f0-9]{64}$/.test(friendUser) ? friendUser : await hashUsername(friendUser);
    if (sentToHashes.has(friendHash)) continue;
    let encPubKey = friendInfo.encPubKey;
    if (!encPubKey) {
      try {
        const profile = await api.request(`/api/profile/${friendHash}`);
        if (profile.encryptionPublicKey) {
          encPubKey = profile.encryptionPublicKey;
          vault.friends[addr].encPubKey = encPubKey;
        }
      } catch {}
    }
    if (!encPubKey) { remaining.push(entry); continue; }
    try {
      const keyPayload = await encryptFeedKeyForFriend(identity.feedKeyB64, identity.encryption.privateKey, encPubKey, vault.displayName || null, vault.photoHash || null, vault.fullPhotoHash || null, window._currentUser);
      await api.request("/api/key-exchange", { method: "POST", body: JSON.stringify({ toUsername: friendHash, encryptedPayload: keyPayload }) });
      sentToHashes.add(friendHash);
    } catch { remaining.push(entry); }
  }
  if (remaining.length > 0) {
    vault.pendingKeyRotations = remaining;
  } else {
    delete vault.pendingKeyRotations;
  }
  await saveVault();
}

async function processFriendAccepted() {
  if (!identity || !vault) return;
  try {
    const { notifications } = await api.request("/api/notifications");
    const accepted = notifications.filter(n => n.type === "friend_accepted");
    for (const notif of accepted) {
      try {
        const [fromUsername, fromDomain] = (notif.from || "").split("@");
        if (!fromUsername || !fromDomain) continue;
        const fromEncPubKey = notif.fromKeys?.encryption;
        if (!fromEncPubKey) continue;
        const myDisplayName = vault.displayName || null;
        const myPhotoHash = vault.photoHash || null;
        const myFullPhotoHash = vault.fullPhotoHash || null;
        const keyPayload = await encryptFeedKeyForFriend(identity.feedKeyB64, identity.encryption.privateKey, fromEncPubKey, myDisplayName, myPhotoHash, myFullPhotoHash, window._currentUser);
        await api.request("/api/key-exchange", { method: "POST", body: JSON.stringify({ toUsername: fromUsername, encryptedPayload: keyPayload }) });
        const addr = `${fromUsername}@${fromDomain}`;
        if (!vault.friends[addr]) vault.friends[addr] = {};
        vault.friends[addr].encPubKey = fromEncPubKey;
        await saveVault();
        await api.request(`/api/notifications/${notif.id}`, { method: "DELETE" });
      } catch (err) { console.warn("[friend-accepted] Processing failed:", err); }
    }
  } catch {}
}

// ============================================================================
// Context
// ============================================================================
const AppCtx = createContext(null);
function useApp() { return useContext(AppCtx); }

// ============================================================================
// User Profile Page
// ============================================================================
function UserProfileView({ username, domain, onBack }) {
  const { currentUser } = useApp();
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);

  const displayName = (() => {
    if (username === currentUser || username === identity?.usernameHash) return vault?.displayName || currentUser;
    const addr = `${username}@${domain}`;
    const direct = vault?.friends?.[addr];
    const bySync = findFriendSync(username);
    const friendInfo = (direct && bySync) ? { ...bySync, ...direct } : (direct || bySync);
    if (friendInfo?.displayName) return friendInfo.displayName;
    if (friendInfo?.plaintextUsername) return friendInfo.plaintextUsername;
    return /^[a-f0-9]{64}$/.test(username) ? truncateHash(username) : username;
  })();

  useEffect(() => {
    (async () => {
      if (!vault || !identity) return;
      const usernames = [username];
      if (identity?.usernameHash && username === currentUser) usernames.push(identity.usernameHash);
      const bloom = createBloomFilter(usernames, cachedUserCount);
      try {
        const data = await api.request("/api/feed", {
          method: "POST",
          body: JSON.stringify({ bloom, bloomHashCount: BLOOM_HASH_COUNT, limit: 100 }),
        });
        // Filter to only this user's posts (bloom filter may include false positives)
        const filtered = (data.posts || []).filter(p => p.author === username || (identity?.usernameHash && p.author === identity.usernameHash));
        setPosts(filtered);
      } catch (err) { console.error("[profile-feed]", err); }
      setLoading(false);
    })();
  }, [username]);

  const handleDelete = (postId) => { setPosts(prev => prev.filter(p => p.id !== postId)); };

  return (
    <div>
      <button onClick={onBack} style={{ background: "none", border: "none", color: T.accent, cursor: "pointer", fontSize: 14, padding: "0 0 16px", display: "flex", alignItems: "center", gap: 6 }}>
        ← Back to feed
      </button>
      <div style={{ background: T.bgCard, borderRadius: 12, padding: 24, border: `1px solid ${T.border}`, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
          <Avatar username={username} size={64} domain={domain} clickable />
          <div>
            <h2 style={{ margin: 0, color: T.text, fontSize: 20 }}>{displayName}</h2>
            <div style={{ color: T.textMuted, fontSize: 14, marginTop: 2 }}>@{/^[a-f0-9]{64}$/.test(username) ? truncateHash(username) : username}@{domain}</div>
          </div>
        </div>
      </div>
      <h3 style={{ color: T.text, fontSize: 16, marginBottom: 12 }}>Posts</h3>
      {loading && <div style={{ textAlign: "center", padding: 20, color: T.textDim }}>Loading posts...</div>}
      {!loading && posts.length === 0 && <div style={{ textAlign: "center", padding: 40, color: T.textDim, fontSize: 14 }}>No posts to show.</div>}
      {posts.map(p => <Post key={p.id} post={p} onDelete={handleDelete} />)}
    </div>
  );
}

// ============================================================================
// Components
// ============================================================================
function Avatar({ username, size = 36, domain = "lsocial.org", clickable = false }) {
  const name = typeof username === "object" ? (username?.username || "?") : (username || "?");
  const colors = ["#4a9eff", "#ff6b4a", "#4aff8b", "#ff4ae0", "#ffb84a", "#4affec"];
  const idx = name.split("").reduce((a, c) => a + c.charCodeAt(0), 0) % colors.length;
  const [photoUrl, setPhotoUrl] = useState(null);
  const [lightboxUrl, setLightboxUrl] = useState(null);
  useEffect(() => { loadAvatar(name, domain).then(url => { if (url) setPhotoUrl(url); }); }, [name, domain]);
  const handleClick = async () => {
    if (!clickable) return;
    const addr = `${name}@${domain}`;
    let fullHash = null, feedKey = null;
    if ((name === window._currentUser || name === identity?.usernameHash) && vault?.fullPhotoHash && identity) { fullHash = vault.fullPhotoHash; feedKey = identity.feedKey; }
    else {
      let fi = vault?.friends?.[addr];
      if (!fi?.fullPhotoHash) {
        const merged = await findFriend(name);
        if (merged) fi = fi ? { ...merged, ...fi, fullPhotoHash: fi.fullPhotoHash || merged.fullPhotoHash, feedKeyB64: fi.feedKeyB64 || merged.feedKeyB64 } : merged;
      }
      if (fi?.fullPhotoHash && fi?.feedKeyB64) { fullHash = fi.fullPhotoHash; try { feedKey = await importFeedKeyFromB64(fi.feedKeyB64); } catch { return; } }
    }
    if (!fullHash || !feedKey) return;
    const url = await loadFullPhoto(fullHash, feedKey);
    if (url) setLightboxUrl(url);
  };
  const style = clickable && photoUrl ? { cursor: "pointer" } : {};
  const el = photoUrl
    ? <img src={photoUrl} alt={name} onClick={handleClick} style={{ width: size, height: size, borderRadius: "50%", objectFit: "cover", flexShrink: 0, ...style }} />
    : <div onClick={handleClick} style={{ width: size, height: size, borderRadius: "50%", background: `linear-gradient(135deg, ${colors[idx]}, ${colors[(idx+2)%colors.length]})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: size*0.42, fontWeight: 700, color: "#fff", flexShrink: 0, ...style }}>{name[0].toUpperCase()}</div>;
  return <>{el}{lightboxUrl && <PhotoLightbox url={lightboxUrl} onClose={() => { URL.revokeObjectURL(lightboxUrl); setLightboxUrl(null); }} />}</>;
}

function TimeAgo({ ts }) {
  const d = Date.now() - ts, m = Math.floor(d/60000), h = Math.floor(d/3600000), dy = Math.floor(d/86400000);
  return <span style={{ color: T.textMuted, fontSize: 13 }}>{dy > 0 ? `${dy}d ago` : h > 0 ? `${h}h ago` : m > 0 ? `${m}m ago` : "just now"}</span>;
}

function Btn({ children, variant = "primary", onClick, disabled, small, style = {} }) {
  const base = { border: "none", borderRadius: 8, cursor: disabled ? "not-allowed" : "pointer", fontWeight: 600, fontSize: small ? 13 : 14, padding: small ? "6px 12px" : "10px 20px", opacity: disabled ? 0.5 : 1, transition: "all 0.15s" };
  const v = { primary: { background: T.accent, color: "#fff" }, ghost: { background: "transparent", color: T.accent, border: `1px solid ${T.border}` }, danger: { background: "transparent", color: T.danger, border: `1px solid ${T.border}` } };
  return <button style={{ ...base, ...v[variant], ...style }} onClick={onClick} disabled={disabled}>{children}</button>;
}

// ============================================================================
// Post
// ============================================================================
function Post({ post, onDelete, isMobile }) {
  const { currentUser, navigateToProfile, vaultVersion } = useApp();
  const [content, setContent] = useState(null);
  const [failed, setFailed] = useState(false);
  const [authorFeedKey, setAuthorFeedKey] = useState(null);
  const [showComments, setShowComments] = useState(false);
  const [comments, setComments] = useState([]);
  const [loadingComments, setLoadingComments] = useState(false);
  const [commentText, setCommentText] = useState("");
  const [posting, setPosting] = useState(false);
  const [editingComment, setEditingComment] = useState(null); // { id, text }
  const [decryptedPhotos, setDecryptedPhotos] = useState([]);
  const [decryptedVideos, setDecryptedVideos] = useState([]); // { url, type }
  const [videosLoading, setVideosLoading] = useState(false);
  const [lightboxPhoto, setLightboxPhoto] = useState(null);
  const [expanded, setExpanded] = useState(false);
  const [overflows, setOverflows] = useState(false);
  const [editingPost, setEditingPost] = useState(false);
  const [editText, setEditText] = useState("");
  const [friendReqSent, setFriendReqSent] = useState(new Set());
  const contentRef = useRef(null);
  const commentCount = post.commentCount || 0;
  const [localCommentCount, setLocalCommentCount] = useState(commentCount);

  useEffect(() => {
    if (contentRef.current) { setOverflows(contentRef.current.scrollHeight > window.innerHeight * 0.5); }
  }, [content, decryptedPhotos, decryptedVideos]);

  useEffect(() => {
    if (!post.envelope) { setFailed(true); return; }
    if (content && !failed) return; // Already decrypted successfully
    setFailed(false);
    (async () => {
      try {
        const env = typeof post.envelope === "string" ? JSON.parse(post.envelope) : post.envelope;
        let decrypted = null, fk = null;
        const isOwnPost = post.author === currentUser || post.author === identity?.usernameHash;
        if (isOwnPost && identity) {
          decrypted = await decryptWithFeedKey(env.ct, env.iv, identity.feedKey);
          if (decrypted) fk = identity.feedKey;
          // Try previous own feed keys
          if (!decrypted && vault?.previousFeedKeys) {
            for (const prev of vault.previousFeedKeys) {
              try {
                const prevKey = await importFeedKeyFromB64(prev.feedKeyB64);
                decrypted = await decryptWithFeedKey(env.ct, env.iv, prevKey);
                if (decrypted) { fk = prevKey; break; }
              } catch {}
            }
          }
        }
        if (!decrypted && vault) {
          const addr = `${post.author}@${post.domain}`;
          let friendInfo = vault.friends[addr];
          if (!friendInfo) friendInfo = await findFriend(post.author);
          if (friendInfo?.feedKeyB64) {
            const importedKey = await importFeedKeyFromB64(friendInfo.feedKeyB64);
            decrypted = await decryptWithFeedKey(env.ct, env.iv, importedKey);
            if (decrypted) fk = importedKey;
          }
          if (!decrypted && friendInfo?.previousFeedKeyB64) {
            try {
              const prevKey = await importFeedKeyFromB64(friendInfo.previousFeedKeyB64);
              decrypted = await decryptWithFeedKey(env.ct, env.iv, prevKey);
              if (decrypted) fk = prevKey;
            } catch {}
          }
          // Try all stored previous keys for this friend
          if (!decrypted && friendInfo?.previousFeedKeys) {
            for (const prevB64 of friendInfo.previousFeedKeys) {
              try {
                const prevKey = await importFeedKeyFromB64(prevB64);
                decrypted = await decryptWithFeedKey(env.ct, env.iv, prevKey);
                if (decrypted) { fk = prevKey; break; }
              } catch {}
            }
          }
        }
        if (decrypted) {
          setAuthorFeedKey(fk);
          try {
            const parsed = JSON.parse(decrypted);
            if (parsed._linked && parsed.contentHash && parsed.contentKey) {
              const res = await fetch(`/content/${parsed.contentHash}`);
              if (res.ok) { const blob = new Uint8Array(await res.arrayBuffer()); const ck = await crypto.subtle.importKey("raw", fromB64(parsed.contentKey), { name: "AES-GCM", length: 256 }, false, ["decrypt"]); const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(parsed.contentIv) }, ck, blob); setContent({ text: dec.decode(plain) }); }
              else { setContent({ text: parsed.preview || "[Content unavailable]" }); }
              return;
            }
            if (parsed.text !== undefined || parsed.photos || parsed.videos) {
              setContent({ text: parsed.text || null, photos: parsed.photos || [], videos: parsed.videos || [] });
              if (parsed.photos?.length) {
                const urls = [];
                for (const photo of parsed.photos) {
                  try { const res = await fetch(`/content/${photo.hash}`); if (!res.ok) { urls.push(null); continue; } const encrypted = new Uint8Array(await res.arrayBuffer()); const iv = encrypted.slice(0, 12); const ct = encrypted.slice(12); const photoKey = await crypto.subtle.importKey("raw", fromB64(photo.key), { name: "AES-GCM", length: 256 }, false, ["decrypt"]); const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, photoKey, ct); urls.push(URL.createObjectURL(new Blob([plain], { type: photo.type || "image/jpeg" }))); }
                  catch { urls.push(null); }
                }
                setDecryptedPhotos(urls);
              }
              if (parsed.videos?.length) {
                setVideosLoading(true);
                const vids = [];
                for (const video of parsed.videos) {
                  try { const res = await fetch(`/content/${video.hash}`); if (!res.ok) { vids.push(null); continue; } const encrypted = new Uint8Array(await res.arrayBuffer()); const iv = encrypted.slice(0, 12); const ct = encrypted.slice(12); const videoKey = await crypto.subtle.importKey("raw", fromB64(video.key), { name: "AES-GCM", length: 256 }, false, ["decrypt"]); const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, videoKey, ct); vids.push({ url: URL.createObjectURL(new Blob([plain], { type: video.type || "video/mp4" })), type: video.type || "video/mp4" }); }
                  catch { vids.push(null); }
                }
                setDecryptedVideos(vids);
                setVideosLoading(false);
              }
              return;
            }
            setContent({ text: decrypted });
          } catch { setContent({ text: decrypted }); }
        } else { setFailed(true); }
      } catch { setFailed(true); }
    })();
    return () => { decryptedPhotos.forEach(u => { if (u) URL.revokeObjectURL(u); }); decryptedVideos.forEach(v => { if (v?.url) URL.revokeObjectURL(v.url); }); };
  }, [post, vaultVersion]);

  const getDisplayName = (username, domain, authorHash) => {
    if (username === currentUser || username === identity?.usernameHash) return vault?.displayName || currentUser;
    const addr = `${username}@${domain}`;
    const direct = vault?.friends?.[addr];
    const bySync = findFriendSync(username);
    const friendInfo = (direct && bySync) ? { ...bySync, ...direct } : (direct || bySync);
    if (friendInfo?.displayName) return friendInfo.displayName;
    if (friendInfo?.plaintextUsername) return friendInfo.plaintextUsername;
    if (authorHash) return truncateHash(authorHash) + "@" + domain;
    return /^[a-f0-9]{64}$/.test(username) ? truncateHash(username) : username;
  };

  const getHandle = (username, domain) => {
    if (username === currentUser || username === identity?.usernameHash) return currentUser;
    const addr = `${username}@${domain}`;
    const direct = vault?.friends?.[addr];
    const bySync = findFriendSync(username);
    const friendInfo = (direct && bySync) ? { ...bySync, ...direct } : (direct || bySync);
    if (friendInfo?.plaintextUsername) return friendInfo.plaintextUsername;
    return /^[a-f0-9]{64}$/.test(username) ? truncateHash(username) : username;
  };

  const loadComments = async () => {
    if (!post.id || !authorFeedKey) return;
    setLoadingComments(true);
    try {
      const { comments: raw } = await api.request(`/api/posts/${post.id}/comments`);
      const decrypted = [];
      for (const c of raw) { try { const text = await decryptWithFeedKey(c.encryptedContent, c.iv, authorFeedKey); decrypted.push({ ...c, text: text || "[Decryption failed]" }); } catch { decrypted.push({ ...c, text: "[Decryption failed]" }); } }
      setComments(decrypted);
    } catch (err) { console.error("[comments]", err); }
    setLoadingComments(false);
  };

  const toggleComments = () => { if (!showComments && comments.length === 0) loadComments(); setShowComments(!showComments); };

  const submitComment = async () => {
    if (!commentText.trim() || !authorFeedKey || !post.id) return;
    setPosting(true);
    try {
      const { ciphertext, iv } = await encryptWithFeedKey(commentText.trim(), authorFeedKey);
      const res = await api.request(`/api/posts/${post.id}/comments`, { method: "POST", body: JSON.stringify({ encryptedContent: ciphertext, iv }) });
      setComments(prev => [...prev, { id: res.id, author: identity?.usernameHash || currentUser, domain: "lsocial.org", text: commentText.trim(), createdAt: Date.now() }]);
      setLocalCommentCount(prev => prev + 1);
      setCommentText("");
    } catch (err) { console.error("[comment]", err); }
    setPosting(false);
  };

  const deletePost = async () => {
    if (!confirm("Delete this post? This cannot be undone.")) return;
    try {
      await api.request(`/api/posts/${post.id}`, { method: "DELETE" });
      if (onDelete) onDelete(post.id);
    } catch (err) { console.error("[delete]", err); }
  };

  const startEditPost = () => {
    if (content?.text) setEditText(content.text);
    setEditingPost(true);
  };

  const saveEditPost = async () => {
    if (!editText.trim() || !identity) return;
    try {
      const postContent = { text: editText.trim(), photos: content?.photos, videos: content?.videos };
      const postJson = JSON.stringify(postContent);
      const { ciphertext, iv } = await encryptWithFeedKey(
        content?.photos || content?.videos ? postJson : editText.trim(),
        identity.feedKey
      );
      const envelope = { ct: ciphertext, iv };
      await api.request(`/api/posts/${post.id}`, {
        method: "PUT",
        body: JSON.stringify({ envelope }),
      });
      setContent({ ...content, text: editText.trim() });
      setEditingPost(false);
    } catch (err) { console.error("[edit-post]", err); }
  };

  const saveEditComment = async (commentId, newText) => {
    if (!newText.trim() || !authorFeedKey) return;
    try {
      const { ciphertext, iv } = await encryptWithFeedKey(newText.trim(), authorFeedKey);
      await api.request(`/api/posts/${post.id}/comments/${commentId}`, {
        method: "PUT",
        body: JSON.stringify({ encryptedContent: ciphertext, iv }),
      });
      setComments(prev => prev.map(c => c.id === commentId ? { ...c, text: newText.trim() } : c));
      setEditingComment(null);
    } catch (err) { console.error("[edit-comment]", err); }
  };

  const sendHashFriendRequest = async (authorHash, domain) => {
    if (!authorHash || !identity?.usernameHash || friendReqSent.has(authorHash)) return;
    try {
      // Encrypt plaintext username with ECDH for the recipient
      let encryptedUsername = null;
      try {
        const profile = await api.request(`/api/profile/by-hash/${authorHash}`);
        if (profile.encryptionPublicKey) {
          const recipientPub = await crypto.subtle.importKey("raw", fromB64(profile.encryptionPublicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
          const shared = await crypto.subtle.deriveKey({ name: "ECDH", public: recipientPub }, identity.encryption.privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, shared, enc.encode(window._currentUser));
          encryptedUsername = { ct: toB64(new Uint8Array(ct)), iv: toB64(iv) };
        }
      } catch {}
      const payload = JSON.stringify({
        senderHash: identity.usernameHash,
        senderDomain: "lsocial.org",
        senderEncPubKey: identity.encryptionPublicKeyB64,
        senderSignPubKey: identity.signingPublicKeyB64,
        senderFingerprint: identity.fingerprint,
        encryptedUsername,
      });
      await api.request("/api/friend-request", { method: "POST", body: JSON.stringify({ toHash: authorHash, toDomain: domain || "lsocial.org", payload }) });
      setFriendReqSent(prev => new Set([...prev, authorHash]));
    } catch (err) { console.error("[friend-request]", err); }
  };

  const isOwnOrFriend = (author, domain) => {
    if (author === currentUser || author === identity?.usernameHash) return true;
    const addr = `${author}@${domain}`;
    if (vault?.friends?.[addr]?.feedKeyB64) return true;
    const fi = findFriendSync(author);
    if (fi?.feedKeyB64) return true;
    return false;
  };

  return (
    <div style={{ background: T.bgCard, borderRadius: 12, padding: isMobile ? 14 : 20, border: `1px solid ${T.border}`, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: isMobile ? 8 : 12, marginBottom: 12 }}>
        <Avatar username={post.author} size={isMobile ? 34 : 40} domain={post.domain} clickable />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: isMobile ? 4 : 8, flexWrap: "wrap" }}>
            <span onClick={() => navigateToProfile(post.author, post.domain)} style={{ fontWeight: 600, color: T.text, cursor: "pointer", fontSize: isMobile ? 14 : undefined }}>{getDisplayName(post.author, post.domain, post.authorHash)}</span>
            <span onClick={() => navigateToProfile(post.author, post.domain)} style={{ color: T.textDim, fontSize: isMobile ? 11 : 13, cursor: "pointer", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>@{getHandle(post.author, post.domain)}@{post.domain}</span>
          </div>
          <TimeAgo ts={post.createdAt} />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {post.author !== currentUser && post.author !== identity?.usernameHash && post.authorHash && !isOwnOrFriend(post.author, post.domain) && (
            <button onClick={() => sendHashFriendRequest(post.authorHash, post.domain)}
              disabled={friendReqSent.has(post.authorHash)}
              style={{ background: friendReqSent.has(post.authorHash) ? T.bgHover : T.accentDim, border: `1px solid ${friendReqSent.has(post.authorHash) ? T.border : T.accent}`, borderRadius: 6, color: friendReqSent.has(post.authorHash) ? T.success : T.accent, cursor: friendReqSent.has(post.authorHash) ? "default" : "pointer", fontSize: 12, padding: "4px 10px", fontWeight: 600 }}
              title="Send friend request">{friendReqSent.has(post.authorHash) ? "Sent" : "+ Friend"}</button>
          )}
          {(post.author === currentUser || post.author === identity?.usernameHash) && (
            <>
              <button onClick={startEditPost} style={{ background: "none", border: "none", color: T.textDim, cursor: "pointer", fontSize: 13, padding: "2px 4px" }} title="Edit post">✏️</button>
              <button onClick={deletePost} style={{ background: "none", border: "none", color: T.textDim, cursor: "pointer", fontSize: 14, padding: "2px 4px" }} title="Delete post">🗑</button>
            </>
          )}
        </div>
      </div>
      {content ? (<>
        <div ref={contentRef} style={{ maxHeight: expanded ? "none" : "50vh", overflow: "hidden", position: "relative" }}>
          {editingPost ? (
            <div>
              <textarea value={editText} onChange={e => setEditText(e.target.value)} rows={4}
                style={{ width: "100%", background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: 12, color: T.text, fontSize: 15, resize: "vertical", fontFamily: "inherit", lineHeight: 1.5, outline: "none", boxSizing: "border-box" }} />
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <Btn small onClick={saveEditPost}>Save</Btn>
                <Btn variant="ghost" small onClick={() => setEditingPost(false)}>Cancel</Btn>
              </div>
            </div>
          ) : (
            content.text && <div style={{ color: T.text, lineHeight: 1.6, fontSize: 15, whiteSpace: "pre-wrap" }}><Linkify text={content.text} /></div>
          )}
          {decryptedPhotos.length > 0 && (
            <div style={{ display: "grid", gridTemplateColumns: decryptedPhotos.length === 1 ? "1fr" : (isMobile && decryptedPhotos.length >= 3) ? "1fr 1fr" : decryptedPhotos.length === 2 ? "1fr 1fr" : "1fr 1fr 1fr", gap: 4, marginTop: content.text ? 12 : 0, borderRadius: 12, overflow: "hidden" }}>
              {decryptedPhotos.map((url, i) => url
                ? <img key={i} src={url} alt="" onClick={() => setLightboxPhoto(url)} style={{ width: "100%", aspectRatio: decryptedPhotos.length === 1 ? "auto" : "1.618 / 1", maxHeight: decryptedPhotos.length === 1 ? "50vh" : undefined, objectFit: decryptedPhotos.length === 1 ? "contain" : "cover", cursor: "pointer", display: "block" }} />
                : <div key={i} style={{ aspectRatio: "1.618 / 1", background: T.bgHover, display: "flex", alignItems: "center", justifyContent: "center", color: T.textDim, fontSize: 13 }}>Failed to load</div>
              )}
            </div>
          )}
          {!expanded && overflows && <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 80, background: `linear-gradient(transparent, ${T.bgCard})`, pointerEvents: "none" }} />}
        </div>
        {videosLoading && (
          <div style={{ marginTop: 12, padding: 20, background: T.bgHover, borderRadius: 12, textAlign: "center" }}>
            <div style={{ color: T.textMuted, fontSize: 14 }}>🔓 Downloading and decrypting video...</div>
          </div>
        )}
        {decryptedVideos.length > 0 && (
          <div style={{ marginTop: content.text || decryptedPhotos.length > 0 ? 12 : 0 }}>
            {decryptedVideos.map((v, i) => v ? (
              <video key={i} controls preload="metadata" style={{ width: "100%", maxHeight: "50vh", borderRadius: 12, marginBottom: 8, background: "#000" }}>
                <source src={v.url} type={v.type} />
              </video>
            ) : (
              <div key={i} style={{ height: 200, background: T.bgHover, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", color: T.textDim, fontSize: 13, marginBottom: 8 }}>Failed to load video</div>
            ))}
          </div>
        )}
        {overflows && !expanded && <button onClick={() => setExpanded(true)} style={{ background: "none", border: "none", color: T.accent, cursor: "pointer", fontSize: 13, fontWeight: 600, padding: "8px 0 0", display: "block" }}>Show more</button>}
        {expanded && overflows && <button onClick={() => setExpanded(false)} style={{ background: "none", border: "none", color: T.accent, cursor: "pointer", fontSize: 13, fontWeight: 600, padding: "8px 0 0", display: "block" }}>Show less</button>}
        {lightboxPhoto && <PhotoLightbox url={lightboxPhoto} onClose={() => setLightboxPhoto(null)} />}
      </>) : failed ? (
        <div style={{ color: T.textDim, fontSize: 14, fontStyle: "italic", padding: "12px 0" }}>🔒 Encrypted — not in your network</div>
      ) : (
        <div style={{ color: T.textDim, fontSize: 14, fontStyle: "italic", padding: "12px 0" }}>🔓 Decrypting...</div>
      )}
      {content && (content.text || decryptedPhotos.length > 0 || decryptedVideos.length > 0) && (
        <div style={{ marginTop: 12 }}>
          <button onClick={toggleComments} style={{ background: "none", border: "none", color: T.textMuted, cursor: "pointer", fontSize: 13, padding: "4px 0" }}>
            💬 {localCommentCount > 0 ? `${localCommentCount} comment${localCommentCount !== 1 ? "s" : ""}` : "Comment"}
          </button>
        </div>
      )}
      {showComments && content && (
        <div style={{ marginTop: 12, borderTop: `1px solid ${T.border}`, paddingTop: 12 }}>
          {loadingComments && <div style={{ color: T.textDim, fontSize: 13, padding: "8px 0" }}>Loading comments...</div>}
          {comments.map(c => (
            <div key={c.id} style={{ display: "flex", gap: isMobile ? 6 : 10, padding: "8px 0", borderBottom: `1px solid ${T.border}` }}>
              <Avatar username={c.author} size={isMobile ? 24 : 28} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: isMobile ? 4 : 6, flexWrap: "wrap" }}>
                  <span onClick={() => navigateToProfile(c.author, c.domain || "lsocial.org")} style={{ fontWeight: 600, color: T.text, fontSize: 13, cursor: "pointer" }}>{getDisplayName(c.author, c.domain || "lsocial.org", c.authorHash)}</span>
                  <span onClick={() => navigateToProfile(c.author, c.domain || "lsocial.org")} style={{ color: T.textDim, fontSize: 11, cursor: "pointer" }}>@{getHandle(c.author, c.domain || "lsocial.org")}@{c.domain || "lsocial.org"}</span>
                  <TimeAgo ts={c.createdAt} />
                  {c.author !== currentUser && c.author !== identity?.usernameHash && c.authorHash && !isOwnOrFriend(c.author, c.domain || "lsocial.org") && (
                    <button onClick={() => sendHashFriendRequest(c.authorHash, c.domain || "lsocial.org")}
                      disabled={friendReqSent.has(c.authorHash)}
                      style={{ background: "none", border: "none", color: friendReqSent.has(c.authorHash) ? T.success : T.accent, cursor: friendReqSent.has(c.authorHash) ? "default" : "pointer", fontSize: 11, padding: "0 4px", fontWeight: 600 }}
                      title="Send friend request">{friendReqSent.has(c.authorHash) ? "Sent" : "+ Friend"}</button>
                  )}
                  {(c.author === currentUser || c.author === identity?.usernameHash) && (
                    <>
                      <button onClick={() => setEditingComment({ id: c.id, text: c.text })} style={{ background: "none", border: "none", color: T.textDim, cursor: "pointer", fontSize: 11, padding: "0 2px" }} title="Edit comment">✏️</button>
                      <button onClick={async () => {
                        if (!confirm("Delete this comment?")) return;
                        try {
                          await api.request(`/api/posts/${post.id}/comments/${c.id}`, { method: "DELETE" });
                          setComments(prev => prev.filter(x => x.id !== c.id));
                          setLocalCommentCount(prev => prev - 1);
                        } catch (err) { console.error("[delete-comment]", err); }
                      }} style={{ background: "none", border: "none", color: T.textDim, cursor: "pointer", fontSize: 12, padding: "0 2px" }} title="Delete comment">🗑</button>
                    </>
                  )}
                </div>
                {editingComment?.id === c.id ? (
                  <div style={{ marginTop: 4 }}>
                    <input value={editingComment.text} onChange={e => setEditingComment({ ...editingComment, text: e.target.value })}
                      onKeyDown={e => e.key === "Enter" && saveEditComment(c.id, editingComment.text)}
                      style={{ width: "100%", background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: "6px 10px", color: T.text, fontSize: 13, outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} />
                    <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
                      <Btn small onClick={() => saveEditComment(c.id, editingComment.text)} style={{ padding: "4px 10px", fontSize: 12 }}>Save</Btn>
                      <Btn variant="ghost" small onClick={() => setEditingComment(null)} style={{ padding: "4px 10px", fontSize: 12 }}>Cancel</Btn>
                    </div>
                  </div>
                ) : (
                  <div style={{ color: T.text, fontSize: 14, lineHeight: 1.5, marginTop: 2 }}><Linkify text={c.text} /></div>
                )}
              </div>
            </div>
          ))}
          {authorFeedKey && (
            <div style={{ display: "flex", gap: 8, marginTop: 10, alignItems: "center" }}>
              <Avatar username={currentUser} size={28} />
              <input value={commentText} onChange={e => setCommentText(e.target.value)} onKeyDown={e => e.key === "Enter" && !e.shiftKey && (e.preventDefault(), submitComment())} placeholder="Write a comment..."
                style={{ flex: 1, background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 20, padding: "8px 14px", color: T.text, fontSize: 13, outline: "none", fontFamily: "inherit" }} />
              <Btn small onClick={submitComment} disabled={!commentText.trim() || posting} style={{ borderRadius: 20, padding: "6px 14px" }}>{posting ? "..." : "Post"}</Btn>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Compose
// ============================================================================
function Compose({ onPost, isMobile }) {
  const [text, setText] = useState("");
  const [posting, setPosting] = useState(false);
  const [status, setStatus] = useState("");
  const [attachedPhotos, setAttachedPhotos] = useState([]);
  const [attachedVideos, setAttachedVideos] = useState([]); // { file, previewUrl }
  const { currentUser } = useApp();
  const mediaInputRef = useRef(null);
  const videoInputRef = useRef(null);
  const addPhotos = (e) => {
    const files = Array.from(e.target.files || []);
    const newPhotos = files.filter(f => f.type.startsWith("image/")).slice(0, 100 - attachedPhotos.length).map(file => ({ file, previewUrl: URL.createObjectURL(file) }));
    const newVideos = files.filter(f => f.type.startsWith("video/")).slice(0, 10 - attachedVideos.length).map(file => ({ file, previewUrl: URL.createObjectURL(file) }));
    setAttachedPhotos(prev => [...prev, ...newPhotos].slice(0, 100));
    setAttachedVideos(prev => [...prev, ...newVideos].slice(0, 10));
    e.target.value = "";
  };
  const removePhoto = (idx) => { setAttachedPhotos(prev => { URL.revokeObjectURL(prev[idx].previewUrl); return prev.filter((_, i) => i !== idx); }); };
  const removeVideo = (idx) => { setAttachedVideos(prev => { URL.revokeObjectURL(prev[idx].previewUrl); return prev.filter((_, i) => i !== idx); }); };
  const submit = async () => {
    if ((!text.trim() && attachedPhotos.length === 0 && attachedVideos.length === 0) || !identity) return;
    setPosting(true);
    try {
      const plaintext = text.trim(); const photoRefs = []; const videoRefs = [];
      for (let i = 0; i < attachedPhotos.length; i++) {
        setStatus(`Encrypting photo ${i + 1}/${attachedPhotos.length}...`);
        const photoRaw = new Uint8Array(await attachedPhotos[i].file.arrayBuffer());
        const photoKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const photoIv = crypto.getRandomValues(new Uint8Array(12));
        const photoCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: photoIv }, photoKey, photoRaw));
        const combined = new Uint8Array(12 + photoCt.length); combined.set(photoIv); combined.set(photoCt, 12);
        const photoHash = await computeHashClient(combined);
        setStatus(`Uploading photo ${i + 1}/${attachedPhotos.length}...`);
        const formData = new FormData();
        formData.append("file", new Blob([combined], { type: "application/octet-stream" }), `photo-${i}.enc`);
        const uploadRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: formData });
        if (!uploadRes.ok) throw new Error("Photo upload failed");
        const rawKey = await crypto.subtle.exportKey("raw", photoKey);
        photoRefs.push({ hash: photoHash, key: toB64(new Uint8Array(rawKey)), iv: toB64(photoIv), type: attachedPhotos[i].file.type || "image/jpeg" });
      }
      for (let i = 0; i < attachedVideos.length; i++) {
        setStatus(`Encrypting video ${i + 1}/${attachedVideos.length}...`);
        const videoRaw = new Uint8Array(await attachedVideos[i].file.arrayBuffer());
        const videoKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const videoIv = crypto.getRandomValues(new Uint8Array(12));
        const videoCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: videoIv }, videoKey, videoRaw));
        const combined = new Uint8Array(12 + videoCt.length); combined.set(videoIv); combined.set(videoCt, 12);
        const videoHash = await computeHashClient(combined);
        setStatus(`Uploading video ${i + 1}/${attachedVideos.length}...`);
        const formData = new FormData();
        formData.append("file", new Blob([combined], { type: "application/octet-stream" }), `video-${i}.enc`);
        const uploadRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: formData });
        if (!uploadRes.ok) throw new Error("Video upload failed");
        const rawKey = await crypto.subtle.exportKey("raw", videoKey);
        videoRefs.push({ hash: videoHash, key: toB64(new Uint8Array(rawKey)), iv: toB64(videoIv), type: attachedVideos[i].file.type || "video/mp4" });
      }
      let envelope;
      const postContent = { text: plaintext || null, photos: photoRefs.length > 0 ? photoRefs : undefined, videos: videoRefs.length > 0 ? videoRefs : undefined };
      const postJson = JSON.stringify(postContent);
      if (new Blob([postJson]).size <= 200 && photoRefs.length === 0 && videoRefs.length === 0) {
        setStatus("Encrypting..."); const { ciphertext, iv } = await encryptWithFeedKey(plaintext, identity.feedKey); envelope = { ct: ciphertext, iv };
      } else {
        setStatus("Encrypting envelope..."); const { ciphertext, iv } = await encryptWithFeedKey(postJson, identity.feedKey); envelope = { ct: ciphertext, iv, _hasMedia: photoRefs.length > 0 };
      }
      setStatus("Uploading...");
      const res = await api.request("/api/posts", { method: "POST", body: JSON.stringify({ envelope }) });
      attachedPhotos.forEach(p => URL.revokeObjectURL(p.previewUrl));
      attachedVideos.forEach(v => URL.revokeObjectURL(v.previewUrl));
      onPost({ id: res.id, author: currentUser, domain: "lsocial.org", envelope: JSON.stringify(envelope), contentHash: res.contentHash, createdAt: Date.now(), _localContent: plaintext, _localPhotos: photoRefs, _localVideos: videoRefs });
      setStatus(""); setText(""); setAttachedPhotos([]); setAttachedVideos([]);
    } catch (err) { console.error("Post failed:", err); setStatus("Failed"); setTimeout(() => setStatus(""), 3000); }
    setPosting(false);
  };
  return (
    <div style={{ background: T.bgCard, borderRadius: 12, padding: isMobile ? 12 : 16, border: `1px solid ${T.border}`, marginBottom: 16 }}>
      <div style={{ display: "flex", gap: isMobile ? 8 : 12 }}>
        {!isMobile && <Avatar username={currentUser} size={36} />}
        <textarea value={text} onChange={e => setText(e.target.value)} placeholder="" rows={3}
          style={{ flex: 1, background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: isMobile ? 10 : 12, color: T.text, fontSize: isMobile ? 14 : 15, resize: "vertical", fontFamily: "inherit", lineHeight: 1.5, outline: "none", minHeight: 60 }}
          onFocus={e => e.target.style.borderColor = T.borderFocus} onBlur={e => e.target.style.borderColor = T.border} />
      </div>
      {attachedPhotos.length > 0 && (
        <div style={{ display: "flex", gap: 8, marginTop: 10, paddingLeft: isMobile ? 0 : 48, flexWrap: "wrap" }}>
          {attachedPhotos.map((p, i) => (
            <div key={i} style={{ position: "relative", width: isMobile ? 64 : 80, height: isMobile ? 64 : 80, borderRadius: 8, overflow: "hidden" }}>
              <img src={p.previewUrl} alt="" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
              <button onClick={() => removePhoto(i)} style={{ position: "absolute", top: 2, right: 2, width: 20, height: 20, borderRadius: "50%", background: "rgba(0,0,0,0.7)", border: "none", color: "#fff", fontSize: 11, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
            </div>
          ))}
        </div>
      )}
      {attachedVideos.length > 0 && (
        <div style={{ display: "flex", gap: 8, marginTop: 10, paddingLeft: isMobile ? 0 : 48, flexWrap: "wrap" }}>
          {attachedVideos.map((v, i) => (
            <div key={i} style={{ position: "relative", width: isMobile ? 100 : 120, height: isMobile ? 64 : 80, borderRadius: 8, overflow: "hidden", background: T.bgHover }}>
              <video src={v.previewUrl} style={{ width: "100%", height: "100%", objectFit: "cover" }} muted />
              <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", color: "#fff", fontSize: 24, textShadow: "0 1px 4px rgba(0,0,0,0.8)" }}>▶</div>
              <button onClick={() => removeVideo(i)} style={{ position: "absolute", top: 2, right: 2, width: 20, height: 20, borderRadius: "50%", background: "rgba(0,0,0,0.7)", border: "none", color: "#fff", fontSize: 11, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
            </div>
          ))}
        </div>
      )}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12, paddingLeft: isMobile ? 0 : 48 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button onClick={() => mediaInputRef.current?.click()} style={{ background: "none", border: "none", color: T.textMuted, cursor: "pointer", fontSize: 20 }} title="Attach photos or videos">📎</button>
          <input ref={mediaInputRef} type="file" accept="image/*,video/*" multiple onChange={addPhotos} style={{ display: "none" }} />
          {(attachedPhotos.length > 0 || attachedVideos.length > 0) && <span style={{ fontSize: 12, color: T.textDim }}>{attachedPhotos.length > 0 ? `${attachedPhotos.length} photo${attachedPhotos.length !== 1 ? "s" : ""}` : ""}{attachedPhotos.length > 0 && attachedVideos.length > 0 ? ", " : ""}{attachedVideos.length > 0 ? `${attachedVideos.length} video${attachedVideos.length !== 1 ? "s" : ""}` : ""}</span>}
          {!isMobile && <span style={{ fontSize: 12, color: T.accent }}>🔒 Encrypted</span>}
        </div>
        <Btn onClick={submit} disabled={(!text.trim() && attachedPhotos.length === 0 && attachedVideos.length === 0) || posting || !identity} small>{posting ? status || "Posting..." : "Post"}</Btn>
      </div>
      {status && !posting && <div style={{ paddingLeft: isMobile ? 0 : 48, marginTop: 6, fontSize: 12, color: status.includes("Failed") ? T.danger : T.success }}>{status}</div>}
    </div>
  );
}

// ============================================================================
// Feed
// ============================================================================
function FeedView({ isMobile }) {
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const { currentUser } = useApp();
  const fetchFeed = useCallback(async () => {
    if (!vault || !identity) return;
    const usernames = [currentUser];
    if (identity?.usernameHash) usernames.push(identity.usernameHash);
    if (vault?.friends) { for (const [addr, info] of Object.entries(vault.friends)) { if (info.feedKeyB64 || info.previousFeedKeyB64) usernames.push(addr.split("@")[0]); } }
    const bloom = createBloomFilter(usernames, cachedUserCount);
    try { const data = await api.request("/api/feed", { method: "POST", body: JSON.stringify({ bloom, bloomHashCount: BLOOM_HASH_COUNT }) }); if (data.userCount) cachedUserCount = data.userCount; setPosts(data.posts || []); }
    catch (err) { console.error("[feed]", err); }
    setLoading(false);
  }, [currentUser]);
  useEffect(() => { fetchFeed(); }, [fetchFeed]);
  const handlePost = (post) => { setPosts(prev => [post, ...prev]); };
  const handleDelete = (postId) => { setPosts(prev => prev.filter(p => p.id !== postId)); };
  return (
    <div>
      <Compose onPost={handlePost} isMobile={isMobile} />
      {loading && <div style={{ textAlign: "center", padding: 20, color: T.textDim }}>Loading feed...</div>}
      {!loading && posts.length === 0 && <div style={{ textAlign: "center", padding: 40, color: T.textDim, fontSize: 14 }}>No posts yet. Write something, or add friends to see their posts here.</div>}
      {posts.map(p => <Post key={p.id} post={{ ...p, _localContent: p._localContent }} onDelete={handleDelete} isMobile={isMobile} />)}
      {!loading && posts.length > 0 && <div style={{ textAlign: "center", padding: 20, color: T.textDim, fontSize: 13 }}>That's everything. No algorithm to scroll past.</div>}
    </div>
  );
}

// ============================================================================
// Friends
// ============================================================================
function FriendsView() {
  const [addr, setAddr] = useState("");
  const [sent, setSent] = useState(null);
  const [pendingRequests, setPendingRequests] = useState([]);
  const [hashRequests, setHashRequests] = useState([]);
  const [decryptedReqUsernames, setDecryptedReqUsernames] = useState({});
  const { currentUser, navigateToProfile } = useApp();
  const friendsList = vault ? Object.entries(vault.friends).map(([addr, info]) => { const [username, domain] = addr.split("@"); return { username, domain, addr, ...info }; }) : [];
  const activeFriends = friendsList.filter(f => !f.expired);
  const expiredFriends = friendsList.filter(f => f.expired);
  useEffect(() => {
    const fetchData = async () => {
      try { const data = await api.request("/api/notifications"); setPendingRequests((data.notifications || []).filter(n => n.type === "friend_request")); } catch {}
      // Fetch hash-based friend requests
      try { const data = await api.request("/api/friend-requests"); setHashRequests(data.requests || []); } catch {}
      await processKeyExchanges(); await processFriendAccepted(); await retryPendingKeyRotations();
    };
    fetchData(); const interval = setInterval(fetchData, 30000); return () => clearInterval(interval);
  }, []);
  useEffect(() => {
    (async () => {
      const names = {};
      for (const r of hashRequests) {
        try {
          const p = JSON.parse(r.payload);
          if (p.encryptedUsername && p.senderEncPubKey && identity) {
            const senderPub = await crypto.subtle.importKey("raw", fromB64(p.senderEncPubKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
            const shared = await crypto.subtle.deriveKey({ name: "ECDH", public: senderPub }, identity.encryption.privateKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
            const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(p.encryptedUsername.iv) }, shared, fromB64(p.encryptedUsername.ct));
            names[r.id] = dec.decode(plain);
          }
        } catch {}
      }
      if (Object.keys(names).length) setDecryptedReqUsernames(names);
    })();
  }, [hashRequests]);
  const sendReq = async () => {
    if (!addr.includes("@") || !identity) return;
    const [friendUsername, friendDomain] = addr.split("@");
    if (!friendUsername || !friendDomain) return;
    try {
      const friendHash = await hashUsername(friendUsername);
      // Encrypt our plaintext username for the recipient
      let encryptedUsername = null;
      try {
        const profile = await api.request(`/api/profile/by-hash/${friendHash}`);
        if (profile.encryptionPublicKey) {
          const recipientPub = await crypto.subtle.importKey("raw", fromB64(profile.encryptionPublicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
          const shared = await crypto.subtle.deriveKey({ name: "ECDH", public: recipientPub }, identity.encryption.privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, shared, enc.encode(window._currentUser));
          encryptedUsername = { ct: toB64(new Uint8Array(ct)), iv: toB64(iv) };
        }
      } catch {}
      const payload = JSON.stringify({
        senderHash: identity.usernameHash,
        senderDomain: "lsocial.org",
        senderEncPubKey: identity.encryptionPublicKeyB64,
        senderSignPubKey: identity.signingPublicKeyB64,
        senderFingerprint: identity.fingerprint,
        encryptedUsername,
      });
      await api.request("/api/friend-request", { method: "POST", body: JSON.stringify({ toHash: friendHash, toDomain: friendDomain, payload }) });
      setSent(addr); setAddr("");
    } catch (err) { console.error("[friend-request]", err); alert("Friend request failed: " + (err.message || "Unknown error")); }
  };
  const reFriend = async (friend) => {
    try {
      const friendHash = /^[a-f0-9]{64}$/.test(friend.username) ? friend.username : await hashUsername(friend.username);
      let encryptedUsername = null;
      try {
        const profile = await api.request(`/api/profile/by-hash/${friendHash}`);
        if (profile.encryptionPublicKey && identity) {
          const recipientPub = await crypto.subtle.importKey("raw", fromB64(profile.encryptionPublicKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
          const shared = await crypto.subtle.deriveKey({ name: "ECDH", public: recipientPub }, identity.encryption.privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, shared, enc.encode(window._currentUser));
          encryptedUsername = { ct: toB64(new Uint8Array(ct)), iv: toB64(iv) };
        }
      } catch {}
      const payload = JSON.stringify({
        senderHash: identity.usernameHash,
        senderDomain: "lsocial.org",
        senderEncPubKey: identity.encryptionPublicKeyB64,
        senderSignPubKey: identity.signingPublicKeyB64,
        senderFingerprint: identity.fingerprint,
        encryptedUsername,
      });
      await api.request("/api/friend-request", { method: "POST", body: JSON.stringify({ toHash: friendHash, toDomain: friend.domain, payload }) });
      if (vault?.friends?.[friend.addr]) { delete vault.friends[friend.addr]; await saveVault(); }
      alert(`Friend request sent to ${friend.plaintextUsername || friend.displayName || friend.username}. They'll need to accept to restore the connection.`);
    } catch (err) { console.error("Re-friend failed:", err); }
  };
  const acceptRequest = async (notif) => {
    try {
      const [fromUsername, fromDomain] = (notif.from || "").split("@"); if (!fromUsername || !fromDomain) return;
      const fromEncPubKey = notif.fromKeys?.encryption; if (!fromEncPubKey || !identity) return;
      const myDisplayName = vault?.displayName || null; const myPhotoHash = vault?.photoHash || null; const myFullPhotoHash = vault?.fullPhotoHash || null;
      const keyPayload = await encryptFeedKeyForFriend(identity.feedKeyB64, identity.encryption.privateKey, fromEncPubKey, myDisplayName, myPhotoHash, myFullPhotoHash, window._currentUser);
      await api.request("/api/friends/accept", { method: "POST", body: JSON.stringify({ from: notif.from, notificationId: notif.id, keyExchangePayload: keyPayload }) });
      await api.request("/api/key-exchange", { method: "POST", body: JSON.stringify({ toUsername: fromUsername, encryptedPayload: keyPayload }) });
      vault.friends[notif.from] = { encPubKey: fromEncPubKey, feedKeyB64: null }; await saveVault();
      setPendingRequests(prev => prev.filter(r => r.id !== notif.id));
    } catch (err) { console.error("Accept failed:", err); }
  };
  const acceptHashRequest = async (req) => {
    try {
      const payload = JSON.parse(req.payload);
      const fromEncPubKey = payload.senderEncPubKey;
      if (!fromEncPubKey || !identity) return;
      // Decrypt sender's plaintext username if included
      let senderUsername = null;
      if (payload.encryptedUsername) {
        try {
          const senderPub = await crypto.subtle.importKey("raw", fromB64(fromEncPubKey), { name: "ECDH", namedCurve: "P-256" }, false, []);
          const shared = await crypto.subtle.deriveKey({ name: "ECDH", public: senderPub }, identity.encryption.privateKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
          const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(payload.encryptedUsername.iv) }, shared, fromB64(payload.encryptedUsername.ct));
          senderUsername = dec.decode(plain);
        } catch {}
      }
      const myDisplayName = vault?.displayName || null; const myPhotoHash = vault?.photoHash || null; const myFullPhotoHash = vault?.fullPhotoHash || null;
      const keyPayload = await encryptFeedKeyForFriend(identity.feedKeyB64, identity.encryption.privateKey, fromEncPubKey, myDisplayName, myPhotoHash, myFullPhotoHash, window._currentUser);
      await api.request(`/api/friend-request/${req.id}/accept`, { method: "POST", body: JSON.stringify({ keyExchangePayload: keyPayload }) });
      // Look up the sender's profile by hash to get their username for key exchange
      try {
        const profile = await api.request(`/api/profile/by-hash/${req.fromHash}`);
        if (profile.encryptionPublicKey) {
          const addr = `${req.fromHash}@${req.fromDomain}`;
          vault.friends[addr] = { encPubKey: profile.encryptionPublicKey, feedKeyB64: null, isHashIdentity: true, plaintextUsername: senderUsername };
          await saveVault();
        }
      } catch {}
      setHashRequests(prev => prev.filter(r => r.id !== req.id));
    } catch (err) { console.error("Accept hash request failed:", err); }
  };
  const rejectHashRequest = async (id) => {
    try { await api.request(`/api/friend-request/${id}/reject`, { method: "POST" }); } catch {}
    setHashRequests(prev => prev.filter(r => r.id !== id));
  };
  const dismissRequest = async (id) => { try { await api.request(`/api/notifications/${id}`, { method: "DELETE" }); } catch {} setPendingRequests(prev => prev.filter(r => r.id !== id)); };
  const allPendingCount = pendingRequests.length + hashRequests.length;
  return (
    <div>
      <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, border: `1px solid ${T.border}`, marginBottom: 16 }}>
        <h3 style={{ margin: "0 0 12px", color: T.text, fontSize: 16 }}>Add a Friend</h3>
        <div style={{ display: "flex", gap: 8 }}>
          <input value={addr} onChange={e => setAddr(e.target.value)} onKeyDown={e => e.key === "Enter" && sendReq()} placeholder="username@lsocial.org"
            style={{ flex: 1, background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: "10px 14px", color: T.text, fontSize: 14, outline: "none", fontFamily: "inherit" }} />
          <Btn small disabled={!addr.includes("@")} onClick={sendReq}>Send Request</Btn>
        </div>
        {sent && <p style={{ color: T.success, fontSize: 13, marginTop: 8, marginBottom: 0 }}>Sent to {sent}</p>}
      </div>
      {allPendingCount > 0 && (
        <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, border: `1px solid ${T.border}`, marginBottom: 16 }}>
          <h3 style={{ margin: "0 0 12px", color: T.text, fontSize: 16 }}>Pending Requests ({allPendingCount})</h3>
          {pendingRequests.map(n => (
            <div key={n.id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0", borderBottom: `1px solid ${T.border}` }}>
              <Avatar username={n.from?.split("@")[0] || "?"} size={36} />
              <div style={{ flex: 1 }}><div style={{ color: T.text, fontWeight: 600, fontSize: 14 }}>{n.from}</div><TimeAgo ts={n.timestamp} /></div>
              <Btn small onClick={() => acceptRequest(n)}>Accept</Btn>
              <Btn variant="ghost" small onClick={() => dismissRequest(n.id)}>Dismiss</Btn>
            </div>
          ))}
          {hashRequests.map(r => (
            <div key={`h-${r.id}`} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0", borderBottom: `1px solid ${T.border}` }}>
              <Avatar username={decryptedReqUsernames[r.id] || r.fromHash?.slice(0, 8) || "?"} size={36} />
              <div style={{ flex: 1 }}>
                <div style={{ color: T.text, fontWeight: 600, fontSize: 14 }}>{decryptedReqUsernames[r.id] || truncateHash(r.fromHash)}@{r.fromDomain}</div>
                <TimeAgo ts={r.createdAt} />
              </div>
              <Btn small onClick={() => acceptHashRequest(r)}>Accept</Btn>
              <Btn variant="ghost" small onClick={() => rejectHashRequest(r.id)}>Dismiss</Btn>
            </div>
          ))}
        </div>
      )}
      {activeFriends.length > 0 && (
        <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, border: `1px solid ${T.border}`, marginBottom: 16 }}>
          <h3 style={{ margin: "0 0 16px", color: T.text, fontSize: 16 }}>Friends ({activeFriends.length})</h3>
          {activeFriends.map(f => {
            const isHash = f.isHashIdentity || /^[a-f0-9]{64}$/.test(f.username);
            const friendName = f.plaintextUsername || f.displayName || (isHash ? truncateHash(f.username) : f.username);
            const displayIdent = isHash ? (f.plaintextUsername ? `@${f.plaintextUsername}@${f.domain}` : truncateHash(f.username) + "@" + f.domain) : `@${f.username}@${f.domain}`;
            return (
              <div key={f.addr} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderBottom: `1px solid ${T.border}` }}>
                <Avatar username={f.plaintextUsername || f.username} size={40} domain={f.domain} clickable />
                <div style={{ flex: 1 }}><div onClick={() => navigateToProfile(f.username, f.domain)} style={{ fontWeight: 600, color: T.text, fontSize: 14, cursor: "pointer" }}>{friendName}</div><div onClick={() => navigateToProfile(f.username, f.domain)} style={{ color: T.textMuted, fontSize: 13, cursor: "pointer" }}>{displayIdent}</div></div>
                <div style={{ fontSize: 11, color: f.feedKeyB64 ? T.success : T.warn }}>{f.feedKeyB64 ? "🔑 Feed key received" : "⏳ Awaiting feed key"}</div>
                {f.keyChangedAt && <div style={{ fontSize: 11, color: T.accent }}>🔄 Key updated</div>}
              </div>
            );
          })}
        </div>
      )}
      {expiredFriends.length > 0 && (
        <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, border: `1px solid rgba(255,74,74,0.2)` }}>
          <h3 style={{ margin: "0 0 8px", color: T.text, fontSize: 16 }}>Expired Connections ({expiredFriends.length})</h3>
          <p style={{ color: T.textDim, fontSize: 13, marginBottom: 16, lineHeight: 1.5 }}>These friends changed their keys and the transition period has expired. Send a new friend request to reconnect.</p>
          {expiredFriends.map(f => (
            <div key={f.addr} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderBottom: `1px solid ${T.border}` }}>
              <Avatar username={f.plaintextUsername || f.username} size={40} domain={f.domain} />
              <div style={{ flex: 1 }}><div style={{ fontWeight: 600, color: T.text, fontSize: 14 }}>{f.plaintextUsername || f.displayName || f.username}</div><div style={{ color: T.textMuted, fontSize: 13 }}>@{f.plaintextUsername || f.username}@{f.domain}</div></div>
              <Btn small onClick={() => reFriend(f)} style={{ background: T.warn, color: "#000" }}>Re-friend (keys expired)</Btn>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// ECDH chat encryption (per-conversation shared secret)
// ============================================================================
async function deriveConversationKey(myEncPrivateKey, theirEncPubKeyB64) {
  const theirPub = await crypto.subtle.importKey("raw", fromB64(theirEncPubKeyB64), { name: "ECDH", namedCurve: "P-256" }, false, []);
  return crypto.subtle.deriveKey({ name: "ECDH", public: theirPub }, myEncPrivateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encryptChatMessage(content, conversationKey) {
  const payload = typeof content === "string" ? content : JSON.stringify(content);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, conversationKey, enc.encode(payload));
  return { encryptedContent: toB64(new Uint8Array(ct)), iv: toB64(iv) };
}

async function decryptChatMessage(encryptedContent, iv, conversationKey) {
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, conversationKey, fromB64(encryptedContent));
    const str = dec.decode(plain);
    try { const parsed = JSON.parse(str); if (parsed && typeof parsed === "object" && ("text" in parsed || "photos" in parsed || "videos" in parsed)) return parsed; } catch {}
    return { text: str };
  } catch { return null; }
}

// ============================================================================
// Chat media decryption + display
// ============================================================================
function ChatMediaGrid({ refs, type, isMobile }) {
  const [urls, setUrls] = useState([]);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const result = [];
      for (const ref of refs) {
        try {
          const res = await fetch(`/content/${ref.hash}`);
          if (!res.ok) { result.push(null); continue; }
          const encrypted = new Uint8Array(await res.arrayBuffer());
          const iv = encrypted.slice(0, 12);
          const ct = encrypted.slice(12);
          const key = await crypto.subtle.importKey("raw", fromB64(ref.key), { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
          const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
          result.push(URL.createObjectURL(new Blob([plain], { type: ref.type || (type === "photo" ? "image/jpeg" : "video/mp4") })));
        } catch { result.push(null); }
      }
      if (!cancelled) setUrls(result);
    })();
    return () => { cancelled = true; urls.forEach(u => { if (u) URL.revokeObjectURL(u); }); };
  }, [refs]);
  if (urls.length === 0) return null;
  if (type === "video") return (<div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
    {urls.map((u, i) => u ? <video key={i} src={u} controls style={{ maxWidth: "100%", borderRadius: 12, maxHeight: 300 }} /> : null)}
  </div>);
  return (<div style={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
    {urls.map((u, i) => u ? <img key={i} src={u} alt="" style={{ maxWidth: urls.length === 1 ? "100%" : "calc(50% - 1px)", borderRadius: urls.length === 1 ? 12 : 4, maxHeight: 300, objectFit: "cover", cursor: "pointer" }} onClick={() => window.open(u, "_blank")} /> : null)}
  </div>);
}

// ============================================================================
// Group list item (decrypts group name)
// ============================================================================
function GroupListItem({ group, activeGroup, onOpen, decryptGroupKey, decryptGroupName }) {
  const [name, setName] = useState("...");
  useEffect(() => {
    (async () => {
      const gKey = await decryptGroupKey(group.encryptedKey, group.keyIv, group.creator);
      if (gKey) { const n = await decryptGroupName(group.nameEncrypted, group.nameIv, gKey); setName(n); }
      else setName("Group");
    })();
  }, [group.id]);
  return (
    <div onClick={() => onOpen(group)} style={{
      padding: "10px 16px", cursor: "pointer", display: "flex", gap: 12, alignItems: "center",
      background: activeGroup === group.id ? T.accentDim : "transparent",
      borderLeft: activeGroup === group.id ? `3px solid ${T.accent}` : "3px solid transparent",
    }}>
      <div style={{ width: 32, height: 32, borderRadius: "50%", background: T.accent + "33", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, color: T.accent, fontWeight: 600 }}>G</div>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 500, color: T.text, fontSize: 13 }}>{name}</div>
      </div>
    </div>
  );
}

// ============================================================================
// DMs (Chats)
// ============================================================================
function DMView({ isMobile }) {
  const { currentUser, navigateToProfile } = useApp();
  const [conversations, setConversations] = useState([]);
  const [active, setActive] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMsg, setNewMsg] = useState("");
  const [sending, setSending] = useState(false);
  const [loading, setLoading] = useState(false);
  const [convKey, setConvKey] = useState(null);
  const [newChatAddr, setNewChatAddr] = useState("");
  const [chatRequests, setChatRequests] = useState([]);
  const [chatPhotos, setChatPhotos] = useState([]);
  const [chatVideos, setChatVideos] = useState([]);
  const [sendStatus, setSendStatus] = useState("");
  // Group chat state
  const [groups, setGroups] = useState([]);
  const [activeGroup, setActiveGroup] = useState(null);
  const [groupMessages, setGroupMessages] = useState([]);
  const [groupKey, setGroupKey] = useState(null);
  const [groupMembers, setGroupMembers] = useState([]);
  const [groupName, setGroupName] = useState("");
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [selectedFriends, setSelectedFriends] = useState([]);
  const [groupChatPhotos, setGroupChatPhotos] = useState([]);
  const [groupChatVideos, setGroupChatVideos] = useState([]);
  const [groupSendStatus, setGroupSendStatus] = useState("");
  const endRef = useRef(null);
  const pollRef = useRef(null);
  const chatMediaRef = useRef(null);
  const groupMediaRef = useRef(null);
  const groupEndRef = useRef(null);

  const addChatMedia = (e) => {
    const files = Array.from(e.target.files || []);
    const newPhotos = files.filter(f => f.type.startsWith("image/")).slice(0, 10 - chatPhotos.length).map(file => ({ file, previewUrl: URL.createObjectURL(file) }));
    const newVideos = files.filter(f => f.type.startsWith("video/")).slice(0, 5 - chatVideos.length).map(file => ({ file, previewUrl: URL.createObjectURL(file) }));
    setChatPhotos(prev => [...prev, ...newPhotos].slice(0, 10));
    setChatVideos(prev => [...prev, ...newVideos].slice(0, 5));
    e.target.value = "";
  };
  const removeChatPhoto = (idx) => { setChatPhotos(prev => { URL.revokeObjectURL(prev[idx].previewUrl); return prev.filter((_, i) => i !== idx); }); };
  const removeChatVideo = (idx) => { setChatVideos(prev => { URL.revokeObjectURL(prev[idx].previewUrl); return prev.filter((_, i) => i !== idx); }); };
  const addGroupMedia = (e) => {
    const files = Array.from(e.target.files || []);
    const newPhotos = files.filter(f => f.type.startsWith("image/")).slice(0, 10 - groupChatPhotos.length).map(file => ({ file, previewUrl: URL.createObjectURL(file) }));
    const newVideos = files.filter(f => f.type.startsWith("video/")).slice(0, 5 - groupChatVideos.length).map(file => ({ file, previewUrl: URL.createObjectURL(file) }));
    setGroupChatPhotos(prev => [...prev, ...newPhotos].slice(0, 10));
    setGroupChatVideos(prev => [...prev, ...newVideos].slice(0, 5));
    e.target.value = "";
  };
  const removeGroupPhoto = (idx) => { setGroupChatPhotos(prev => { URL.revokeObjectURL(prev[idx].previewUrl); return prev.filter((_, i) => i !== idx); }); };
  const removeGroupVideo = (idx) => { setGroupChatVideos(prev => { URL.revokeObjectURL(prev[idx].previewUrl); return prev.filter((_, i) => i !== idx); }); };

  useEffect(() => {
    const fetchData = async () => {
      try { const data = await api.request("/api/chats"); setConversations(data.conversations || []); } catch {}
      try { const data = await api.request("/api/notifications"); setChatRequests((data.notifications || []).filter(n => n.type === "chat_request")); } catch {}
      try { const data = await api.request("/api/groups"); setGroups(data.groups || []); } catch {}
    };
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages.length]);
  useEffect(() => { groupEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [groupMessages.length]);

  const getDisplayName = (username) => {
    if (username === currentUser || username === identity?.usernameHash) return vault?.displayName || currentUser;
    const addr = `${username}@lsocial.org`;
    const direct = vault?.friends?.[addr];
    const bySync = findFriendSync(username);
    const friendInfo = (direct && bySync) ? { ...bySync, ...direct } : (direct || bySync);
    if (friendInfo?.displayName) return friendInfo.displayName;
    if (friendInfo?.plaintextUsername) return friendInfo.plaintextUsername;
    return /^[a-f0-9]{64}$/.test(username) ? truncateHash(username) : username;
  };

  const getEncPubKey = (username) => {
    const addr = `${username}@lsocial.org`;
    if (vault?.friends?.[addr]?.encPubKey) return vault.friends[addr].encPubKey;
    const contact = (vault?.chatContacts || []).find(c => c.username === username);
    return contact?.encPubKey || null;
  };

  const isFriend = (username) => {
    const addr = `${username}@lsocial.org`;
    return vault?.friends?.[addr]?.feedKeyB64 ? true : false;
  };

  const openConversation = async (username) => {
    setActiveGroup(null); setGroupKey(null); setGroupMessages([]);
    setActive(username);
    setMessages([]);
    setLoading(true);
    let encPubKey = getEncPubKey(username);
    if (!encPubKey) {
      try {
        const profile = await api.request(`/api/profile/${username}`);
        encPubKey = profile.encryptionPublicKey;
      } catch {}
    }
    if (encPubKey && identity) {
      const key = await deriveConversationKey(identity.encryption.privateKey, encPubKey);
      setConvKey(key);
      await loadMessages(username, key);
    }
    setLoading(false);
  };

  const loadMessages = async (username, key) => {
    try {
      const { messages: raw } = await api.request(`/api/chats/${username}/messages`);
      const decrypted = [];
      for (const m of raw) {
        const content = await decryptChatMessage(m.encryptedContent, m.iv, key);
        if (!content) { decrypted.push({ ...m, text: "[Decryption failed]", photos: [], videos: [] }); }
        else { decrypted.push({ ...m, text: content.text || "", photos: content.photos || [], videos: content.videos || [] }); }
      }
      setMessages(decrypted);
    } catch (err) { console.error("[chat]", err); }
  };

  useEffect(() => {
    if (!active || !convKey) return;
    const poll = async () => {
      try {
        const { messages: raw } = await api.request(`/api/chats/${active}/messages`);
        const decrypted = [];
        for (const m of raw) {
          const content = await decryptChatMessage(m.encryptedContent, m.iv, convKey);
          if (!content) { decrypted.push({ ...m, text: "[Decryption failed]", photos: [], videos: [] }); }
          else { decrypted.push({ ...m, text: content.text || "", photos: content.photos || [], videos: content.videos || [] }); }
        }
        setMessages(decrypted);
      } catch {}
    };
    pollRef.current = setInterval(poll, 5000);
    return () => clearInterval(pollRef.current);
  }, [active, convKey]);

  const sendMessage = async () => {
    if ((!newMsg.trim() && chatPhotos.length === 0 && chatVideos.length === 0) || !active || !convKey) return;
    setSending(true);
    try {
      const photoRefs = [];
      for (let i = 0; i < chatPhotos.length; i++) {
        setSendStatus(`Encrypting photo ${i + 1}/${chatPhotos.length}...`);
        const raw = new Uint8Array(await chatPhotos[i].file.arrayBuffer());
        const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw));
        const combined = new Uint8Array(12 + ct.length); combined.set(iv); combined.set(ct, 12);
        const hash = await computeHashClient(combined);
        setSendStatus(`Uploading photo ${i + 1}/${chatPhotos.length}...`);
        const formData = new FormData();
        formData.append("file", new Blob([combined], { type: "application/octet-stream" }), `chat-photo-${i}.enc`);
        const uploadRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: formData });
        if (!uploadRes.ok) throw new Error("Photo upload failed");
        const rawKey = await crypto.subtle.exportKey("raw", key);
        photoRefs.push({ hash, key: toB64(new Uint8Array(rawKey)), iv: toB64(iv), type: chatPhotos[i].file.type || "image/jpeg" });
      }
      const videoRefs = [];
      for (let i = 0; i < chatVideos.length; i++) {
        setSendStatus(`Encrypting video ${i + 1}/${chatVideos.length}...`);
        const raw = new Uint8Array(await chatVideos[i].file.arrayBuffer());
        const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw));
        const combined = new Uint8Array(12 + ct.length); combined.set(iv); combined.set(ct, 12);
        const hash = await computeHashClient(combined);
        setSendStatus(`Uploading video ${i + 1}/${chatVideos.length}...`);
        const formData = new FormData();
        formData.append("file", new Blob([combined], { type: "application/octet-stream" }), `chat-video-${i}.enc`);
        const uploadRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: formData });
        if (!uploadRes.ok) throw new Error("Video upload failed");
        const rawKey = await crypto.subtle.exportKey("raw", key);
        videoRefs.push({ hash, key: toB64(new Uint8Array(rawKey)), iv: toB64(iv), type: chatVideos[i].file.type || "video/mp4" });
      }
      setSendStatus("");
      const content = { text: newMsg.trim() || null };
      if (photoRefs.length > 0) content.photos = photoRefs;
      if (videoRefs.length > 0) content.videos = videoRefs;
      const { encryptedContent, iv: msgIv } = await encryptChatMessage(content, convKey);
      const res = await api.request(`/api/chats/${active}/messages`, {
        method: "POST",
        body: JSON.stringify({ encryptedContent, iv: msgIv }),
      });
      setMessages(prev => [...prev, { id: res.id, from: currentUser, to: active, text: content.text || "", photos: photoRefs, videos: videoRefs, createdAt: Date.now() }]);
      setNewMsg("");
      chatPhotos.forEach(p => URL.revokeObjectURL(p.previewUrl));
      chatVideos.forEach(v => URL.revokeObjectURL(v.previewUrl));
      setChatPhotos([]); setChatVideos([]);
      setConversations(prev => {
        const existing = prev.find(c => c.partner === active);
        if (existing) return [{ ...existing, lastMessageAt: Date.now(), lastMessageFrom: currentUser }, ...prev.filter(c => c.partner !== active)];
        return [{ partner: active, lastMessageAt: Date.now(), lastMessageFrom: currentUser }, ...prev];
      });
    } catch (err) { console.error("[chat-send]", err); setSendStatus(""); }
    setSending(false);
  };

  const sendChatRequest = async () => {
    const username = newChatAddr.split("@")[0];
    if (!username) return;
    try {
      const userHash = await hashUsername(username);
      await api.request(`/api/chats/${userHash}/request`, { method: "POST" });
      setNewChatAddr("");
      alert(`Chat request sent to ${username}`);
    } catch (err) { console.error("[chat-request]", err); alert(err.message); }
  };

  const acceptChatRequest = async (notif) => {
    const [fromUsername, fromDomain] = (notif.from || "").split("@");
    if (!fromUsername) return;
    const encPubKey = notif.fromKeys?.encryption;
    if (!encPubKey) return;
    if (!vault.chatContacts) vault.chatContacts = [];
    if (!vault.chatContacts.find(c => c.username === fromUsername)) {
      vault.chatContacts.push({ username: fromUsername, domain: fromDomain || "lsocial.org", encPubKey });
      await saveVault();
    }
    try { await api.request(`/api/notifications/${notif.id}`, { method: "DELETE" }); } catch {}
    setChatRequests(prev => prev.filter(r => r.id !== notif.id));
    await openConversation(fromUsername);
  };

  const dismissChatRequest = async (id) => {
    try { await api.request(`/api/notifications/${id}`, { method: "DELETE" }); } catch {}
    setChatRequests(prev => prev.filter(r => r.id !== id));
  };

  // ── Group chat functions ──

  const decryptGroupKey = async (encryptedKeyB64, keyIvB64, creatorUsername) => {
    if (!identity) return null;
    // Try vault key first (creator's own key)
    try {
      const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(keyIvB64) }, identity.vaultKey, fromB64(encryptedKeyB64));
      return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    } catch {}
    // Try ECDH with creator's public key (invited member)
    if (creatorUsername) {
      try {
        let encPubKey = getEncPubKey(creatorUsername);
        if (!encPubKey) {
          const profile = await api.request(`/api/profile/${creatorUsername}`);
          encPubKey = profile.encryptionPublicKey;
        }
        if (encPubKey) {
          const sharedKey = await deriveConversationKey(identity.encryption.privateKey, encPubKey);
          const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(keyIvB64) }, sharedKey, fromB64(encryptedKeyB64));
          return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
        }
      } catch {}
    }
    return null;
  };

  const decryptGroupName = async (nameEncrypted, nameIv, gKey) => {
    try {
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(nameIv) }, gKey, fromB64(nameEncrypted));
      return dec.decode(plain);
    } catch { return "Group"; }
  };

  const openGroup = async (group) => {
    setActive(null); setActiveGroup(group.id); setGroupMessages([]); setLoading(true);
    const gKey = await decryptGroupKey(group.encryptedKey, group.keyIv, group.creator);
    if (!gKey) { setLoading(false); return; }
    setGroupKey(gKey);
    const name = await decryptGroupName(group.nameEncrypted, group.nameIv, gKey);
    setGroupName(name);
    try {
      const data = await api.request(`/api/groups/${group.id}`);
      setGroupMembers(data.members || []);
    } catch {}
    try {
      const { messages: raw } = await api.request(`/api/groups/${group.id}/messages`);
      const decrypted = [];
      for (const m of raw) {
        const content = await decryptChatMessage(m.encryptedContent, m.iv, gKey);
        if (!content) { decrypted.push({ ...m, text: "[Decryption failed]", photos: [], videos: [] }); }
        else { decrypted.push({ ...m, text: content.text || "", photos: content.photos || [], videos: content.videos || [] }); }
      }
      setGroupMessages(decrypted);
    } catch (err) { console.error("[group-load]", err); }
    setLoading(false);
  };

  // Poll group messages
  useEffect(() => {
    if (!activeGroup || !groupKey) return;
    const poll = async () => {
      try {
        const { messages: raw } = await api.request(`/api/groups/${activeGroup}/messages`);
        const decrypted = [];
        for (const m of raw) {
          const content = await decryptChatMessage(m.encryptedContent, m.iv, groupKey);
          if (!content) { decrypted.push({ ...m, text: "[Decryption failed]", photos: [], videos: [] }); }
          else { decrypted.push({ ...m, text: content.text || "", photos: content.photos || [], videos: content.videos || [] }); }
        }
        setGroupMessages(decrypted);
      } catch {}
    };
    const interval = setInterval(poll, 5000);
    return () => clearInterval(interval);
  }, [activeGroup, groupKey]);

  const sendGroupMessage = async () => {
    if ((!newMsg.trim() && groupChatPhotos.length === 0 && groupChatVideos.length === 0) || !activeGroup || !groupKey) return;
    setSending(true);
    try {
      const photoRefs = [];
      for (let i = 0; i < groupChatPhotos.length; i++) {
        setGroupSendStatus(`Encrypting photo ${i + 1}/${groupChatPhotos.length}...`);
        const raw = new Uint8Array(await groupChatPhotos[i].file.arrayBuffer());
        const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw));
        const combined = new Uint8Array(12 + ct.length); combined.set(iv); combined.set(ct, 12);
        const hash = await computeHashClient(combined);
        setGroupSendStatus(`Uploading photo ${i + 1}/${groupChatPhotos.length}...`);
        const formData = new FormData();
        formData.append("file", new Blob([combined], { type: "application/octet-stream" }), `gphoto-${i}.enc`);
        const uploadRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: formData });
        if (!uploadRes.ok) throw new Error("Photo upload failed");
        const rawKey = await crypto.subtle.exportKey("raw", key);
        photoRefs.push({ hash, key: toB64(new Uint8Array(rawKey)), iv: toB64(iv), type: groupChatPhotos[i].file.type || "image/jpeg" });
      }
      const videoRefs = [];
      for (let i = 0; i < groupChatVideos.length; i++) {
        setGroupSendStatus(`Encrypting video ${i + 1}/${groupChatVideos.length}...`);
        const raw = new Uint8Array(await groupChatVideos[i].file.arrayBuffer());
        const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw));
        const combined = new Uint8Array(12 + ct.length); combined.set(iv); combined.set(ct, 12);
        const hash = await computeHashClient(combined);
        setGroupSendStatus(`Uploading video ${i + 1}/${groupChatVideos.length}...`);
        const formData = new FormData();
        formData.append("file", new Blob([combined], { type: "application/octet-stream" }), `gvideo-${i}.enc`);
        const uploadRes = await fetch("/api/content/upload", { method: "POST", headers: { "Authorization": `Bearer ${api.token}` }, body: formData });
        if (!uploadRes.ok) throw new Error("Video upload failed");
        const rawKey = await crypto.subtle.exportKey("raw", key);
        videoRefs.push({ hash, key: toB64(new Uint8Array(rawKey)), iv: toB64(iv), type: groupChatVideos[i].file.type || "video/mp4" });
      }
      setGroupSendStatus("");
      const content = { text: newMsg.trim() || null };
      if (photoRefs.length > 0) content.photos = photoRefs;
      if (videoRefs.length > 0) content.videos = videoRefs;
      const { encryptedContent, iv: msgIv } = await encryptChatMessage(content, groupKey);
      const res = await api.request(`/api/groups/${activeGroup}/messages`, {
        method: "POST", body: JSON.stringify({ encryptedContent, iv: msgIv }),
      });
      setGroupMessages(prev => [...prev, { id: res.id, from: currentUser, groupId: activeGroup, text: content.text || "", photos: photoRefs, videos: videoRefs, createdAt: Date.now() }]);
      setNewMsg("");
      groupChatPhotos.forEach(p => URL.revokeObjectURL(p.previewUrl));
      groupChatVideos.forEach(v => URL.revokeObjectURL(v.previewUrl));
      setGroupChatPhotos([]); setGroupChatVideos([]);
    } catch (err) { console.error("[group-send]", err); setGroupSendStatus(""); }
    setSending(false);
  };

  const createGroupChat = async () => {
    if (!newGroupName.trim() || selectedFriends.length === 0 || !identity) return;
    try {
      // Generate random AES group key
      const rawGroupKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const rawKeyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", rawGroupKey));
      // Encrypt group name with group key
      const nameIv = crypto.getRandomValues(new Uint8Array(12));
      const nameCt = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nameIv }, rawGroupKey, enc.encode(newGroupName.trim()));
      // Encrypt group key for each member using their vault key (wrapped with our vault key for self, ECDH for others won't work since we don't have their private key)
      // Approach: encrypt the raw group key with each member's encryption public key via ECDH
      // For self: encrypt with our own vault key
      const members = [];
      // Self
      const selfIv = crypto.getRandomValues(new Uint8Array(12));
      const selfWrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv: selfIv }, identity.vaultKey, rawKeyBytes);
      members.push({ username: currentUser, encryptedKey: toB64(new Uint8Array(selfWrapped)), keyIv: toB64(selfIv) });
      // Other members — wrap with ECDH-derived key
      for (const friend of selectedFriends) {
        const encPubKey = getEncPubKey(friend.username);
        if (!encPubKey) continue;
        const sharedKey = await deriveConversationKey(identity.encryption.privateKey, encPubKey);
        const memberIv = crypto.getRandomValues(new Uint8Array(12));
        const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv: memberIv }, sharedKey, rawKeyBytes);
        members.push({ username: friend.username, encryptedKey: toB64(new Uint8Array(wrapped)), keyIv: toB64(memberIv) });
      }
      const res = await api.request("/api/groups", {
        method: "POST",
        body: JSON.stringify({ nameEncrypted: toB64(new Uint8Array(nameCt)), nameIv: toB64(nameIv), members }),
      });
      // Refresh groups
      const data = await api.request("/api/groups");
      setGroups(data.groups || []);
      setShowCreateGroup(false); setNewGroupName(""); setSelectedFriends([]);
    } catch (err) { console.error("[group-create]", err); alert("Failed to create group: " + err.message); }
  };

  const convPartners = new Set(conversations.map(c => c.partner));
  const friendsForChat = vault?.friends ? Object.entries(vault.friends)
    .filter(([addr, info]) => !info.expired && info.feedKeyB64)
    .map(([addr]) => { const [username, domain] = addr.split("@"); return { username, domain }; })
    .filter(f => !convPartners.has(f.username)) : [];
  const contactsList = (vault?.chatContacts || [])
    .filter(c => !convPartners.has(c.username) && !isFriend(c.username));

  const allFriends = vault?.friends ? Object.entries(vault.friends)
    .filter(([, info]) => !info.expired && info.feedKeyB64)
    .map(([addr]) => { const [username, domain] = addr.split("@"); return { username, domain }; }) : [];

  const showConvList = !isMobile || (!active && !activeGroup);
  const showChat = !isMobile || active || activeGroup;

  const convListPanel = (
    <div style={{ width: isMobile ? "100%" : 280, background: T.bgCard, overflowY: "auto", flexShrink: 0 }}>
      <div style={{ padding: 16, borderBottom: `1px solid ${T.border}` }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
          <h3 style={{ margin: 0, color: T.text, fontSize: 16 }}>Chats</h3>
          <button onClick={() => setShowCreateGroup(true)} style={{ background: "none", border: "none", color: T.accent, cursor: "pointer", fontSize: 12, fontWeight: 600, fontFamily: "inherit" }}>+ Group</button>
        </div>
        <p style={{ margin: "0 0 8px", color: T.textDim, fontSize: 12 }}>End-to-end encrypted</p>
        <div style={{ display: "flex", gap: 6 }}>
          <input value={newChatAddr} onChange={e => setNewChatAddr(e.target.value)} onKeyDown={e => e.key === "Enter" && sendChatRequest()} placeholder="username@lsocial.org"
            style={{ flex: 1, background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 6, padding: "6px 10px", color: T.text, fontSize: 12, outline: "none", fontFamily: "inherit" }} />
          <Btn small onClick={sendChatRequest} disabled={!newChatAddr.includes("@")} style={{ padding: "6px 10px", fontSize: 11 }}>Request</Btn>
        </div>
      </div>

      {chatRequests.length > 0 && (<>
        <div style={{ padding: "10px 16px 6px", color: T.warn, fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>Chat Requests</div>
        {chatRequests.map(n => (
          <div key={n.id} style={{ padding: "10px 16px", display: "flex", gap: 10, alignItems: "center", borderBottom: `1px solid ${T.border}` }}>
            <Avatar username={n.from?.split("@")[0] || "?"} size={32} />
            <div style={{ flex: 1 }}><div style={{ color: T.text, fontSize: 13, fontWeight: 600 }}>{n.from?.split("@")[0]}</div></div>
            <button onClick={() => acceptChatRequest(n)} style={{ background: T.accent, border: "none", color: "#fff", borderRadius: 6, padding: "4px 8px", fontSize: 11, fontWeight: 600, cursor: "pointer" }}>Accept</button>
            <button onClick={() => dismissChatRequest(n.id)} style={{ background: "none", border: "none", color: T.textDim, cursor: "pointer", fontSize: 13 }}>✕</button>
          </div>
        ))}
      </>)}

      {conversations.length > 0 && conversations.map(c => (
        <div key={c.partner} onClick={() => openConversation(c.partner)} style={{
          padding: "14px 16px", cursor: "pointer", display: "flex", gap: 12, alignItems: "center",
          background: active === c.partner ? T.accentDim : "transparent",
          borderLeft: active === c.partner ? `3px solid ${T.accent}` : "3px solid transparent",
        }}>
          <Avatar username={c.partner} size={36} />
          <div style={{ flex: 1, overflow: "hidden" }}>
            <div style={{ fontWeight: 600, color: T.text, fontSize: 14 }}>{getDisplayName(c.partner)}</div>
            <div style={{ color: T.textMuted, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {c.lastMessageFrom === currentUser ? "You: " : ""}message
            </div>
          </div>
        </div>
      ))}

      {friendsForChat.length > 0 && (<>
        <div style={{ padding: "10px 16px 6px", color: T.textDim, fontSize: 11, textTransform: "uppercase", letterSpacing: 1, borderTop: `1px solid ${T.border}` }}>Friends</div>
        {friendsForChat.map(f => (
          <div key={f.username} onClick={() => openConversation(f.username)} style={{
            padding: "10px 16px", cursor: "pointer", display: "flex", gap: 12, alignItems: "center",
            background: active === f.username ? T.accentDim : "transparent",
            borderLeft: active === f.username ? `3px solid ${T.accent}` : "3px solid transparent",
          }}>
            <Avatar username={f.username} size={32} domain={f.domain} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 500, color: T.textMuted, fontSize: 13 }}>{getDisplayName(f.username)}</div>
            </div>
          </div>
        ))}
      </>)}

      {contactsList.length > 0 && (<>
        <div style={{ padding: "10px 16px 6px", color: T.textDim, fontSize: 11, textTransform: "uppercase", letterSpacing: 1, borderTop: `1px solid ${T.border}` }}>Contacts</div>
        {contactsList.map(c => (
          <div key={c.username} onClick={() => openConversation(c.username)} style={{
            padding: "10px 16px", cursor: "pointer", display: "flex", gap: 12, alignItems: "center",
            background: active === c.username ? T.accentDim : "transparent",
            borderLeft: active === c.username ? `3px solid ${T.accent}` : "3px solid transparent",
          }}>
            <Avatar username={c.username} size={32} domain={c.domain} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 500, color: T.textMuted, fontSize: 13 }}>{c.username}</div>
            </div>
          </div>
        ))}
      </>)}

      {groups.length > 0 && (<>
        <div style={{ padding: "10px 16px 6px", color: T.textDim, fontSize: 11, textTransform: "uppercase", letterSpacing: 1, borderTop: `1px solid ${T.border}` }}>Groups</div>
        {groups.map(g => (
          <GroupListItem key={g.id} group={g} activeGroup={activeGroup} onOpen={openGroup} decryptGroupKey={decryptGroupKey} decryptGroupName={decryptGroupName} />
        ))}
      </>)}

      {conversations.length === 0 && friendsForChat.length === 0 && contactsList.length === 0 && chatRequests.length === 0 && groups.length === 0 && (
        <div style={{ padding: 20, color: T.textDim, fontSize: 13, textAlign: "center" }}>Add friends or send a chat request to start</div>
      )}
    </div>
  );

  const chatPanel = (
    <div style={{ flex: 1, background: T.bg, display: "flex", flexDirection: "column", minHeight: isMobile ? "calc(100vh - 200px)" : undefined }}>
      {active ? (<>
        <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", gap: 12, background: T.bgCard }}>
          {isMobile && <button onClick={() => setActive(null)} style={{ background: "none", border: "none", color: T.accent, cursor: "pointer", fontSize: 18, padding: "2px 6px 2px 0" }}>←</button>}
          <Avatar username={active} size={32} clickable />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div onClick={() => navigateToProfile(active, "lsocial.org")} style={{ fontWeight: 600, color: T.text, fontSize: 14, cursor: "pointer" }}>{getDisplayName(active)}</div>
            <div style={{ color: T.textDim, fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>@{active}@lsocial.org · 🔒 E2E</div>
          </div>
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: isMobile ? 12 : 20, display: "flex", flexDirection: "column", gap: 8 }}>
          {loading && <div style={{ color: T.textDim, fontSize: 13, textAlign: "center", padding: 20 }}>Loading messages...</div>}
          {!loading && messages.length === 0 && <div style={{ color: T.textDim, fontSize: 13, textAlign: "center", padding: 20 }}>No messages yet. Say hello!</div>}
          {messages.map(m => (
            <div key={m.id} style={{ alignSelf: m.from === currentUser ? "flex-end" : "flex-start", maxWidth: isMobile ? "85%" : "70%" }}>
              <div style={{
                background: m.from === currentUser ? T.accent : T.bgCard,
                color: m.from === currentUser ? "#fff" : T.text,
                padding: (m.photos?.length || m.videos?.length) ? 4 : "10px 14px", borderRadius: 16,
                borderBottomRightRadius: m.from === currentUser ? 4 : 16,
                borderBottomLeftRadius: m.from !== currentUser ? 4 : 16,
                fontSize: 14, lineHeight: 1.5, overflow: "hidden",
              }}>
                {m.photos?.length > 0 && <ChatMediaGrid refs={m.photos} type="photo" isMobile={isMobile} />}
                {m.videos?.length > 0 && <ChatMediaGrid refs={m.videos} type="video" isMobile={isMobile} />}
                {m.text && <div style={{ padding: (m.photos?.length || m.videos?.length) ? "6px 10px 8px" : 0 }}><Linkify text={m.text} color={m.from === currentUser ? "#fff" : undefined} /></div>}
              </div>
              <div style={{ fontSize: 11, color: T.textDim, marginTop: 4, textAlign: m.from === currentUser ? "right" : "left" }}>
                <TimeAgo ts={m.createdAt} />
              </div>
            </div>
          ))}
          <div ref={endRef} />
        </div>
        <div style={{ borderTop: `1px solid ${T.border}`, background: T.bgCard }}>
          {(chatPhotos.length > 0 || chatVideos.length > 0) && (
            <div style={{ display: "flex", gap: 6, padding: "8px 12px 0", flexWrap: "wrap" }}>
              {chatPhotos.map((p, i) => (
                <div key={`p${i}`} style={{ position: "relative", width: 56, height: 56, borderRadius: 8, overflow: "hidden" }}>
                  <img src={p.previewUrl} alt="" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
                  <button onClick={() => removeChatPhoto(i)} style={{ position: "absolute", top: 1, right: 1, width: 18, height: 18, borderRadius: "50%", background: "rgba(0,0,0,0.7)", border: "none", color: "#fff", fontSize: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
                </div>
              ))}
              {chatVideos.map((v, i) => (
                <div key={`v${i}`} style={{ position: "relative", width: 72, height: 56, borderRadius: 8, overflow: "hidden", background: T.bgHover }}>
                  <video src={v.previewUrl} style={{ width: "100%", height: "100%", objectFit: "cover" }} muted />
                  <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", color: "#fff", fontSize: 18 }}>▶</div>
                  <button onClick={() => removeChatVideo(i)} style={{ position: "absolute", top: 1, right: 1, width: 18, height: 18, borderRadius: "50%", background: "rgba(0,0,0,0.7)", border: "none", color: "#fff", fontSize: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
                </div>
              ))}
            </div>
          )}
          {sendStatus && <div style={{ padding: "4px 12px", fontSize: 11, color: T.accent }}>{sendStatus}</div>}
          <div style={{ padding: isMobile ? 10 : 12, display: "flex", gap: 8, alignItems: "center" }}>
            <button onClick={() => chatMediaRef.current?.click()} style={{ background: "none", border: "none", color: T.textMuted, cursor: "pointer", fontSize: 18, padding: 4 }} title="Attach photos or videos">📎</button>
            <input ref={chatMediaRef} type="file" accept="image/*,video/*" multiple onChange={addChatMedia} style={{ display: "none" }} />
            <input value={newMsg} onChange={e => setNewMsg(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && (e.preventDefault(), sendMessage())}
              placeholder="Type a message..."
              style={{ flex: 1, background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 24, padding: "10px 16px", color: T.text, fontSize: 14, outline: "none", fontFamily: "inherit" }} />
            <Btn onClick={sendMessage} disabled={(!newMsg.trim() && chatPhotos.length === 0 && chatVideos.length === 0) || sending} small style={{ borderRadius: 24 }}>
              {sending ? "..." : "Send"}
            </Btn>
          </div>
        </div>
      </>) : !activeGroup ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: T.textDim, fontSize: 14 }}>
          Select a conversation or start a new chat
        </div>
      ) : null}
    </div>
  );

  const groupChatPanel = (
    <div style={{ flex: 1, background: T.bg, display: "flex", flexDirection: "column", minHeight: isMobile ? "calc(100vh - 200px)" : undefined }}>
      <div style={{ padding: "12px 16px", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", gap: 12, background: T.bgCard }}>
        {isMobile && <button onClick={() => setActiveGroup(null)} style={{ background: "none", border: "none", color: T.accent, cursor: "pointer", fontSize: 18, padding: "2px 6px 2px 0" }}>←</button>}
        <div style={{ width: 32, height: 32, borderRadius: "50%", background: T.accent + "33", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, color: T.accent, fontWeight: 600 }}>G</div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, color: T.text, fontSize: 14 }}>{groupName}</div>
          <div style={{ color: T.textDim, fontSize: 11 }}>{groupMembers.length} members · 🔒 E2E</div>
        </div>
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: isMobile ? 12 : 20, display: "flex", flexDirection: "column", gap: 8 }}>
        {loading && <div style={{ color: T.textDim, fontSize: 13, textAlign: "center", padding: 20 }}>Loading messages...</div>}
        {!loading && groupMessages.length === 0 && <div style={{ color: T.textDim, fontSize: 13, textAlign: "center", padding: 20 }}>No messages yet. Say something!</div>}
        {groupMessages.map(m => (
          <div key={m.id} style={{ alignSelf: m.from === currentUser ? "flex-end" : "flex-start", maxWidth: isMobile ? "85%" : "70%" }}>
            {m.from !== currentUser && <div style={{ fontSize: 11, color: T.accent, marginBottom: 2, fontWeight: 600 }}>{getDisplayName(m.from)}</div>}
            <div style={{
              background: m.from === currentUser ? T.accent : T.bgCard,
              color: m.from === currentUser ? "#fff" : T.text,
              padding: (m.photos?.length || m.videos?.length) ? 4 : "10px 14px", borderRadius: 16,
              borderBottomRightRadius: m.from === currentUser ? 4 : 16,
              borderBottomLeftRadius: m.from !== currentUser ? 4 : 16,
              fontSize: 14, lineHeight: 1.5, overflow: "hidden",
            }}>
              {m.photos?.length > 0 && <ChatMediaGrid refs={m.photos} type="photo" isMobile={isMobile} />}
              {m.videos?.length > 0 && <ChatMediaGrid refs={m.videos} type="video" isMobile={isMobile} />}
              {m.text && <div style={{ padding: (m.photos?.length || m.videos?.length) ? "6px 10px 8px" : 0 }}><Linkify text={m.text} color={m.from === currentUser ? "#fff" : undefined} /></div>}
            </div>
            <div style={{ fontSize: 11, color: T.textDim, marginTop: 4, textAlign: m.from === currentUser ? "right" : "left" }}>
              <TimeAgo ts={m.createdAt} />
            </div>
          </div>
        ))}
        <div ref={groupEndRef} />
      </div>
      <div style={{ borderTop: `1px solid ${T.border}`, background: T.bgCard }}>
        {(groupChatPhotos.length > 0 || groupChatVideos.length > 0) && (
          <div style={{ display: "flex", gap: 6, padding: "8px 12px 0", flexWrap: "wrap" }}>
            {groupChatPhotos.map((p, i) => (
              <div key={`p${i}`} style={{ position: "relative", width: 56, height: 56, borderRadius: 8, overflow: "hidden" }}>
                <img src={p.previewUrl} alt="" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
                <button onClick={() => removeGroupPhoto(i)} style={{ position: "absolute", top: 1, right: 1, width: 18, height: 18, borderRadius: "50%", background: "rgba(0,0,0,0.7)", border: "none", color: "#fff", fontSize: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
              </div>
            ))}
            {groupChatVideos.map((v, i) => (
              <div key={`v${i}`} style={{ position: "relative", width: 72, height: 56, borderRadius: 8, overflow: "hidden", background: T.bgHover }}>
                <video src={v.previewUrl} style={{ width: "100%", height: "100%", objectFit: "cover" }} muted />
                <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", color: "#fff", fontSize: 18 }}>▶</div>
                <button onClick={() => removeGroupVideo(i)} style={{ position: "absolute", top: 1, right: 1, width: 18, height: 18, borderRadius: "50%", background: "rgba(0,0,0,0.7)", border: "none", color: "#fff", fontSize: 10, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
              </div>
            ))}
          </div>
        )}
        {groupSendStatus && <div style={{ padding: "4px 12px", fontSize: 11, color: T.accent }}>{groupSendStatus}</div>}
        <div style={{ padding: isMobile ? 10 : 12, display: "flex", gap: 8, alignItems: "center" }}>
          <button onClick={() => groupMediaRef.current?.click()} style={{ background: "none", border: "none", color: T.textMuted, cursor: "pointer", fontSize: 18, padding: 4 }} title="Attach photos or videos">📎</button>
          <input ref={groupMediaRef} type="file" accept="image/*,video/*" multiple onChange={addGroupMedia} style={{ display: "none" }} />
          <input value={newMsg} onChange={e => setNewMsg(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !e.shiftKey && (e.preventDefault(), sendGroupMessage())}
            placeholder="Type a message..."
            style={{ flex: 1, background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 24, padding: "10px 16px", color: T.text, fontSize: 14, outline: "none", fontFamily: "inherit" }} />
          <Btn onClick={sendGroupMessage} disabled={(!newMsg.trim() && groupChatPhotos.length === 0 && groupChatVideos.length === 0) || sending} small style={{ borderRadius: 24 }}>
            {sending ? "..." : "Send"}
          </Btn>
        </div>
      </div>
    </div>
  );

  const createGroupModal = showCreateGroup ? (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, padding: 20 }} onClick={() => setShowCreateGroup(false)}>
      <div onClick={e => e.stopPropagation()} style={{ background: T.bgCard, borderRadius: 16, padding: 24, maxWidth: 400, width: "100%", maxHeight: "80vh", overflowY: "auto", border: `1px solid ${T.border}` }}>
        <h3 style={{ margin: "0 0 16px", color: T.text, fontSize: 18 }}>New Group Chat</h3>
        <input value={newGroupName} onChange={e => setNewGroupName(e.target.value)} placeholder="Group name"
          style={{ width: "100%", background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: "10px 12px", color: T.text, fontSize: 14, outline: "none", fontFamily: "inherit", marginBottom: 16, boxSizing: "border-box" }} />
        <div style={{ color: T.textDim, fontSize: 12, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>Select friends to invite</div>
        <div style={{ maxHeight: 250, overflowY: "auto", marginBottom: 16 }}>
          {allFriends.map(f => {
            const selected = selectedFriends.some(s => s.username === f.username);
            return (
              <div key={f.username} onClick={() => {
                if (selected) setSelectedFriends(prev => prev.filter(s => s.username !== f.username));
                else setSelectedFriends(prev => [...prev, f]);
              }} style={{ padding: "10px 12px", display: "flex", gap: 10, alignItems: "center", cursor: "pointer", borderRadius: 8, background: selected ? T.accentDim : "transparent", marginBottom: 2 }}>
                <Avatar username={f.username} size={28} domain={f.domain} />
                <div style={{ flex: 1, color: T.text, fontSize: 13 }}>{getDisplayName(f.username)}</div>
                <div style={{ width: 20, height: 20, borderRadius: 4, border: `2px solid ${selected ? T.accent : T.border}`, background: selected ? T.accent : "transparent", display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontSize: 12 }}>
                  {selected && "✓"}
                </div>
              </div>
            );
          })}
          {allFriends.length === 0 && <div style={{ color: T.textDim, fontSize: 13, textAlign: "center", padding: 20 }}>Add friends first to create a group</div>}
        </div>
        {selectedFriends.length > 0 && <div style={{ color: T.textDim, fontSize: 12, marginBottom: 12 }}>{selectedFriends.length} friend{selectedFriends.length !== 1 ? "s" : ""} selected</div>}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <Btn small onClick={() => { setShowCreateGroup(false); setNewGroupName(""); setSelectedFriends([]); }} style={{ background: T.bgHover, color: T.text }}>Cancel</Btn>
          <Btn small onClick={createGroupChat} disabled={!newGroupName.trim() || selectedFriends.length === 0}>Create Group</Btn>
        </div>
      </div>
    </div>
  ) : null;

  if (isMobile) {
    return (<>
      {createGroupModal}
      <div style={{ background: T.border, borderRadius: 12, overflow: "hidden", border: `1px solid ${T.border}` }}>
        {showConvList && convListPanel}
        {showChat && active && chatPanel}
        {showChat && activeGroup && groupChatPanel}
      </div>
    </>);
  }

  return (<>
    {createGroupModal}
    <div style={{ display: "flex", height: "calc(100vh - 120px)", gap: 1, background: T.border, borderRadius: 12, overflow: "hidden", border: `1px solid ${T.border}` }}>
      {convListPanel}
      {active ? chatPanel : activeGroup ? groupChatPanel : chatPanel}
    </div>
  </>);
}

// ============================================================================
// Profile
// ============================================================================
function ProfileView({ isMobile }) {
  const { currentUser } = useApp();
  const [editing, setEditing] = useState(false);
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [saving, setSaving] = useState(false);
  const [uploadingPhoto, setUploadingPhoto] = useState(false);
  const [photoPreview, setPhotoPreview] = useState(null);
  const [cropFile, setCropFile] = useState(null);
  const fileInputRef = useRef(null);
  useEffect(() => {
    if (vault?.displayName) { const parts = vault.displayName.split(" "); setFirstName(parts[0] || ""); setLastName(parts.slice(1).join(" ") || ""); }
    if (vault?.photoHash && identity) { loadAvatar(currentUser, "lsocial.org").then(url => { if (url) setPhotoPreview(url); }); }
  }, []);
  const saveName = async () => { if (!vault) return; setSaving(true); vault.displayName = [firstName.trim(), lastName.trim()].filter(Boolean).join(" ") || null; await saveVault(); setSaving(false); setEditing(false); };
  const handlePhotoSelect = (e) => { const file = e.target.files?.[0]; if (!file) return; setCropFile(file); e.target.value = ""; };
  const handleCropDone = async (thumbBlob, originalFile) => {
    setCropFile(null); if (!identity) return; setUploadingPhoto(true);
    try {
      const { thumbHash, fullHash } = await uploadAvatar(thumbBlob, originalFile, identity.feedKey);
      vault.photoHash = thumbHash; vault.fullPhotoHash = fullHash; await saveVault();
      avatarCache.delete(`${currentUser}@lsocial.org`);
      const url = await loadAvatar(currentUser, "lsocial.org"); if (url) setPhotoPreview(url);
      // Send updated photo hash to all friends
      for (const addr of Object.keys(vault.friends || {})) {
        const friendInfo = vault.friends[addr]; if (!friendInfo?.encPubKey) continue;
        try {
          const friendUser = addr.split("@")[0];
          const toUsername = /^[a-f0-9]{64}$/.test(friendUser) ? friendUser : await hashUsername(friendUser);
          const keyPayload = await encryptFeedKeyForFriend(identity.feedKeyB64, identity.encryption.privateKey, friendInfo.encPubKey, vault.displayName || null, vault.photoHash, vault.fullPhotoHash, window._currentUser);
          await api.request("/api/key-exchange", { method: "POST", body: JSON.stringify({ toUsername, encryptedPayload: keyPayload }) });
        } catch (err) { console.warn(`[photo-update] Key exchange failed for ${addr}:`, err); }
      }
    }
    catch (err) { console.error("[photo]", err); } setUploadingPhoto(false);
  };
  return (
    <div>
      <div style={{ background: T.bgCard, borderRadius: 12, padding: isMobile ? 16 : 24, border: `1px solid ${T.border}`, marginBottom: 16 }}>
        <div style={{ display: "flex", flexDirection: isMobile ? "column" : "row", gap: isMobile ? 16 : 20, alignItems: isMobile ? "center" : "flex-start" }}>
          <div style={{ position: "relative", cursor: "pointer" }} onClick={() => fileInputRef.current?.click()}>
            {photoPreview ? <img src={photoPreview} alt={currentUser} style={{ width: 72, height: 72, borderRadius: "50%", objectFit: "cover" }} /> : <Avatar username={currentUser} size={72} />}
            <div style={{ position: "absolute", bottom: 0, right: 0, width: 24, height: 24, borderRadius: "50%", background: T.accent, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, color: "#fff", border: `2px solid ${T.bgCard}` }}>📷</div>
            <input ref={fileInputRef} type="file" accept="image/*" onChange={handlePhotoSelect} style={{ display: "none" }} />
            {uploadingPhoto && <div style={{ position: "absolute", top: 0, left: 0, width: 72, height: 72, borderRadius: "50%", background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontSize: 11 }}>Uploading...</div>}
          </div>
          <div style={{ flex: 1, minWidth: 0, width: isMobile ? "100%" : undefined, textAlign: isMobile ? "center" : undefined }}>
            <h2 style={{ margin: 0, color: T.text, fontSize: isMobile ? 20 : undefined }}>{vault?.displayName || currentUser}</h2>
            <div style={{ color: T.textMuted, fontSize: 14, marginTop: 2 }}>@{currentUser}@lsocial.org</div>
            {identity && <div style={{ marginTop: 16, padding: "12px 16px", background: T.accentDim, borderRadius: 8, fontSize: isMobile ? 11 : 13, color: T.accent, overflowWrap: "break-word", wordBreak: "break-all", textAlign: "left" }}>🔑 Fingerprint: <code style={{ background: T.bgHover, padding: "2px 6px", borderRadius: 4 }}>{identity.fingerprint}</code></div>}
            <div style={{ marginTop: 16 }}>
              {!editing ? (
                <div>
                  <div style={{ color: T.textMuted, fontSize: 13, marginBottom: 4 }}>Display name: <span style={{ color: T.text }}>{vault?.displayName || "Not set"}</span><span style={{ color: T.textDim, fontSize: 11, marginLeft: 6 }}>(only visible to friends)</span></div>
                  <Btn variant="ghost" small onClick={() => setEditing(true)}>Edit name</Btn>
                </div>
              ) : (
                <div>
                  <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                    <div style={{ flex: 1 }}><label style={{ color: T.textMuted, fontSize: 12, marginBottom: 4, display: "block" }}>First name</label><input value={firstName} onChange={e => setFirstName(e.target.value)} placeholder="First" style={{ width: "100%", background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: "8px 12px", color: T.text, fontSize: 14, outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} /></div>
                    <div style={{ flex: 1 }}><label style={{ color: T.textMuted, fontSize: 12, marginBottom: 4, display: "block" }}>Last name</label><input value={lastName} onChange={e => setLastName(e.target.value)} placeholder="Last" style={{ width: "100%", background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: "8px 12px", color: T.text, fontSize: 14, outline: "none", fontFamily: "inherit", boxSizing: "border-box" }} /></div>
                  </div>
                  <div style={{ display: "flex", gap: 8 }}><Btn small onClick={saveName} disabled={saving}>{saving ? "Saving..." : "Save"}</Btn><Btn variant="ghost" small onClick={() => setEditing(false)}>Cancel</Btn></div>
                  <div style={{ color: T.textDim, fontSize: 11, marginTop: 6 }}>Your name is encrypted and only shared with friends.</div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      {cropFile && <PhotoCropModal file={cropFile} onCrop={handleCropDone} onCancel={() => setCropFile(null)} />}
    </div>
  );
}

// ============================================================================
// Settings
// ============================================================================
function SettingsView() {
  const { currentUser } = useApp();
  const [health, setHealth] = useState(null);
  const [rotating, setRotating] = useState(false);
  const [rotatePassword, setRotatePassword] = useState("");
  const [rotateError, setRotateError] = useState("");
  const [rotateStatus, setRotateStatus] = useState("");
  const [showRotate, setShowRotate] = useState(false);
  const [changingPw, setChangingPw] = useState(false);
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPwConfirm, setNewPwConfirm] = useState("");
  const [pwStatus, setPwStatus] = useState("");
  const [pwError, setPwError] = useState("");
  const [pwLoading, setPwLoading] = useState(false);

  useEffect(() => { api.request("/api/health").then(setHealth).catch(() => {}); }, []);

  const rotateFeedKey = async () => {
    if (!identity || !vault || !rotatePassword) { setRotateError("Password required"); return; }
    setRotating(true); setRotateError(""); setRotateStatus("Verifying password...");
    try {
      const oldKeys = await deriveAllKeys(currentUser, rotatePassword, "lsocial.org", identity.feedKeyVersion);
      if (oldKeys.fingerprint !== identity.fingerprint) { setRotateError("Wrong password"); setRotating(false); setRotateStatus(""); return; }

      const newFeedKeyVersion = (vault.feedKeyVersion || 1) + 1;
      setRotateStatus("Deriving new feed key...");
      const newKeys = await deriveAllKeys(currentUser, rotatePassword, "lsocial.org", newFeedKeyVersion);

      // Save old feed key in vault for decrypting old posts
      if (!vault.previousFeedKeys) vault.previousFeedKeys = [];
      vault.previousFeedKeys.push({ version: identity.feedKeyVersion, feedKeyB64: identity.feedKeyB64 });

      setRotateStatus("Updating vault...");
      vault.feedKeyVersion = newFeedKeyVersion;
      const newVaultStr = await encryptVault(vault, newKeys.vaultKey);

      setRotateStatus("Updating server...");
      const res = await api.request("/api/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          newSigningPublicKey: newKeys.signingPublicKeyB64,
          newEncryptionPublicKey: newKeys.encryptionPublicKeyB64,
          newFingerprint: newKeys.fingerprint,
          newFeedKeyVersion,
          newVault: newVaultStr,
        }),
      });

      api.token = res.token;

      // Re-encrypt avatar with new feed key
      if (vault.photoHash || vault.fullPhotoHash) {
        setRotateStatus("Re-encrypting avatar...");
        try {
          if (vault.photoHash) {
            const newHash = await reEncryptContent(vault.photoHash, identity.feedKey, newKeys.feedKey);
            if (newHash) vault.photoHash = newHash;
          }
          if (vault.fullPhotoHash) {
            const newHash = await reEncryptContent(vault.fullPhotoHash, identity.feedKey, newKeys.feedKey);
            if (newHash) vault.fullPhotoHash = newHash;
          }
        } catch (err) { console.warn("[rotate] Avatar re-encryption failed:", err); }
      }

      identity = newKeys;

      setRotateStatus("Sending new feed key to friends...");
      let sent = 0;
      const failed = [];
      // Deduplicate friends - avoid sending to both plaintext and hash entries for the same person
      const sentToHashes = new Set();
      for (const addr of Object.keys(vault.friends || {})) {
        const friendInfo = vault.friends[addr];
        const friendUser = addr.split("@")[0];
        const friendHash = /^[a-f0-9]{64}$/.test(friendUser) ? friendUser : await hashUsername(friendUser);
        if (sentToHashes.has(friendHash)) continue;
        // Fetch encPubKey from server if missing in vault
        let encPubKey = friendInfo?.encPubKey;
        if (!encPubKey) {
          try {
            const profile = await api.request(`/api/profile/${friendHash}`);
            if (profile.encryptionPublicKey) {
              encPubKey = profile.encryptionPublicKey;
              vault.friends[addr].encPubKey = encPubKey;
            }
          } catch {}
        }
        if (!encPubKey) { failed.push(addr); continue; }
        try {
          const toUsername = friendHash;
          const keyPayload = await encryptFeedKeyForFriend(newKeys.feedKeyB64, newKeys.encryption.privateKey, encPubKey, vault.displayName || null, vault.photoHash || null, vault.fullPhotoHash || null, window._currentUser);
          await api.request("/api/key-exchange", { method: "POST", body: JSON.stringify({ toUsername, encryptedPayload: keyPayload }) });
          sentToHashes.add(friendHash);
          sent++;
        } catch (err) { console.warn(`[rotate] Key exchange failed for ${addr}:`, err); failed.push(addr); }
      }

      // Track friends who didn't receive the new key for retry on next login
      if (failed.length > 0) {
        vault.pendingKeyRotations = failed.map(addr => ({ addr, createdAt: Date.now() }));
      } else {
        delete vault.pendingKeyRotations;
      }

      await saveVault();
      try { await saveTrustedSession(currentUser, newKeys); } catch {}

      setRotateStatus(""); setShowRotate(false); setRotatePassword("");
      const failMsg = failed.length > 0 ? ` ${failed.length} friend${failed.length !== 1 ? "s" : ""} could not be reached and will be retried automatically.` : "";
      alert(`Feed key rotated to version ${newFeedKeyVersion}. New key sent to ${sent} friend${sent !== 1 ? "s" : ""}.${failMsg} Old posts remain readable with the old key.`);
    } catch (err) {
      console.error("[rotate]", err);
      setRotateError(err.message || "Rotation failed");
      setRotateStatus("");
    }
    setRotating(false);
  };

  const handleChangePassword = async () => {
    if (!oldPw || !newPw) { setPwError("Both passwords required"); return; }
    const v = validatePassword(newPw);
    if (!v.valid) { setPwError(v.issues.find(i => i.type === "error")?.text); return; }
    if (newPw !== newPwConfirm) { setPwError("New passwords don't match"); return; }
    if (oldPw === newPw) { setPwError("New password must be different"); return; }
    setPwLoading(true); setPwError(""); setPwStatus("Verifying old password...");
    try {
      const oldKeys = await deriveAllKeys(currentUser, oldPw, "lsocial.org", identity.feedKeyVersion);
      if (oldKeys.fingerprint !== identity.fingerprint) { setPwError("Old password is incorrect"); setPwLoading(false); setPwStatus(""); return; }
      setPwStatus("Deriving new keys...");
      const newFeedKeyVersion = (vault.feedKeyVersion || 1) + 1;
      const newKeys = await deriveAllKeys(currentUser, newPw, "lsocial.org", newFeedKeyVersion);
      setPwStatus("Re-encrypting vault...");
      const oldVault = { ...vault }; oldVault.feedKeyVersion = newFeedKeyVersion;
      // Save old feed key for decrypting old posts
      if (!oldVault.previousFeedKeys) oldVault.previousFeedKeys = [];
      oldVault.previousFeedKeys.push({ version: identity.feedKeyVersion, feedKeyB64: identity.feedKeyB64 });
      const newVaultStr = await encryptVault(oldVault, newKeys.vaultKey);
      setPwStatus("Updating server...");
      const res = await api.request("/api/auth/change-password", { method: "POST", body: JSON.stringify({ newSigningPublicKey: newKeys.signingPublicKeyB64, newEncryptionPublicKey: newKeys.encryptionPublicKeyB64, newFingerprint: newKeys.fingerprint, newFeedKeyVersion, newVault: newVaultStr }) });
      api.token = res.token; vault = oldVault;
      // Re-encrypt avatar with new feed key
      if (vault.photoHash || vault.fullPhotoHash) {
        setPwStatus("Re-encrypting avatar...");
        try {
          if (vault.photoHash) {
            const newHash = await reEncryptContent(vault.photoHash, identity.feedKey, newKeys.feedKey);
            if (newHash) vault.photoHash = newHash;
          }
          if (vault.fullPhotoHash) {
            const newHash = await reEncryptContent(vault.fullPhotoHash, identity.feedKey, newKeys.feedKey);
            if (newHash) vault.fullPhotoHash = newHash;
          }
        } catch (err) { console.warn("[pw-change] Avatar re-encryption failed:", err); }
      }
      identity = newKeys;
      setPwStatus("Sending new feed key to friends...");
      let sent = 0;
      for (const addr of Object.keys(vault.friends || {})) {
        const friendInfo = vault.friends[addr]; if (!friendInfo?.encPubKey) continue;
        try {
          const friendUser = addr.split("@")[0];
          const toUsername = /^[a-f0-9]{64}$/.test(friendUser) ? friendUser : await hashUsername(friendUser);
          const keyPayload = await encryptFeedKeyForFriend(newKeys.feedKeyB64, newKeys.encryption.privateKey, friendInfo.encPubKey, vault.displayName || null, vault.photoHash || null, vault.fullPhotoHash || null, window._currentUser);
          await api.request("/api/key-exchange", { method: "POST", body: JSON.stringify({ toUsername, encryptedPayload: keyPayload }) });
          sent++;
        } catch (err) { console.warn(`[pw-change] Key exchange failed for ${addr}:`, err); }
      }
      await saveVault();
      try { await saveTrustedSession(currentUser, newKeys); } catch {}
      setPwStatus(""); setChangingPw(false); setOldPw(""); setNewPw(""); setNewPwConfirm("");
      alert(`Password changed successfully. New feed key sent to ${sent} friend${sent !== 1 ? "s" : ""}.`);
    } catch (err) { console.error("[pw-change]", err); setPwError(err.message || "Password change failed"); setPwStatus(""); }
    setPwLoading(false);
  };

  const inputStyle = { width: "100%", background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: "10px 14px", color: T.text, fontSize: 14, outline: "none", fontFamily: "inherit", boxSizing: "border-box" };

  return (
    <div>
      <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, marginBottom: 12, border: `1px solid ${T.border}` }}>
        <h3 style={{ margin: "0 0 6px", color: T.text, fontSize: 16 }}>Identity</h3>
        <p style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.5, marginBottom: 12 }}>All keys derived deterministically from your password. No key storage needed.</p>
        {identity ? (
          <div style={{ background: T.accentDim, borderRadius: 8, padding: 12 }}>
            <div style={{ color: T.accent, fontSize: 13, fontWeight: 600 }}>🔑 Identity active</div>
            <div style={{ color: T.textMuted, fontSize: 12, marginTop: 2 }}>Fingerprint: <code style={{ background: T.bgHover, padding: "2px 6px", borderRadius: 4 }}>{identity.fingerprint}</code></div>
            <div style={{ color: T.textMuted, fontSize: 12, marginTop: 2 }}>Feed key version: {identity.feedKeyVersion}</div>
          </div>
        ) : <div style={{ color: T.textDim, fontSize: 13 }}>No identity loaded.</div>}
      </div>

      <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, marginBottom: 12, border: `1px solid ${T.border}` }}>
        <h3 style={{ margin: "0 0 6px", color: T.text, fontSize: 16 }}>Feed Key</h3>
        <p style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.5, marginBottom: 12 }}>Rotate your feed key if you suspect it has been shared without your permission. Old posts remain readable with the old key. New posts will use the new key.</p>
        {!showRotate ? (
          <Btn variant="ghost" small onClick={() => setShowRotate(true)}>Rotate Feed Key</Btn>
        ) : (
          <div>
            <label style={{ color: T.textMuted, fontSize: 12, marginBottom: 4, display: "block" }}>Enter your password to confirm</label>
            <input type="password" value={rotatePassword} onChange={e => setRotatePassword(e.target.value)} onKeyDown={e => e.key === "Enter" && rotateFeedKey()} placeholder="Your current password" style={{ ...inputStyle, marginBottom: 8 }} />
            {rotateError && <div style={{ color: T.danger, fontSize: 13, marginBottom: 8 }}>{rotateError}</div>}
            {rotateStatus && <div style={{ color: T.accent, fontSize: 13, marginBottom: 8 }}>{rotateStatus}</div>}
            <div style={{ display: "flex", gap: 8 }}>
              <Btn small onClick={rotateFeedKey} disabled={!rotatePassword || rotating}>{rotating ? rotateStatus || "Rotating..." : "Rotate"}</Btn>
              <Btn variant="ghost" small onClick={() => { setShowRotate(false); setRotatePassword(""); setRotateError(""); setRotateStatus(""); }}>Cancel</Btn>
            </div>
          </div>
        )}
      </div>

      <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, marginBottom: 12, border: `1px solid ${T.border}` }}>
        <h3 style={{ margin: "0 0 6px", color: T.text, fontSize: 16 }}>Change Password</h3>
        <p style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.5, marginBottom: 12 }}>Changing your password generates new keys. Your friends will receive your new feed key automatically.</p>
        {!changingPw ? (
          <Btn variant="ghost" small onClick={() => setChangingPw(true)}>Change Password</Btn>
        ) : (
          <div>
            <label style={{ color: T.textMuted, fontSize: 12, marginBottom: 4, display: "block" }}>Current password</label>
            <input type="password" value={oldPw} onChange={e => setOldPw(e.target.value)} placeholder="Enter current password" style={{ ...inputStyle, marginBottom: 12 }} />
            <label style={{ color: T.textMuted, fontSize: 12, marginBottom: 4, display: "block" }}>New password</label>
            <input type="password" value={newPw} onChange={e => setNewPw(e.target.value)} placeholder="At least 15 characters" style={inputStyle} />
            <PasswordStrengthMeter password={newPw} />
            <label style={{ color: T.textMuted, fontSize: 12, marginBottom: 4, display: "block", marginTop: 12 }}>Confirm new password</label>
            <input type="password" value={newPwConfirm} onChange={e => setNewPwConfirm(e.target.value)} onKeyDown={e => e.key === "Enter" && handleChangePassword()} placeholder="Type it again" style={inputStyle} />
            {newPwConfirm && newPw !== newPwConfirm && <div style={{ color: T.danger, fontSize: 12, marginTop: 4 }}>Passwords don't match</div>}
            {pwError && <div style={{ color: T.danger, fontSize: 13, marginTop: 8 }}>{pwError}</div>}
            {pwStatus && <div style={{ color: T.accent, fontSize: 13, marginTop: 8 }}>{pwStatus}</div>}
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <Btn small onClick={handleChangePassword} disabled={!oldPw || !validatePassword(newPw).valid || newPw !== newPwConfirm || pwLoading}>{pwLoading ? pwStatus || "Changing..." : "Change Password"}</Btn>
              <Btn variant="ghost" small onClick={() => { setChangingPw(false); setOldPw(""); setNewPw(""); setNewPwConfirm(""); setPwError(""); setPwStatus(""); }}>Cancel</Btn>
            </div>
          </div>
        )}
      </div>

      <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, marginBottom: 12, border: `1px solid ${T.border}` }}>
        <h3 style={{ margin: "0 0 6px", color: T.text, fontSize: 16 }}>Security</h3>
        <p style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.5, marginBottom: 12 }}>PBKDF2-SHA256 (600k iterations) · HKDF key derivation · ECDSA P-256 signing · ECDH P-256 key exchange · AES-256-GCM encryption · Bloom filter feed privacy</p>
        <div style={{ color: T.warn, fontSize: 12 }}>⚠️ If you forget your password, your account cannot be recovered.</div>
      </div>

      <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, marginBottom: 12, border: `1px solid ${T.border}` }}>
        <h3 style={{ margin: "0 0 6px", color: T.text, fontSize: 16 }}>Server</h3>
        <div style={{ fontSize: 13, color: T.textMuted }}>
          Status: {health ? <span style={{ color: T.success }}>● online</span> : <span style={{ color: T.warn }}>● checking</span>}
          {health && ` · ${health.storage?.contentFiles || 0} content files · Uptime: ${Math.floor(health.uptime)}s`}
        </div>
      </div>

      <div style={{ background: T.bgCard, borderRadius: 12, padding: 20, border: "1px solid rgba(255,74,74,0.2)" }}>
        <h3 style={{ margin: "0 0 6px", color: T.text, fontSize: 16 }}>Danger Zone</h3>
        <div style={{ marginBottom: 16 }}>
          <p style={{ color: T.textMuted, fontSize: 14, marginBottom: 8, lineHeight: 1.5 }}>
            <strong style={{ color: T.danger }}>Emergency key revocation</strong> — If your account is compromised, immediately revoke all previous keys. Friends who haven't received your new key will need to re-friend you.
          </p>
          <Btn variant="danger" small onClick={async () => {
            if (!confirm("Are you sure? This will immediately invalidate all previous keys. Friends who haven't updated will lose access and need to re-friend you.")) return;
            try { await api.request("/api/auth/revoke-keys", { method: "POST" }); alert("All previous keys revoked."); } catch (err) { alert("Revocation failed: " + err.message); }
          }}>Revoke All Previous Keys</Btn>
        </div>
        <div>
          <p style={{ color: T.textMuted, fontSize: 14, marginBottom: 8 }}>Permanently delete your account.</p>
          <Btn variant="danger" small>Delete Account</Btn>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Auth
// ============================================================================
function AuthScreen({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [loadingText, setLoadingText] = useState("");
  const [captchaToken, setCaptchaToken] = useState(null);
  const [captchaSolving, setCaptchaSolving] = useState(false);
  const [captchaStatus, setCaptchaStatus] = useState("");
  const [trustDevice, setTrustDevice] = useState(false);
  const captchaRef = useRef(null);

  useEffect(() => {
    if (!document.querySelector('script[src*="cap.js/widget"]')) {
      const script = document.createElement("script"); script.src = "https://cdn.jsdelivr.net/npm/@cap.js/widget"; script.async = true; document.head.appendChild(script);
    }
  }, []);

  useEffect(() => {
    if (mode !== "register") return;
    const interval = setInterval(() => {
      const widget = document.querySelector("cap-widget");
      if (widget && !captchaRef.current) {
        captchaRef.current = widget;
        widget.addEventListener("solve", (e) => { setCaptchaToken(e.detail.token); setCaptchaSolving(false); setCaptchaStatus("Verified!"); });
        widget.addEventListener("error", (e) => { console.error("[captcha] Error:", e.detail); setCaptchaStatus("Failed — try again"); });
        clearInterval(interval);
      }
    }, 200);
    return () => clearInterval(interval);
  }, [mode]);

  const handleRegister = async () => {
    if (!username.trim()) { setError("Username required"); return; }
    const v = validatePassword(password); if (!v.valid) { setError(v.issues.find(i => i.type === "error")?.text); return; }
    if (password !== passwordConfirm) { setError("Passwords don't match"); return; }
    if (!captchaToken) { setError("Please complete the CAPTCHA first"); return; }
    setLoading(true); setError(null); setLoadingText("Deriving keys...");
    try {
      // Key derivation uses plaintext username (client-side only, never sent to server)
      const keys = await deriveAllKeys(username, password, "lsocial.org", 1);
      setLoadingText("Computing identity hash...");
      const uHash = await hashUsername(username);
      setLoadingText("Registering...");
      // Only send the hash — plaintext username never leaves the client
      const res = await api.request("/api/auth/register", { method: "POST", body: JSON.stringify({ usernameHash: uHash, signingPublicKey: keys.signingPublicKeyB64, encryptionPublicKey: keys.encryptionPublicKeyB64, fingerprint: keys.fingerprint, captchaToken }) });
      api.token = res.token; identity = keys; identity.usernameHash = uHash;
      const displayName = [firstName.trim(), lastName.trim()].filter(Boolean).join(" ") || null;
      vault = { friends: {}, feedKeyVersion: 1, displayName };
      await saveVault();
      onLogin(username, trustDevice);
    } catch (err) { setError(err.message || "Registration failed"); setCaptchaToken(null); setCaptchaStatus(""); }
    setLoading(false);
  };

  const handleLogin = async () => {
    if (!username.trim() || !password) { setError("Username and password required"); return; }
    setLoading(true); setError(null); setLoadingText("Computing identity hash...");
    try {
      const uHash = await hashUsername(username);
      // Try profile lookup by hash first, then plaintext (for unmigrated users)
      let feedKeyVersion = 1;
      let loginIdentifier = uHash;
      try { const profile = await api.request(`/api/profile/${uHash}`); feedKeyVersion = profile.feedKeyVersion || 1; }
      catch {
        try { const profile = await api.request(`/api/profile/${username}`); feedKeyVersion = profile.feedKeyVersion || 1; loginIdentifier = username; }
        catch {}
      }
      setLoadingText("Deriving keys...");
      const keys = await deriveAllKeys(username, password, "lsocial.org", feedKeyVersion);
      setLoadingText("Authenticating...");
      // Authenticate using whichever identifier the server knows
      const { nonce } = await api.request("/api/auth/challenge", { method: "POST", body: JSON.stringify({ username: loginIdentifier }) });
      const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.signing.privateKey, enc.encode(nonce));
      const res = await api.request("/api/auth/verify", { method: "POST", body: JSON.stringify({ username: loginIdentifier, signature: toB64(new Uint8Array(sig)) }) });
      api.token = res.token; identity = keys;
      identity.usernameHash = uHash;
      // If user still has plaintext username in DB, migrate to hash
      if (loginIdentifier !== uHash || (res.user?.username && res.user.username !== uHash)) {
        setLoadingText("Migrating identity...");
        try {
          const migrateRes = await api.request("/api/migrate-identity", { method: "POST", body: JSON.stringify({ usernameHash: uHash }) });
          // Migration returns a new token since the username changed
          if (migrateRes.token) api.token = migrateRes.token;
        } catch (err) { console.warn("[migrate]", err); }
      }
      setLoadingText("Loading vault...");
      await loadVault(); await buildVaultHashCache(); await processKeyExchanges(); await processFriendAccepted(); await retryPendingKeyRotations();
      onLogin(username, trustDevice);
    } catch (err) { console.error("[auth]", err); setError("Login failed — wrong password or user not found."); }
    setLoading(false);
  };

  const inputStyle = { width: "100%", background: T.bgInput, border: `1px solid ${T.border}`, borderRadius: 8, padding: "12px 14px", color: T.text, fontSize: 15, outline: "none", fontFamily: "inherit", boxSizing: "border-box" };

  return (
    <div style={{ minHeight: "100vh", background: T.bg, display: "flex", alignItems: "center", justifyContent: "center", padding: 20, fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }}>
      <div style={{ maxWidth: 440, width: "100%", textAlign: "center" }}>
        <h1 style={{ color: T.text, fontSize: 32, marginBottom: 4 }}><span style={{ color: T.accent }}>libera</span>social</h1>
        <p style={{ color: T.textMuted, marginBottom: 32, fontSize: 15, lineHeight: 1.6 }}>Decentralized. Encrypted. No algorithm.</p>
        <div style={{ background: T.bgCard, borderRadius: 16, padding: 28, border: `1px solid ${T.border}`, textAlign: "left" }}>
          <div style={{ display: "flex", marginBottom: 20, background: T.bgHover, borderRadius: 8, padding: 3 }}>
            {["login", "register"].map(m => (
              <button key={m} onClick={() => { setMode(m); setError(null); setPassword(""); setPasswordConfirm(""); }}
                style={{ flex: 1, padding: "8px 0", border: "none", borderRadius: 6, background: mode === m ? T.accent : "transparent", color: mode === m ? "#fff" : T.textMuted, fontWeight: 600, fontSize: 14, cursor: "pointer" }}>
                {m === "login" ? "Sign In" : "Create Account"}
              </button>
            ))}
          </div>

          <label style={{ color: T.textMuted, fontSize: 13, marginBottom: 6, display: "block" }}>Username</label>
          <input value={username} onChange={e => setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, ""))} placeholder="yourname" style={{ ...inputStyle, marginBottom: 4 }} />
          {mode === "register" && <div style={{ color: T.textDim, fontSize: 12, marginBottom: 12 }}>{username && <span>{username}@lsocial.org <span style={{ color: T.textDim, fontSize: 11 }}>(public identity will be hashed)</span></span>}</div>}
          {mode === "login" && <div style={{ marginBottom: 12 }} />}

          {mode === "register" && (
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <div style={{ flex: 1 }}><label style={{ color: T.textMuted, fontSize: 13, marginBottom: 6, display: "block" }}>First name <span style={{ color: T.textDim }}>(optional)</span></label><input value={firstName} onChange={e => setFirstName(e.target.value)} placeholder="First" style={inputStyle} /></div>
              <div style={{ flex: 1 }}><label style={{ color: T.textMuted, fontSize: 13, marginBottom: 6, display: "block" }}>Last name <span style={{ color: T.textDim }}>(optional)</span></label><input value={lastName} onChange={e => setLastName(e.target.value)} placeholder="Last" style={inputStyle} /></div>
            </div>
          )}

          <label style={{ color: T.textMuted, fontSize: 13, marginBottom: 6, display: "block" }}>Password</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === "Enter" && mode === "login" && handleLogin()}
            placeholder={mode === "register" ? "At least 15 characters" : "Enter your password"} style={inputStyle} />
          {mode === "register" && <PasswordStrengthMeter password={password} />}

          {mode === "register" && (<>
            <label style={{ color: T.textMuted, fontSize: 13, marginBottom: 6, display: "block", marginTop: 16 }}>Confirm password</label>
            <input type="password" value={passwordConfirm} onChange={e => setPasswordConfirm(e.target.value)} onKeyDown={e => e.key === "Enter" && handleRegister()} placeholder="Type it again" style={inputStyle} />
            {passwordConfirm && password !== passwordConfirm && <div style={{ color: T.danger, fontSize: 12, marginTop: 4 }}>Passwords don't match</div>}
            <div style={{ marginTop: 16 }}>
              <cap-widget data-cap-api-endpoint="/api/captcha/" style={{ width: "100%" }} />
              {captchaToken && <div style={{ color: T.success, fontSize: 12, marginTop: 6 }}>✓ Proof-of-work verified</div>}
            </div>
          </>)}

          {error && <div style={{ color: T.danger, fontSize: 13, marginTop: 12 }}>{error}</div>}

          <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12, cursor: "pointer", color: T.textMuted, fontSize: 13 }}>
            <input type="checkbox" checked={trustDevice} onChange={e => setTrustDevice(e.target.checked)} style={{ accentColor: T.accent, width: 16, height: 16, cursor: "pointer" }} />
            Trust this device <span style={{ color: T.textDim, fontSize: 11 }}>(stay logged in until you sign out)</span>
          </label>

          {mode === "register" ? (
            <Btn onClick={handleRegister} disabled={!username.trim() || !validatePassword(password).valid || password !== passwordConfirm || !captchaToken || loading} style={{ width: "100%", marginTop: 20, padding: 14 }}>{loading ? loadingText : "Create Account"}</Btn>
          ) : (
            <Btn onClick={handleLogin} disabled={!username.trim() || !password || loading} style={{ width: "100%", marginTop: 16, padding: 14 }}>{loading ? loadingText : "Sign In"}</Btn>
          )}
          <p style={{ color: T.textDim, fontSize: 12, marginTop: 12, textAlign: "center", lineHeight: 1.5 }}>
            {mode === "register" ? "Your password derives all keys locally. It is never sent to the server." : "Your password re-derives keys on any device. Nothing stored locally."}
          </p>
        </div>
        <div style={{ marginTop: 24, display: "flex", justifyContent: "center", gap: 16, flexWrap: "wrap" }}>
          {["Open Source", "AGPL-3.0", "E2E Encrypted", "No Algorithm", "Bloom Filter Privacy"].map(t => (
            <span key={t} style={{ color: T.textDim, fontSize: 12, background: T.bgCard, padding: "4px 10px", borderRadius: 20, border: `1px solid ${T.border}` }}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Sidebar + App
// ============================================================================
const NAV = [
  { id: "feed", label: "Feed", icon: "📡" }, { id: "messages", label: "Chats", icon: "💬" },
  { id: "friends", label: "Friends", icon: "👥" }, { id: "profile", label: "Profile", icon: "👤" },
  { id: "settings", label: "Settings", icon: "⚙️" },
];

function Sidebar({ active, onNav, onLogout, isMobile }) {
  const { currentUser } = useApp();
  const [menuOpen, setMenuOpen] = useState(false);

  const handleNav = (id) => { onNav(id); setMenuOpen(false); };

  if (isMobile) {
    return (
      <>
        <div style={{ position: "sticky", top: 0, zIndex: 100, background: T.bgCard, borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px" }}>
          <h2 style={{ margin: 0, fontSize: 18, color: T.text }}><span style={{ color: T.accent }}>libera</span>social</h2>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ color: T.textMuted, fontSize: 13 }}>{NAV.find(n => n.id === active)?.icon} {NAV.find(n => n.id === active)?.label}</span>
            <button onClick={() => setMenuOpen(!menuOpen)} style={{ background: "none", border: "none", color: T.text, fontSize: 24, cursor: "pointer", padding: "2px 4px", lineHeight: 1 }}>{menuOpen ? "✕" : "☰"}</button>
          </div>
        </div>
        {menuOpen && (
          <>
            <div onClick={() => setMenuOpen(false)} style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.5)", zIndex: 199 }} />
            <div style={{ position: "fixed", top: 0, right: 0, width: "min(280px, 80vw)", height: "100vh", background: T.bgCard, zIndex: 200, display: "flex", flexDirection: "column", boxShadow: "-4px 0 20px rgba(0,0,0,0.4)" }}>
              <div style={{ padding: "16px", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <h2 style={{ margin: 0, fontSize: 18, color: T.text }}><span style={{ color: T.accent }}>libera</span>social</h2>
                <button onClick={() => setMenuOpen(false)} style={{ background: "none", border: "none", color: T.textMuted, fontSize: 22, cursor: "pointer", padding: "2px 6px" }}>✕</button>
              </div>
              <nav style={{ flex: 1, padding: "8px 8px", overflowY: "auto" }}>
                {NAV.map(n => (
                  <button key={n.id} onClick={() => handleNav(n.id)} style={{ display: "flex", alignItems: "center", gap: 12, width: "100%", padding: "12px 12px", border: "none", borderRadius: 8, cursor: "pointer", background: active === n.id ? T.accentDim : "transparent", color: active === n.id ? T.accent : T.textMuted, fontSize: 15, fontWeight: active === n.id ? 600 : 400, textAlign: "left", marginBottom: 2 }}>
                    <span style={{ fontSize: 20 }}>{n.icon}</span>{n.label}
                  </button>
                ))}
              </nav>
              <div style={{ padding: 16, borderTop: `1px solid ${T.border}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                  <Avatar username={currentUser} size={32} />
                  <div><div style={{ color: T.text, fontSize: 13, fontWeight: 600 }}>{currentUser}</div><div style={{ color: T.textDim, fontSize: 11 }}>@{currentUser}@lsocial.org</div></div>
                </div>
                <div style={{ fontSize: 11, color: T.textDim }}><span style={{ color: T.success }}>●</span> Connected</div>
                <button onClick={onLogout} style={{ display: "block", marginTop: 10, background: "none", border: "none", color: T.textDim, cursor: "pointer", fontSize: 12, padding: 0 }}>Sign out</button>
              </div>
            </div>
          </>
        )}
      </>
    );
  }

  return (
    <div style={{ width: 220, background: T.bgCard, borderRight: `1px solid ${T.border}`, display: "flex", flexDirection: "column", flexShrink: 0, height: "100vh", position: "fixed", top: 0, left: 0, zIndex: 100 }}>
      <div style={{ padding: "20px 16px 12px" }}><h2 style={{ margin: 0, fontSize: 18, color: T.text }}><span style={{ color: T.accent }}>libera</span>social</h2><div style={{ color: T.textDim, fontSize: 11, marginTop: 2 }}>Encrypted · Federated</div></div>
      <nav style={{ flex: 1, padding: "8px 8px" }}>
        {NAV.map(n => (
          <button key={n.id} onClick={() => onNav(n.id)} style={{ display: "flex", alignItems: "center", gap: 12, width: "100%", padding: "10px 12px", border: "none", borderRadius: 8, cursor: "pointer", background: active === n.id ? T.accentDim : "transparent", color: active === n.id ? T.accent : T.textMuted, fontSize: 14, fontWeight: active === n.id ? 600 : 400, textAlign: "left", marginBottom: 2 }}>
            <span style={{ fontSize: 18 }}>{n.icon}</span>{n.label}
          </button>
        ))}
      </nav>
      <div style={{ padding: 16, borderTop: `1px solid ${T.border}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <Avatar username={currentUser} size={32} />
          <div><div style={{ color: T.text, fontSize: 13, fontWeight: 600 }}>{currentUser}</div><div style={{ color: T.textDim, fontSize: 11 }}>@{currentUser}@lsocial.org</div></div>
        </div>
        <div style={{ fontSize: 11, color: T.textDim }}><span style={{ color: T.success }}>●</span> Connected</div>
        <button onClick={onLogout} style={{ display: "block", marginTop: 10, background: "none", border: "none", color: T.textDim, cursor: "pointer", fontSize: 12, padding: 0 }}>Sign out</button>
      </div>
    </div>
  );
}

export default function App() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [currentUser, setCurrentUser] = useState("");
  const [view, setView] = useState("feed");
  const [restoring, setRestoring] = useState(true);
  const [profileTarget, setProfileTarget] = useState(null); // { username, domain }
  const isMobile = useIsMobile();

  const navigateToProfile = (username, domain) => {
    setProfileTarget({ username, domain: domain || "lsocial.org" });
    setView("user-profile");
  };

  useEffect(() => {
    (async () => {
      try {
        const session = await restoreTrustedSession();
        if (session) {
          api.token = session.token; identity = session.keys; window._currentUser = session.username; setCurrentUser(session.username);
          // Ensure usernameHash is computed
          if (!identity.usernameHash) {
            identity.usernameHash = await hashUsername(session.username);
          }
          const uHash = identity.usernameHash;
          try { const h = await api.request("/api/health"); cachedUserCount = h.users || 0; } catch {
            // Re-auth: try hash first, fall back to plaintext username
            try { const newToken = await reAuthWithCachedKeys(uHash, session.keys.signing.privateKey); api.token = newToken; await saveTrustedSession(session.username, session.keys); }
            catch {
              try { const newToken = await reAuthWithCachedKeys(session.username, session.keys.signing.privateKey); api.token = newToken; await saveTrustedSession(session.username, session.keys); }
              catch { api.token = null; identity = null; await deviceStore.clear(); setRestoring(false); return; }
            }
          }
          // Migrate plaintext username to hash if needed
          try {
            const migrateRes = await api.request("/api/migrate-identity", { method: "POST", body: JSON.stringify({ usernameHash: uHash }) });
            if (migrateRes.token) { api.token = migrateRes.token; await saveTrustedSession(session.username, session.keys); }
          } catch {}
          await loadVault(); await buildVaultHashCache(); await processKeyExchanges(); await processFriendAccepted(); await retryPendingKeyRotations(); setLoggedIn(true);
        }
      } catch {}
      setRestoring(false);
    })();
  }, []);

  const handleLogin = (u, trusted) => { setCurrentUser(u); window._currentUser = u; setLoggedIn(true); if (trusted) saveTrustedSession(u, identity); };
  const handleLogout = async () => { api.token = null; identity = null; vault = null; window._currentUser = null; avatarCache.clear(); await deviceStore.clear(); setLoggedIn(false); };

  // Periodically process key exchanges while logged in
  const [vaultVersion, setVaultVersion] = useState(0);
  useEffect(() => {
    if (!loggedIn) return;
    const interval = setInterval(async () => {
      try {
        const updated = await processKeyExchanges();
        await processFriendAccepted();
        await retryPendingKeyRotations();
        if (updated) setVaultVersion(v => v + 1);
      } catch {}
    }, 30000);
    return () => clearInterval(interval);
  }, [loggedIn]);

  if (restoring) return (
    <div style={{ minHeight: "100vh", background: T.bg, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }}>
      <div style={{ textAlign: "center" }}><h1 style={{ color: T.text, fontSize: 24, marginBottom: 8 }}><span style={{ color: T.accent }}>libera</span>social</h1><div style={{ color: T.textDim, fontSize: 14 }}>Restoring session...</div></div>
    </div>
  );

  if (!loggedIn) return <AuthScreen onLogin={handleLogin} />;

  const views = { feed: <FeedView isMobile={isMobile} />, messages: <DMView isMobile={isMobile} />, friends: <FriendsView />, profile: <ProfileView isMobile={isMobile} />, settings: <SettingsView />, "user-profile": profileTarget ? <UserProfileView username={profileTarget.username} domain={profileTarget.domain} onBack={() => setView("feed")} /> : <FeedView isMobile={isMobile} /> };
  return (
    <AppCtx.Provider value={{ currentUser, navigateToProfile, vaultVersion }}>
      <div style={{ minHeight: "100vh", background: T.bg, color: T.text, fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }}>
        <Sidebar active={view} onNav={setView} onLogout={handleLogout} isMobile={isMobile} />
        <main style={{ marginLeft: isMobile ? 0 : 220, width: isMobile ? "100%" : "calc(100vw - 220px)", padding: isMobile ? "16px 12px" : "24px 15%", boxSizing: "border-box" }}>
          <div style={{ marginBottom: isMobile ? 14 : 20 }}>
            <h1 style={{ margin: 0, fontSize: isMobile ? 20 : 22, color: T.text }}>{view === "user-profile" && profileTarget ? profileTarget.username : NAV.find(n => n.id === view)?.label}</h1>
            {view === "feed" && <p style={{ margin: "4px 0 0", color: T.textDim, fontSize: 13 }}>Chronological. From your friends. That's it.</p>}
          </div>
          {views[view]}
        </main>
      </div>
    </AppCtx.Provider>
  );
}
