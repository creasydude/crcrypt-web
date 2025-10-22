// src/crypto.js
// Offline-only crypto utilities using Web Crypto AES-GCM 256 and PBKDF2-SHA256.
// No persistence, no network, no side effects beyond returned values.

import { toHex, fromHex } from "./utils/hex.js";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");

export const DEFAULTS = Object.freeze({
  saltLength: 32,
  ivLength: 12,        // AES-GCM recommended 96-bit IV
  iterations: 310000,  // PBKDF2 iterations
  keyLength: 32        // 32 bytes = 256 bits
});

function ensureWebCrypto() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error("Web Crypto API not available in this environment");
  }
}

function utf8Encode(str) {
  return enc.encode(str);
}

function utf8Decode(bytes) {
  return dec.decode(bytes);
}

/**
 * Generate secure random bytes.
 * @param {number} length
 * @returns {Uint8Array}
 */
export function randomBytes(length) {
  ensureWebCrypto();
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("randomBytes length must be a positive integer");
  }
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/**
 * Validate AES-GCM parameter constraints for interoperability and security.
 * @param {{keyLength:number, ivLength:number}} params
 */
function validateAesGcmParams({ keyLength, ivLength }) {
  if (keyLength !== 32) {
    throw new Error("AES-256-GCM requires a 32-byte key length");
  }
  if (ivLength !== 12) {
    throw new Error("AES-GCM requires a 12-byte IV length");
  }
}

/**
 * Derive an AES-GCM CryptoKey using PBKDF2-SHA256.
 * @param {string} password
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @param {number} keyLength - bytes (must be 32 for AES-256-GCM)
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKeyPBKDF2(password, salt, iterations = DEFAULTS.iterations, keyLength = DEFAULTS.keyLength) {
  ensureWebCrypto();
  if (typeof password !== "string" || password.trim() === "") {
    throw new Error("Password must not be empty");
  }
  if (!(salt instanceof Uint8Array)) {
    throw new Error("Salt must be a Uint8Array");
  }
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new Error("Iterations must be a positive integer");
  }
  if (keyLength !== 32) {
    throw new Error("AES-256-GCM requires a 32-byte key length");
  }

  const baseKey = await globalThis.crypto.subtle.importKey(
    "raw",
    utf8Encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  const derivedKey = await globalThis.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable for security
    ["encrypt", "decrypt"]
  );

  return derivedKey;
}

/**
 * Encrypt plaintext with AES-GCM 256. Returns hex format: salt:iv:ciphertext:tag
 * @param {string} plaintext
 * @param {string} password
 * @param {{saltLength?:number, ivLength?:number, iterations?:number, keyLength?:number}} opts
 * @returns {Promise<string>}
 */
export async function encryptText(plaintext, password, opts = {}) {
  ensureWebCrypto();
  const {
    saltLength = DEFAULTS.saltLength,
    ivLength = DEFAULTS.ivLength,
    iterations = DEFAULTS.iterations,
    keyLength = DEFAULTS.keyLength
  } = opts;

  validateAesGcmParams({ keyLength, ivLength });

  if (typeof plaintext !== "string" || plaintext.trim() === "") {
    throw new Error("Plaintext cannot be empty");
  }
  if (typeof password !== "string" || password.trim() === "") {
    throw new Error("Password cannot be empty");
  }

  const salt = randomBytes(Number(saltLength));
  const iv = randomBytes(Number(ivLength));
  const key = await deriveKeyPBKDF2(password, salt, Number(iterations), Number(keyLength));

  const ptBytes = utf8Encode(plaintext);
  let cipherBuf;
  try {
    cipherBuf = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      ptBytes
    );
  } finally {
    // Zeroize plaintext bytes ASAP
    wipeBytes(ptBytes);
  }

  const all = new Uint8Array(cipherBuf);
  const TAG_LEN = 16; // bytes (128-bit tag)
  if (all.length < TAG_LEN) {
    wipeBytes(all);
    throw new Error("Encryption failed: ciphertext too short");
  }

  const cipherLen = all.length - TAG_LEN;
  const ciphertext = all.slice(0, cipherLen);
  const tag = all.slice(cipherLen);

  const out = `${toHex(salt)}:${toHex(iv)}:${toHex(ciphertext)}:${toHex(tag)}`;

  // Hygiene: zeroize intermediates
  wipeBytes(all);
  wipeBytes(ciphertext);
  wipeBytes(tag);
  // CryptoKey cannot be directly zeroized; drop reference
  // (garbage collector will reclaim memory)
  return out;
}

/**
 * Decrypt ciphertext string in format salt:iv:ciphertext:tag with AES-GCM 256.
 * @param {string} encString
 * @param {string} password
 * @param {{iterations?:number, keyLength?:number}} opts
 * @returns {Promise<string>}
 */
export async function decryptText(encString, password, opts = {}) {
  ensureWebCrypto();
  const {
    iterations = DEFAULTS.iterations,
    keyLength = DEFAULTS.keyLength
  } = opts;

  if (typeof encString !== "string" || encString.trim() === "") {
    throw new Error("Encrypted input cannot be empty");
  }
  if (typeof password !== "string" || password.trim() === "") {
    throw new Error("Password cannot be empty");
  }

  const parts = encString.split(":");
  if (parts.length !== 4) {
    throw new Error("Invalid format. Expected salt:iv:ciphertext:tag");
  }

  const [saltHex, ivHex, cipherHex, tagHex] = parts.map(s => s.trim());
  const salt = fromHex(saltHex);
  const iv = fromHex(ivHex);
  const ciphertext = fromHex(cipherHex);
  const tag = fromHex(tagHex);

  validateAesGcmParams({ keyLength: Number(keyLength), ivLength: iv.length });

  const joined = new Uint8Array(ciphertext.length + tag.length);
  joined.set(ciphertext, 0);
  joined.set(tag, ciphertext.length);

  try {
    const key = await deriveKeyPBKDF2(password, salt, Number(iterations), Number(keyLength));
    const buf = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      joined
    );
    const ptBytes = new Uint8Array(buf);
    const plaintext = utf8Decode(ptBytes);

    // Hygiene: zeroize intermediates
    wipeBytes(ptBytes);
    wipeBytes(salt);
    wipeBytes(iv);
    wipeBytes(ciphertext);
    wipeBytes(tag);
    wipeBytes(joined);

    return plaintext;
  } catch (err) {
    // Hygiene on failure too
    wipeBytes(salt);
    wipeBytes(iv);
    wipeBytes(ciphertext);
    wipeBytes(tag);
    wipeBytes(joined);

    // Keep error generic to avoid leaking specifics
    if (err && (err.name === "OperationError" || err instanceof DOMException)) {
      throw new Error("Decryption failed: wrong password or corrupted input");
    }
    if (err instanceof Error) {
      throw new Error(err.message);
    }
    throw new Error("Decryption failed");
  }
}

/**
 * Zeroize bytes in-place (Uint8Array or ArrayBuffer).
 * @param {Uint8Array|ArrayBuffer|null|undefined} bytes
 */
export function wipeBytes(bytes) {
  if (!bytes) return;
  if (bytes instanceof ArrayBuffer) {
    const view = new Uint8Array(bytes);
    view.fill(0);
    return;
  }
  if (bytes.buffer instanceof ArrayBuffer) {
    bytes.fill(0);
  }
}

/**
 * Drop references to CryptoKey (cannot be directly zeroized).
 * @param {CryptoKey} key
 */
export function wipeKey(_key) {
  // Intentionally empty: ensure no retained references in user code.
  // CryptoKey is non-extractable and will be reclaimed by GC.
}