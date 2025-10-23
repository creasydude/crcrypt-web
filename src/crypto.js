// src/crypto.js
// Offline-only crypto utilities supporting AES-CBC and AES-GCM (128/192/256) via Web Crypto with PBKDF2-SHA256.
// No persistence, no network, no side effects beyond returned values.

import { toHex, fromHex } from "./utils/hex.js";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");

export const ALGORITHMS = Object.freeze({
  AES_GCM: "AES-GCM",
  AES_CBC: "AES-CBC"
});

export const DEFAULTS = Object.freeze({
  algorithm: ALGORITHMS.AES_CBC,
  saltLength: 32,
  ivLength: 16,        // AES-CBC requires 128-bit IV
  iterations: 100000,  // PBKDF2 iterations
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
function validateCipherParams({ algorithm, keyLength, ivLength }) {
  const validKeyLens = [16, 24, 32]; // AES-128/192/256
  if (!validKeyLens.includes(Number(keyLength))) {
    throw new Error("AES requires a 16, 24, or 32-byte key length");
  }
  if (algorithm === "AES-GCM") {
    if (ivLength !== 12) {
      throw new Error("AES-GCM requires a 12-byte IV length");
    }
  } else if (algorithm === "AES-CBC") {
    if (ivLength !== 16) {
      throw new Error("AES-CBC requires a 16-byte IV length");
    }
  } else {
    throw new Error("Unsupported algorithm");
  }
}

/**
 * PKCS#7 padding for AES block size (16 bytes).
 * Creates a new Uint8Array with appropriate padding applied.
 * @param {Uint8Array} data
 * @param {number} blockSize
 * @returns {Uint8Array}
 */
function pkcs7Pad(data, blockSize = 16) {
  const rem = data.length % blockSize;
  const padLen = rem === 0 ? blockSize : (blockSize - rem);
  const out = new Uint8Array(data.length + padLen);
  out.set(data, 0);
  out.fill(padLen, data.length);
  return out;
}

/**
 * Remove PKCS#7 padding. Throws on invalid padding.
 * @param {Uint8Array} data
 * @param {number} blockSize
 * @returns {Uint8Array}
 */
function pkcs7Unpad(data, blockSize = 16) {
  if (!data || data.length === 0) {
    throw new Error("Invalid padding");
  }
  const padLen = data[data.length - 1];
  if (padLen <= 0 || padLen > blockSize || padLen > data.length) {
    throw new Error("Invalid padding");
  }
  const start = data.length - padLen;
  for (let i = start; i < data.length; i++) {
    if (data[i] !== padLen) {
      throw new Error("Invalid padding");
    }
  }
  return data.slice(0, start);
}

/**
 * Derive an AES-GCM CryptoKey using PBKDF2-SHA256.
 * @param {string} password
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @param {number} keyLength - bytes (must be 32 for AES-256-GCM)
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKeyPBKDF2(
  password,
  salt,
  iterations = DEFAULTS.iterations,
  keyLength = DEFAULTS.keyLength,
  algorithm = DEFAULTS.algorithm
) {
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
  const validKeyLens = [16, 24, 32];
  if (!validKeyLens.includes(Number(keyLength))) {
    throw new Error("AES requires a 16, 24, or 32-byte key length");
  }

  // Import password for PBKDF2 deriveBits
  const baseKey = await globalThis.crypto.subtle.importKey(
    "raw",
    utf8Encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  // Derive raw key material (bytes) for AES-256
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    keyLength * 8 // 256 bits
  );

  const keyMaterial = new Uint8Array(bits);

  // Import raw key material as AES key (CBC by default via DEFAULTS)
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    keyMaterial,
    { name: algorithm },
    false, // non-extractable
    ["encrypt", "decrypt"]
  );

  // Hygiene: zeroize key material buffer
  wipeBytes(keyMaterial);

  return cryptoKey;
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

  // Use provided options or defaults
  const algorithm = opts.algorithm || DEFAULTS.algorithm;
  const saltLength = opts.saltLength || DEFAULTS.saltLength;
  const ivLength = opts.ivLength || DEFAULTS.ivLength;
  const iterations = opts.iterations || DEFAULTS.iterations;
  const keyLength = opts.keyLength || DEFAULTS.keyLength;

  validateCipherParams({ algorithm, keyLength, ivLength });

  if (typeof plaintext !== "string" || plaintext.trim() === "") {
    throw new Error("Plaintext cannot be empty");
  }
  if (typeof password !== "string" || password.trim() === "") {
    throw new Error("Password cannot be empty");
  }

  const salt = randomBytes(Number(saltLength));
  const iv = randomBytes(Number(ivLength));
  const key = await deriveKeyPBKDF2(password, salt, Number(iterations), Number(keyLength), algorithm);

  const ptBytes = utf8Encode(plaintext);
  let out;

  if (algorithm === "AES-GCM") {
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

    out = `${toHex(salt)}:${toHex(iv)}:${toHex(ciphertext)}:${toHex(tag)}`;

    // Hygiene: zeroize intermediates
    wipeBytes(all);
    wipeBytes(ciphertext);
    wipeBytes(tag);
  } else {
    // AES-CBC with PKCS#7 padding
    let padded = pkcs7Pad(ptBytes, 16);
    // Zeroize plaintext ASAP
    wipeBytes(ptBytes);

    const cipherBuf = await globalThis.crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      key,
      padded
    );

    // Hygiene: zeroize padded bytes
    wipeBytes(padded);

    const ciphertext = new Uint8Array(cipherBuf);
    out = `${toHex(salt)}:${toHex(iv)}:${toHex(ciphertext)}`;

    // Hygiene: zeroize intermediates
    wipeBytes(ciphertext);
  }

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
  const iterations = Number.isInteger(opts.iterations) ? Number(opts.iterations) : DEFAULTS.iterations;
  // keyLength hint is optional; auto-detection will try 32, 24, then 16 if not provided

  if (typeof encString !== "string" || encString.trim() === "") {
    throw new Error("Encrypted input cannot be empty");
  }
  if (typeof password !== "string" || password.trim() === "") {
    throw new Error("Password cannot be empty");
  }

  const parts = encString.split(":");
  if (parts.length !== 3 && parts.length !== 4) {
    throw new Error("Invalid format. Expected salt:iv:ciphertext or salt:iv:ciphertext:tag");
  }

  const [saltHex, ivHex, cipherHex, tagHex] = parts.map(s => s.trim());
  const salt = fromHex(saltHex);
  const iv = fromHex(ivHex);

  // Auto-detect algorithm: 4 parts => AES-GCM (ciphertext + tag), 3 parts => AES-CBC
  const algorithm = (parts.length === 4) ? "AES-GCM" : "AES-CBC";

  // Build candidate key lengths (use hint first if provided)
  const keyHint = Number(opts.keyLength);
  const keyCandidates = [32, 24, 16].filter((k) => k !== keyHint);
  const keyOrder = Number.isInteger(keyHint) ? [keyHint, ...keyCandidates] : [32, 24, 16];

  // Validate IV length against algorithm using first candidate key length
  validateCipherParams({ algorithm, keyLength: keyOrder[0], ivLength: iv.length });

  try {
    // Pre-parse ciphertext (and tag if present) once
    const ciphertext = fromHex(cipherHex);
    const tag = algorithm === "AES-GCM" ? fromHex(tagHex) : undefined;

    for (const klen of keyOrder) {
      try {
        validateCipherParams({ algorithm, keyLength: Number(klen), ivLength: iv.length });

        const key = await deriveKeyPBKDF2(
          password,
          salt,
          Number(iterations),
          Number(klen),
          algorithm
        );

        if (algorithm === "AES-GCM") {
          const joined = new Uint8Array(ciphertext.length + (tag ? tag.length : 0));
          joined.set(ciphertext, 0);
          if (tag) joined.set(tag, ciphertext.length);

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
          if (tag) wipeBytes(tag);
          wipeBytes(joined);

          return plaintext;
        } else {
          // AES-CBC - try without unpadding first (CLI doesn't use PKCS#7)
          try {
            const buf = await globalThis.crypto.subtle.decrypt(
              { name: "AES-CBC", iv },
              key,
              ciphertext
            );
            const ptBytes = new Uint8Array(buf);
            const plaintext = utf8Decode(ptBytes);

            // Hygiene: zeroize intermediates
            wipeBytes(ptBytes);
            wipeBytes(salt);
            wipeBytes(iv);
            wipeBytes(ciphertext);

            return plaintext;
          } catch (e) {
            // If that fails, try with PKCS#7 unpadding
            const buf = await globalThis.crypto.subtle.decrypt(
              { name: "AES-CBC", iv },
              key,
              ciphertext
            );
            const padded = new Uint8Array(buf);
            const ptBytes = pkcs7Unpad(padded, 16);
            const plaintext = utf8Decode(ptBytes);

            // Hygiene: zeroize intermediates
            wipeBytes(ptBytes);
            wipeBytes(padded);
            wipeBytes(salt);
            wipeBytes(iv);
            wipeBytes(ciphertext);

            return plaintext;
          }
        }
      } catch (_inner) {
        // Try next candidate key length
        continue;
      }
    }

    // If all candidates failed
    // Hygiene on failure
    wipeBytes(salt);
    wipeBytes(iv);
    wipeBytes(ciphertext);
    if (tag) wipeBytes(tag);

    throw new Error("Decryption failed: wrong password or mismatched parameters");
  } catch (err) {
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