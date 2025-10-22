// src/utils/hex.js
// Hex utilities for ArrayBuffer/Uint8Array conversion.
// All outputs are lowercase hex strings. No persistence or side effects.

/**
 * Convert an ArrayBuffer or Uint8Array to a lowercase hex string.
 * @param {ArrayBuffer|Uint8Array} input
 * @returns {string}
 */
export function toHex(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  // Pre-allocate char array for performance
  const hexChars = new Array(bytes.length * 2);
  const lut = [];
  for (let i = 0; i < 256; i++) {
    lut[i] = (i < 16 ? "0" : "") + i.toString(16);
  }
  let j = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    const h = lut[b];
    hexChars[j++] = h[0];
    hexChars[j++] = h[1];
  }
  return hexChars.join("");
}

/**
 * Convert a hex string to a Uint8Array.
 * Validates input is even-length and contains only hex characters.
 * @param {string} hex
 * @returns {Uint8Array}
 * @throws {Error} if the hex string is invalid
 */
export function fromHex(hex) {
  if (typeof hex !== "string") {
    throw new Error("Hex input must be a string");
  }
  const trimmed = hex.trim();
  if (trimmed.length === 0) {
    return new Uint8Array(0);
  }
  if ((trimmed.length & 1) === 1) {
    throw new Error("Invalid hex: length must be even");
  }
  // Validate characters
  if (!/^[0-9a-fA-F]+$/.test(trimmed)) {
    throw new Error("Invalid hex: contains non-hex characters");
  }

  const out = new Uint8Array(trimmed.length / 2);
  let o = 0;
  for (let i = 0; i < trimmed.length; i += 2) {
    const byte = parseInt(trimmed.slice(i, i + 2), 16);
    out[o++] = byte;
  }
  return out;
}