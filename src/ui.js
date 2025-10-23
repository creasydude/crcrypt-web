// src/ui.js
// UI logic for CRCrypt Web SPA. Zero-persistence, offline-only.
// No storage APIs used; all state is ephemeral in memory.

import { encryptText, decryptText, DEFAULTS } from "./crypto.js";

const $ = (sel) => document.querySelector(sel);
const el = (id) => document.getElementById(id);

// Cached elements
const refs = {
  // Tabs
  tabEncrypt: null,
  tabDecrypt: null,
  encryptPanel: null,
  decryptPanel: null,
  // Encrypt form
  encryptForm: null,
  plaintextInput: null,
  passwordInput: null,
  passwordConfirmInput: null,
  strengthBar: null,
  strengthLabel: null,
  advSaltLen: null,
  advIvLen: null,
  advIterations: null,
  advKeyLen: null,
  advAlgo: null,
  encryptBtn: null,
  cipherOutput: null,
  copyCipherBtn: null,
  // Decrypt form
  decryptForm: null,
  cipherInput: null,
  decryptPasswordInput: null,
  decryptBtn: null,
  plainOutput: null,
  copyPlainBtn: null,
  // Footer
  clearBtn: null,
  // Theme & font controls
  themeRadios: null,
  fontRadios: null,
  // Settings modal
  settingsTrigger: null,
  settingsModal: null,
  settingsClose: null
};

export function initUI() {
  // Bind refs
  refs.tabEncrypt = el("tabEncrypt");
  refs.tabDecrypt = el("tabDecrypt");
  refs.encryptPanel = el("encryptPanel");
  refs.decryptPanel = el("decryptPanel");

  refs.encryptForm = el("encryptForm");
  refs.plaintextInput = el("plaintextInput");
  refs.passwordInput = el("passwordInput");
  refs.passwordConfirmInput = el("passwordConfirmInput");
  refs.strengthBar = el("strengthBar");
  refs.strengthLabel = el("strengthLabel");
  refs.advSaltLen = el("advSaltLen");
  refs.advIvLen = el("advIvLen");
  refs.advIterations = el("advIterations");
  refs.advKeyLen = el("advKeyLen");
  refs.advAlgo = el("advAlgo");
  refs.encryptBtn = el("encryptBtn");
  refs.cipherOutput = el("cipherOutput");
  refs.copyCipherBtn = el("copyCipherBtn");

  refs.decryptForm = el("decryptForm");
  refs.cipherInput = el("cipherInput");
  refs.decryptPasswordInput = el("decryptPasswordInput");
  refs.decryptBtn = el("decryptBtn");
  refs.plainOutput = el("plainOutput");
  refs.copyPlainBtn = el("copyPlainBtn");

  refs.clearBtn = el("clearBtn");

  refs.themeRadios = Array.from(document.querySelectorAll('input[name="theme"]'));
  refs.fontRadios = Array.from(document.querySelectorAll('input[name="fontScale"]'));
  refs.settingsTrigger = el("settingsTrigger");
  refs.settingsModal = el("settingsModal");
  refs.settingsClose = el("settingsClose");

  // Wire events
  refs.tabEncrypt.addEventListener("click", () => handleModeSwitch("encrypt"));
  refs.tabDecrypt.addEventListener("click", () => handleModeSwitch("decrypt"));

  refs.passwordInput.addEventListener("input", () => updateStrengthMeter(refs.passwordInput.value));
  refs.passwordInput.addEventListener("change", () => updateStrengthMeter(refs.passwordInput.value));

  refs.encryptForm.addEventListener("submit", handleEncryptSubmit);
  refs.copyCipherBtn.addEventListener("click", () => copyOutput(refs.cipherOutput.value));

  refs.decryptForm.addEventListener("submit", handleDecryptSubmit);
  refs.copyPlainBtn.addEventListener("click", () => copyOutput(refs.plainOutput.value));

  refs.clearBtn.addEventListener("click", clearAll);

  initThemeToggle();
  initFontSizeControls();
  initAdvancedSettings();
  initSettingsModal();
  registerServiceWorker();

  // Initial strength meter state
  updateStrengthMeter("");
}

function handleModeSwitch(mode) {
  const isEncrypt = mode === "encrypt";

  refs.tabEncrypt.setAttribute("aria-selected", String(isEncrypt));
  refs.tabDecrypt.setAttribute("aria-selected", String(!isEncrypt));

  refs.tabEncrypt.tabIndex = isEncrypt ? 0 : -1;
  refs.tabDecrypt.tabIndex = !isEncrypt ? 0 : -1;

  if (isEncrypt) {
    refs.encryptPanel.hidden = false;
    refs.decryptPanel.hidden = true;
    refs.tabEncrypt.focus();
  } else {
    refs.encryptPanel.hidden = true;
    refs.decryptPanel.hidden = false;
    refs.tabDecrypt.focus();
  }
}

async function handleEncryptSubmit(ev) {
  ev.preventDefault();

  const plaintext = sanitizeInput(refs.plaintextInput.value);
  const password = refs.passwordInput.value ?? "";
  const passwordConfirm = refs.passwordConfirmInput.value ?? "";

  if (plaintext.length === 0) {
    announce("Plaintext cannot be empty");
    refs.plaintextInput.focus();
    return;
  }
  if (password.trim() === "") {
    announce("Password cannot be empty");
    refs.passwordInput.focus();
    return;
  }
  if (password !== passwordConfirm) {
    announce("Passwords must match");
    refs.passwordConfirmInput.setAttribute("aria-invalid", "true");
    refs.passwordConfirmInput.focus();
    return;
  } else {
    refs.passwordConfirmInput.removeAttribute("aria-invalid");
  }

  const { ok, settings, message } = validateAdvancedSettings(readAdvancedSettings());
  if (!ok) {
    announce(message || "Invalid Advanced Settings");
    return;
  }

  // Busy state
  refs.encryptBtn.disabled = true;
  refs.encryptForm.setAttribute("aria-busy", "true");
  refs.encryptBtn.textContent = "Encrypting…";

  try {
    const encString = await encryptText(plaintext, password, settings);
    refs.cipherOutput.value = encString;
    announce("Encryption completed");
  } catch (err) {
    announce(err?.message || "Encryption failed");
  } finally {
    // Hygiene: clear passwords and plaintext fields
    refs.passwordInput.value = "";
    refs.passwordConfirmInput.value = "";
    refs.plaintextInput.value = "";

    refs.encryptBtn.disabled = false;
    refs.encryptForm.removeAttribute("aria-busy");
    refs.encryptBtn.textContent = "Encrypt";
  }
}

async function handleDecryptSubmit(ev) {
  ev.preventDefault();

  const encString = sanitizeInput(refs.cipherInput.value);
  const password = refs.decryptPasswordInput.value ?? "";

  if (encString.length === 0) {
    announce("Encrypted input cannot be empty");
    refs.cipherInput.focus();
    return;
  }
  if (password.trim() === "") {
    announce("Password cannot be empty");
    refs.decryptPasswordInput.focus();
    return;
  }

  const { ok, settings, message } = validateAdvancedSettings(readAdvancedSettings());
  if (!ok) {
    announce(message || "Invalid Advanced Settings");
    return;
  }

  // Busy state
  refs.decryptBtn.disabled = true;
  refs.decryptForm.setAttribute("aria-busy", "true");
  refs.decryptBtn.textContent = "Decrypting…";

  try {
    const plaintext = await decryptText(encString, password, {
      iterations: settings.iterations
    });
    refs.plainOutput.value = plaintext;
    announce("Decryption completed");
  } catch (err) {
    announce(err?.message || "Decryption failed");
  } finally {
    // Hygiene: clear password and enc input
    refs.decryptPasswordInput.value = "";
    refs.cipherInput.value = "";

    refs.decryptBtn.disabled = false;
    refs.decryptForm.removeAttribute("aria-busy");
    refs.decryptBtn.textContent = "Decrypt";
  }
}

function updateStrengthMeter(password) {
  const len = password.length;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);

  let score = 0;
  if (len >= 12) score += 1;
  if (len >= 16) score += 1;
  if (hasLower) score += 1;
  if (hasUpper) score += 1;
  if (hasDigit) score += 1;
  if (hasSymbol) score += 1;

  const pct = Math.min(100, Math.round((score / 6) * 100));
  const label = pct < 34 ? "Weak" : pct < 67 ? "Medium" : "Strong";

  // Update label
  refs.strengthLabel.textContent = `Strength: ${label}`;

  // Update visual bar using discrete classes (CSS additions recommended)
  // Classes: s-0, s-25, s-50, s-75, s-100
  const cls = pct >= 85 ? "s-100" : pct >= 60 ? "s-75" : pct >= 35 ? "s-50" : pct >= 15 ? "s-25" : "s-0";
  refs.strengthBar.classList.remove("s-0", "s-25", "s-50", "s-75", "s-100");
  refs.strengthBar.classList.add(cls);
}

async function copyOutput(text) {
  const trimmed = (text ?? "").trim();
  if (trimmed.length === 0) {
    announce("Nothing to copy");
    return;
  }
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      await navigator.clipboard.writeText(trimmed);
      announce("Copied to clipboard");
    } else {
      // Fallback
      const ta = document.createElement("textarea");
      ta.value = trimmed;
      ta.setAttribute("readonly", "");
      ta.style.position = "absolute";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      announce("Copied to clipboard");
    }
  } catch {
    announce("Copy failed");
  }
}

function clearAll() {
  // Clear form fields
  if (refs.encryptForm) refs.encryptForm.reset();
  if (refs.decryptForm) refs.decryptForm.reset();

  // Explicitly clear outputs
  refs.cipherOutput.value = "";
  refs.plainOutput.value = "";

  // Reset Advanced Settings to defaults
  if (refs.advAlgo) refs.advAlgo.value = "AES-256-CBC";
  refs.advSaltLen.value = String(DEFAULTS.saltLength);
  refs.advIterations.value = String(DEFAULTS.iterations);
  refs.advKeyLen.value = String(DEFAULTS.keyLength);
  
  // Update algorithm settings
  updateAlgorithmSettings();

  // Reset strength meter
  updateStrengthMeter("");

  announce("Cleared all fields and memory references");
}

function initThemeToggle() {
  // Default to system preference: 'system' radio is checked in HTML
  applyTheme(getSelectedRadioValue(refs.themeRadios, "system"));

  refs.themeRadios.forEach((r) => {
    r.addEventListener("change", () => {
      applyTheme(getSelectedRadioValue(refs.themeRadios, "system"));
    });
  });
}

function applyTheme(value) {
  const root = document.documentElement;
  if (value === "light") {
    root.setAttribute("data-theme", "light");
  } else if (value === "dark") {
    root.setAttribute("data-theme", "dark");
  } else {
    // system
    root.removeAttribute("data-theme");
  }
}

function initFontSizeControls() {
  // Default Medium is checked in HTML
  setFontScale(getSelectedRadioValue(refs.fontRadios, "medium"));

  refs.fontRadios.forEach((r) => {
    r.addEventListener("change", () => {
      setFontScale(getSelectedRadioValue(refs.fontRadios, "medium"));
    });
  });
}

function setFontScale(scale) {
  const root = document.documentElement;
  // small | medium | large
  root.setAttribute("data-font", scale);
}

function initAdvancedSettings() {
  // Set initial values
  refs.advSaltLen.value = String(DEFAULTS.saltLength);
  refs.advIvLen.value = String(DEFAULTS.ivLength);
  refs.advIterations.value = String(DEFAULTS.iterations);
  refs.advKeyLen.value = String(DEFAULTS.keyLength);
  if (refs.advAlgo) refs.advAlgo.value = "AES-256-CBC"; // Match CLI default

  try {
    // Enable all settings for encryption
    refs.advSaltLen.disabled = false;
    refs.advIvLen.disabled = false;
    refs.advIterations.disabled = false;
    refs.advKeyLen.disabled = false;
    if (refs.advAlgo) refs.advAlgo.disabled = false;

    // Add algorithm change listener to update IV and key length
    refs.advAlgo.addEventListener("change", updateAlgorithmSettings);
    
    // Initial update based on selected algorithm
    updateAlgorithmSettings();

    // Update helper texts
    const ivHelp = document.getElementById("advIvHelp");
    if (ivHelp) ivHelp.textContent = "AES-CBC requires 16-byte IV, AES-GCM requires 12-byte IV.";
    const iterHelp = document.getElementById("advIterHelp");
    if (iterHelp) iterHelp.textContent = "Default 100k. Higher is slower, more secure. Match CLI config for compatibility.";
  } catch {}
}

function readAdvancedSettings() {
  // Read all settings from UI
  const saltLen = Number.parseInt(refs.advSaltLen.value ?? String(DEFAULTS.saltLength), 10);
  const ivLen = Number.parseInt(refs.advIvLen.value ?? String(DEFAULTS.ivLength), 10);
  const iterStr = refs.advIterations.value ?? String(DEFAULTS.iterations);
  const iterNum = Number.parseInt(iterStr, 10);
  const keyLen = Number.parseInt(refs.advKeyLen.value ?? String(DEFAULTS.keyLength), 10);
  const algo = refs.advAlgo.value ?? "AES-256-CBC";

  // Convert CLI algorithm names to Web Crypto names
  const webAlgo = algo.includes("GCM") ? "AES-GCM" : "AES-CBC";

  return {
    saltLength: Number.isFinite(saltLen) && saltLen > 0 ? saltLen : DEFAULTS.saltLength,
    ivLength: Number.isFinite(ivLen) && ivLen > 0 ? ivLen : DEFAULTS.ivLength,
    iterations: Number.isFinite(iterNum) && iterNum > 0 ? iterNum : DEFAULTS.iterations,
    keyLength: Number.isFinite(keyLen) && keyLen > 0 ? keyLen : DEFAULTS.keyLength,
    algorithm: webAlgo,
    cliAlgorithm: algo // Keep CLI algorithm name for reference
  };
}

function validateAdvancedSettings(_vals) {
  const settings = readAdvancedSettings();
  
  try {
    // Validate salt length
    if (settings.saltLength < 16 || settings.saltLength > 64) {
      refs.advSaltLen.setAttribute("aria-invalid", "true");
      return { ok: false, settings, message: "Salt length must be between 16 and 64 bytes" };
    }
    refs.advSaltLen.removeAttribute("aria-invalid");

    // Validate IV length based on algorithm
    const expectedIvLength = settings.algorithm === "AES-GCM" ? 12 : 16;
    if (settings.ivLength !== expectedIvLength) {
      refs.advIvLen.setAttribute("aria-invalid", "true");
      return { ok: false, settings, message: `${settings.algorithm} requires ${expectedIvLength}-byte IV` };
    }
    refs.advIvLen.removeAttribute("aria-invalid");

    // Validate iterations
    if (settings.iterations < 10000 || settings.iterations > 1000000) {
      refs.advIterations.setAttribute("aria-invalid", "true");
      return { ok: false, settings, message: "Iterations must be between 10,000 and 1,000,000" };
    }
    refs.advIterations.removeAttribute("aria-invalid");

    // Validate key length
    const validKeyLengths = [16, 24, 32];
    if (!validKeyLengths.includes(settings.keyLength)) {
      refs.advKeyLen.setAttribute("aria-invalid", "true");
      return { ok: false, settings, message: "Key length must be 16, 24, or 32 bytes" };
    }
    refs.advKeyLen.removeAttribute("aria-invalid");

    return { ok: true, settings, message: "" };
  } catch {
    return { ok: false, settings, message: "Failed to validate Advanced Settings" };
  }
}

function initSettingsModal() {
  const modal = refs.settingsModal;
  const trigger = refs.settingsTrigger;
  const closeBtn = refs.settingsClose;
  if (!modal || !trigger || !closeBtn) return;

  const container = modal.querySelector(".modal-content") || modal;

  const getFocusable = () => {
    return Array.from(
      container.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
    ).filter((n) => !n.hasAttribute("disabled") && !n.getAttribute("aria-hidden"));
  };

  const restoreBodyScroll = () => { document.body.style.overflow = ""; };
  const preventBodyScroll = () => { document.body.style.overflow = "hidden"; };

  const close = () => {
    modal.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    document.removeEventListener("keydown", onKeyDown);
    document.removeEventListener("click", onDocClick, true);
    modal.removeEventListener("click", onOverlayClick);
    restoreBodyScroll();
    trigger.focus();
  };

  const onKeyDown = (e) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      close();
      return;
    }
    if (e.key === "Tab") {
      const focusables = getFocusable();
      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement;

      if (e.shiftKey) {
        if (active === first || !container.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (active === last || !container.contains(active)) {
          e.preventDefault();
          first.focus();
        }
      }
    }
  };

  const onDocClick = (e) => {
    const t = e.target;
    if (!t) return;
    if (container.contains(t) || trigger.contains(t)) return;
    close();
  };

  const onOverlayClick = (e) => {
    if (e.target === modal) close();
  };

  const open = (e) => {
    if (e) e.preventDefault();
    modal.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    preventBodyScroll();
    const first =
      container.querySelector('input[name="theme"]') ||
      container.querySelector('input[name="fontScale"]') ||
      closeBtn;
    if (first) first.focus();
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("click", onDocClick, true);
    modal.addEventListener("click", onOverlayClick);
  };

  trigger.addEventListener("click", open);
  closeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    close();
  });

  // Close when choosing an option inside modal
  modal.addEventListener("change", (e) => {
    if (e.target && (e.target.name === "theme" || e.target.name === "fontScale")) {
      close();
    }
  });
}

function registerServiceWorker() {
  if ("serviceWorker" in navigator) {
    const isSecure = location.protocol === "https:" || location.hostname === "localhost";
    if (isSecure) {
      navigator.serviceWorker.register("sw.js").catch(() => {
        // Non-fatal; offline still works without SW registration when using file://
      });
    }
  }
}

// Helpers
function getSelectedRadioValue(radios, fallback) {
  const picked = radios.find((r) => r.checked);
  return picked ? picked.value : fallback;
}

function sanitizeInput(text) {
  if (typeof text !== "string") return "";
  return text.trim();
}

function announce(message) {
  // Announce via footer notice for simplicity; avoids storing sensitive data
  const notice = $(".notice");
  if (notice) {
    notice.textContent = message;
  }
}

function updateAlgorithmSettings() {
  const algo = refs.advAlgo.value;
  const isGCM = algo.includes("GCM");
  
  // Update IV length based on algorithm
  const ivLength = isGCM ? 12 : 16;
  refs.advIvLen.value = String(ivLength);
  refs.advIvLen.setAttribute("min", String(ivLength));
  refs.advIvLen.setAttribute("max", String(ivLength));
  refs.advIvLen.setAttribute("step", "1");
  
  // Update key length based on algorithm
  let keyLength = 32; // default to 256
  if (algo.includes("192")) keyLength = 24;
  else if (algo.includes("128")) keyLength = 16;
  
  refs.advKeyLen.value = String(keyLength);
  refs.advKeyLen.setAttribute("min", String(keyLength));
  refs.advKeyLen.setAttribute("max", String(keyLength));
  refs.advKeyLen.setAttribute("step", "1");
  
  // Update helper text
  const ivHelp = document.getElementById("advIvHelp");
  if (ivHelp) {
    ivHelp.textContent = `${algo} requires ${ivLength}-byte IV.`;
  }
  
  const keyHelp = document.getElementById("advKeyHelp");
  if (keyHelp) {
    const bits = keyLength * 8;
    keyHelp.textContent = `${algo} uses ${bits}-bit key (${keyLength} bytes).`;
  }
}

// Boot
initUI();