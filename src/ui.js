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
  modeIndicator: null,
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
  noticeText: null,
  // Theme & font controls
  themeRadios: null,
  fontRadios: null,
  // Settings modal
  settingsTrigger: null,
  settingsModal: null,
  settingsClose: null,
};

// ── Toast System ──────────────────────────────────────────────
function ensureToastContainer() {
  let container = $(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    container.setAttribute("aria-live", "polite");
    container.setAttribute("aria-atomic", "true");
    document.body.appendChild(container);
  }
  return container;
}

function showToast(message, type = "info") {
  const container = ensureToastContainer();
  const toast = document.createElement("div");
  toast.className = `toast toast--${type}`;

  // Icon
  const iconMap = {
    success: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    error: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    info: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  };

  toast.innerHTML = `${iconMap[type] || iconMap.info}<span>${message}</span>`;
  container.appendChild(toast);

  // Auto-dismiss after 3.5s
  setTimeout(() => {
    toast.classList.add("toast--exit");
    toast.addEventListener("animationend", () => toast.remove(), { once: true });
  }, 3500);
}

// ── Announce (footer + toast) ─────────────────────────────────
function announce(message, type = "info") {
  // Update footer notice
  if (refs.noticeText) {
    refs.noticeText.textContent = message;
  }
  // Show toast for important messages
  if (type === "error" || type === "success") {
    showToast(message, type);
  }
}

// ── Boot ──────────────────────────────────────────────────────
export function initUI() {
  // Bind refs
  refs.tabEncrypt = el("tabEncrypt");
  refs.tabDecrypt = el("tabDecrypt");
  refs.encryptPanel = el("encryptPanel");
  refs.decryptPanel = el("decryptPanel");
  refs.modeIndicator = $(".mode-indicator");

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
  refs.noticeText = el("noticeText");

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
  refs.copyCipherBtn.addEventListener("click", () => copyOutput(refs.cipherOutput.value, refs.copyCipherBtn));

  refs.decryptForm.addEventListener("submit", handleDecryptSubmit);
  refs.copyPlainBtn.addEventListener("click", () => copyOutput(refs.plainOutput.value, refs.copyPlainBtn));

  refs.clearBtn.addEventListener("click", clearAll);

  // Password toggles
  document.querySelectorAll('[data-toggle="password"]').forEach((btn) => {
    btn.addEventListener("click", () => togglePasswordVisibility(btn));
  });

  initThemeToggle();
  initFontSizeControls();
  initAdvancedSettings();
  initSettingsModal();
  registerServiceWorker();

  // Initial strength meter state
  updateStrengthMeter("");
}

// ── Password Visibility Toggle ────────────────────────────────
function togglePasswordVisibility(btn) {
  const wrapper = btn.closest(".input-wrapper");
  if (!wrapper) return;
  const input = wrapper.querySelector("input");
  if (!input) return;

  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";

  // Swap icon: eye (show) ↔ eye-off (hide)
  if (isPassword) {
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
    btn.setAttribute("aria-label", "Hide password");
  } else {
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    btn.setAttribute("aria-label", "Show password");
  }

  input.focus();
}

// ── Mode Switch ───────────────────────────────────────────────
function handleModeSwitch(mode) {
  const isEncrypt = mode === "encrypt";

  refs.tabEncrypt.setAttribute("aria-selected", String(isEncrypt));
  refs.tabDecrypt.setAttribute("aria-selected", String(!isEncrypt));

  refs.tabEncrypt.tabIndex = isEncrypt ? 0 : -1;
  refs.tabDecrypt.tabIndex = !isEncrypt ? 0 : -1;

  // Animate mode indicator
  if (refs.modeIndicator) {
    refs.modeIndicator.setAttribute("data-active", isEncrypt ? "encrypt" : "decrypt");
  }

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

// ── Encrypt ───────────────────────────────────────────────────
async function handleEncryptSubmit(ev) {
  ev.preventDefault();

  const plaintext = sanitizeInput(refs.plaintextInput.value);
  const password = refs.passwordInput.value ?? "";
  const passwordConfirm = refs.passwordConfirmInput.value ?? "";

  if (plaintext.length === 0) {
    announce("Plaintext cannot be empty", "error");
    refs.plaintextInput.focus();
    return;
  }
  if (password.trim() === "") {
    announce("Password cannot be empty", "error");
    refs.passwordInput.focus();
    return;
  }
  if (password !== passwordConfirm) {
    announce("Passwords must match", "error");
    refs.passwordConfirmInput.setAttribute("aria-invalid", "true");
    refs.passwordConfirmInput.focus();
    return;
  } else {
    refs.passwordConfirmInput.removeAttribute("aria-invalid");
  }

  const { ok, settings, message } = validateAdvancedSettings(readAdvancedSettings());
  if (!ok) {
    announce(message || "Invalid Advanced Settings", "error");
    return;
  }

  // Busy state
  refs.encryptBtn.disabled = true;
  refs.encryptBtn.setAttribute("aria-busy", "true");
  refs.encryptBtn.querySelector("span").textContent = "Encrypting...";

  try {
    const encString = await encryptText(plaintext, password, settings);
    refs.cipherOutput.value = encString;
    announce("Encryption completed", "success");
  } catch (err) {
    announce(err?.message || "Encryption failed", "error");
  } finally {
    // Hygiene: clear passwords and plaintext fields
    refs.passwordInput.value = "";
    refs.passwordConfirmInput.value = "";
    refs.plaintextInput.value = "";

    refs.encryptBtn.disabled = false;
    refs.encryptBtn.removeAttribute("aria-busy");
    refs.encryptBtn.querySelector("span").textContent = "Encrypt";

    // Reset password toggles
    resetPasswordToggles(refs.encryptForm);
  }
}

// ── Decrypt ───────────────────────────────────────────────────
async function handleDecryptSubmit(ev) {
  ev.preventDefault();

  const encString = sanitizeInput(refs.cipherInput.value);
  const password = refs.decryptPasswordInput.value ?? "";

  if (encString.length === 0) {
    announce("Encrypted input cannot be empty", "error");
    refs.cipherInput.focus();
    return;
  }
  if (password.trim() === "") {
    announce("Password cannot be empty", "error");
    refs.decryptPasswordInput.focus();
    return;
  }

  const { ok, settings, message } = validateAdvancedSettings(readAdvancedSettings());
  if (!ok) {
    announce(message || "Invalid Advanced Settings", "error");
    return;
  }

  // Busy state
  refs.decryptBtn.disabled = true;
  refs.decryptBtn.setAttribute("aria-busy", "true");
  refs.decryptBtn.querySelector("span").textContent = "Decrypting...";

  try {
    const plaintext = await decryptText(encString, password, {
      iterations: settings.iterations,
    });
    refs.plainOutput.value = plaintext;
    announce("Decryption completed", "success");
  } catch (err) {
    announce(err?.message || "Decryption failed", "error");
  } finally {
    // Hygiene: clear password and enc input
    refs.decryptPasswordInput.value = "";
    refs.cipherInput.value = "";

    refs.decryptBtn.disabled = false;
    refs.decryptBtn.removeAttribute("aria-busy");
    refs.decryptBtn.querySelector("span").textContent = "Decrypt";

    // Reset password toggles
    resetPasswordToggles(refs.decryptForm);
  }
}

function resetPasswordToggles(form) {
  if (!form) return;
  form.querySelectorAll('input[type="text"][data-was-password]').forEach((input) => {
    input.type = "password";
    input.removeAttribute("data-was-password");
  });
}

// ── Password Strength ─────────────────────────────────────────
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
  let label, cls;

  if (pct < 25) {
    label = "Weak";
    cls = "s-0";
  } else if (pct < 50) {
    label = "Fair";
    cls = "s-25";
  } else if (pct < 75) {
    label = "Good";
    cls = "s-50";
  } else if (pct < 90) {
    label = "Strong";
    cls = "s-75";
  } else {
    label = "Very Strong";
    cls = "s-100";
  }

  refs.strengthLabel.textContent = `Strength: ${label}`;
  refs.strengthBar.classList.remove("s-0", "s-25", "s-50", "s-75", "s-100");
  refs.strengthBar.classList.add(cls);
}

// ── Copy to Clipboard ─────────────────────────────────────────
async function copyOutput(text, btn) {
  const trimmed = (text ?? "").trim();
  if (trimmed.length === 0) {
    announce("Nothing to copy", "info");
    return;
  }
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      await navigator.clipboard.writeText(trimmed);
    } else {
      const ta = document.createElement("textarea");
      ta.value = trimmed;
      ta.setAttribute("readonly", "");
      ta.style.position = "absolute";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }

    // Visual feedback on button
    if (btn) {
      const originalHTML = btn.innerHTML;
      btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg><span>Copied!</span>';
      btn.style.color = "var(--success)";
      setTimeout(() => {
        btn.innerHTML = originalHTML;
        btn.style.color = "";
      }, 2000);
    }

    announce("Copied to clipboard", "success");
  } catch {
    announce("Copy failed", "error");
  }
}

// ── Clear All ─────────────────────────────────────────────────
function clearAll() {
  if (refs.encryptForm) refs.encryptForm.reset();
  if (refs.decryptForm) refs.decryptForm.reset();

  refs.cipherOutput.value = "";
  refs.plainOutput.value = "";

  // Reset Advanced Settings to defaults
  if (refs.advAlgo) refs.advAlgo.value = "AES-256-CBC";
  refs.advSaltLen.value = String(DEFAULTS.saltLength);
  refs.advIterations.value = String(DEFAULTS.iterations);
  refs.advKeyLen.value = String(DEFAULTS.keyLength);

  updateAlgorithmSettings();
  updateStrengthMeter("");

  // Reset all password inputs to password type
  document.querySelectorAll('input[type="text"][data-was-password]').forEach((input) => {
    input.type = "password";
  });

  announce("Cleared all fields and memory", "success");
}

// ── Theme Toggle ──────────────────────────────────────────────
function initThemeToggle() {
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

// ── Font Size ─────────────────────────────────────────────────
function initFontSizeControls() {
  setFontScale(getSelectedRadioValue(refs.fontRadios, "medium"));

  refs.fontRadios.forEach((r) => {
    r.addEventListener("change", () => {
      setFontScale(getSelectedRadioValue(refs.fontRadios, "medium"));
    });
  });
}

function setFontScale(scale) {
  document.documentElement.setAttribute("data-font", scale);
}

// ── Advanced Settings ─────────────────────────────────────────
function initAdvancedSettings() {
  refs.advSaltLen.value = String(DEFAULTS.saltLength);
  refs.advIvLen.value = String(DEFAULTS.ivLength);
  refs.advIterations.value = String(DEFAULTS.iterations);
  refs.advKeyLen.value = String(DEFAULTS.keyLength);
  if (refs.advAlgo) refs.advAlgo.value = "AES-256-CBC";

  try {
    refs.advSaltLen.disabled = false;
    refs.advIvLen.disabled = false;
    refs.advIterations.disabled = false;
    refs.advKeyLen.disabled = false;
    if (refs.advAlgo) refs.advAlgo.disabled = false;

    refs.advAlgo.addEventListener("change", updateAlgorithmSettings);
    updateAlgorithmSettings();
  } catch {}
}

function readAdvancedSettings() {
  const saltLen = Number.parseInt(refs.advSaltLen.value ?? String(DEFAULTS.saltLength), 10);
  const ivLen = Number.parseInt(refs.advIvLen.value ?? String(DEFAULTS.ivLength), 10);
  const iterStr = refs.advIterations.value ?? String(DEFAULTS.iterations);
  const iterNum = Number.parseInt(iterStr, 10);
  const keyLen = Number.parseInt(refs.advKeyLen.value ?? String(DEFAULTS.keyLength), 10);
  const algo = refs.advAlgo.value ?? "AES-256-CBC";

  const webAlgo = algo.includes("GCM") ? "AES-GCM" : "AES-CBC";

  return {
    saltLength: Number.isFinite(saltLen) && saltLen > 0 ? saltLen : DEFAULTS.saltLength,
    ivLength: Number.isFinite(ivLen) && ivLen > 0 ? ivLen : DEFAULTS.ivLength,
    iterations: Number.isFinite(iterNum) && iterNum > 0 ? iterNum : DEFAULTS.iterations,
    keyLength: Number.isFinite(keyLen) && keyLen > 0 ? keyLen : DEFAULTS.keyLength,
    algorithm: webAlgo,
    cliAlgorithm: algo,
  };
}

function validateAdvancedSettings(_vals) {
  const settings = readAdvancedSettings();

  try {
    if (settings.saltLength < 16 || settings.saltLength > 64) {
      refs.advSaltLen.setAttribute("aria-invalid", "true");
      return { ok: false, settings, message: "Salt length must be between 16 and 64 bytes" };
    }
    refs.advSaltLen.removeAttribute("aria-invalid");

    const expectedIvLength = settings.algorithm === "AES-GCM" ? 12 : 16;
    if (settings.ivLength !== expectedIvLength) {
      refs.advIvLen.setAttribute("aria-invalid", "true");
      return { ok: false, settings, message: `${settings.algorithm} requires ${expectedIvLength}-byte IV` };
    }
    refs.advIvLen.removeAttribute("aria-invalid");

    if (settings.iterations < 10000 || settings.iterations > 1000000) {
      refs.advIterations.setAttribute("aria-invalid", "true");
      return { ok: false, settings, message: "Iterations must be between 10,000 and 1,000,000" };
    }
    refs.advIterations.removeAttribute("aria-invalid");

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

// ── Settings Modal ────────────────────────────────────────────
function initSettingsModal() {
  const modal = refs.settingsModal;
  const trigger = refs.settingsTrigger;
  const closeBtn = refs.settingsClose;
  if (!modal || !trigger || !closeBtn) return;

  const container = modal.querySelector(".modal") || modal;

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

  modal.addEventListener("change", (e) => {
    if (e.target && (e.target.name === "theme" || e.target.name === "fontScale")) {
      close();
    }
  });
}

// ── Service Worker ────────────────────────────────────────────
function registerServiceWorker() {
  if ("serviceWorker" in navigator) {
    const isSecure = location.protocol === "https:" || location.hostname === "localhost";
    if (isSecure) {
      navigator.serviceWorker.register("sw.js").catch(() => {});
    }
  }
}

// ── Helpers ───────────────────────────────────────────────────
function getSelectedRadioValue(radios, fallback) {
  const picked = radios.find((r) => r.checked);
  return picked ? picked.value : fallback;
}

function sanitizeInput(text) {
  if (typeof text !== "string") return "";
  return text.trim();
}

function updateAlgorithmSettings() {
  const algo = refs.advAlgo.value;
  const isGCM = algo.includes("GCM");

  const ivLength = isGCM ? 12 : 16;
  refs.advIvLen.value = String(ivLength);
  refs.advIvLen.setAttribute("min", String(ivLength));
  refs.advIvLen.setAttribute("max", String(ivLength));
  refs.advIvLen.setAttribute("step", "1");

  let keyLength = 32;
  if (algo.includes("192")) keyLength = 24;
  else if (algo.includes("128")) keyLength = 16;

  refs.advKeyLen.value = String(keyLength);
  refs.advKeyLen.setAttribute("min", String(keyLength));
  refs.advKeyLen.setAttribute("max", String(keyLength));
  refs.advKeyLen.setAttribute("step", "1");

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

// ── Init ──────────────────────────────────────────────────────
initUI();
