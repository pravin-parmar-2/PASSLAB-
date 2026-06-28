/* ============================================================
   PASSLAB APP — all state lives in memory only. Refreshing the
   page or closing the tab erases everything. No localStorage,
   no cookies, no network calls, anywhere in this file.
   ============================================================ */

const state = {
  consentGiven: false,
  profile: null, // { name, email, createdAt }
  stats: { analyzed: 0, generated: 0, saved: 0 },
  genHistory: [], // session-only generated passwords
  savedResults: [],
  currentView: "analyzer"
};

function showToast(msg) {
  const toast = document.getElementById("toast");
  toast.textContent = msg;
  toast.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => toast.classList.add("hidden"), 2600);
}

/* ---------------- CONSENT GATE ---------------- */
const consentCheckbox = document.getElementById("consentCheckbox");
const consentAccept = document.getElementById("consentAccept");

consentCheckbox.addEventListener("change", () => {
  consentAccept.disabled = !consentCheckbox.checked;
});

consentAccept.addEventListener("click", () => {
  if (!consentCheckbox.checked) return;
  state.consentGiven = true;
  document.getElementById("consentGate").classList.add("hidden");
  document.getElementById("authScreen").classList.remove("hidden");
});

/* ---------------- AUTH (local-only, NOT real security) ---------------- */
const authTabs = document.querySelectorAll(".auth-tab");
const signinForm = document.getElementById("signinForm");
const signupForm = document.getElementById("signupForm");

authTabs.forEach(tab => {
  tab.addEventListener("click", () => {
    authTabs.forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    const target = tab.dataset.tab;
    signinForm.classList.toggle("hidden", target !== "signin");
    signupForm.classList.toggle("hidden", target !== "signup");
  });
});

// In-memory-only "account" — this is intentionally not persisted to
// disk and not a real auth system. It exists purely so the app has
// a profile concept while staying 100% offline.
let localAccount = null;

signupForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const name = document.getElementById("signupName").value.trim();
  const pass = document.getElementById("signupPass").value;
  const email = document.getElementById("signupEmail").value.trim();
  const consent = document.getElementById("signupConsent").checked;
  const errorEl = document.getElementById("signupError");

  if (!consent) {
    errorEl.textContent = "Please confirm the consent checkbox to continue.";
    return;
  }
  if (name.length < 2 || pass.length < 4) {
    errorEl.textContent = "Enter a profile name (2+ chars) and passphrase (4+ chars).";
    return;
  }
  errorEl.textContent = "";

  localAccount = { name, pass, email };
  state.profile = { name, email, createdAt: new Date() };
  enterApp();
});

signinForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const name = document.getElementById("signinName").value.trim();
  const pass = document.getElementById("signinPass").value;
  const errorEl = document.getElementById("signinError");

  if (!localAccount) {
    errorEl.textContent = "No local profile exists yet in this session — create one first.";
    return;
  }
  if (localAccount.name !== name || localAccount.pass !== pass) {
    errorEl.textContent = "Name or passphrase doesn't match this session's profile.";
    return;
  }
  errorEl.textContent = "";
  state.profile = { name: localAccount.name, email: localAccount.email, createdAt: state.profile?.createdAt || new Date() };
  enterApp();
});

document.querySelectorAll(".pw-toggle").forEach(btn => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.target);
    input.type = input.type === "password" ? "text" : "password";
  });
});

function enterApp() {
  document.getElementById("authScreen").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  document.getElementById("profileName").value = state.profile.name;
  document.getElementById("profileEmail").value = state.profile.email || "";
  document.getElementById("profileStarted").value = state.profile.createdAt.toLocaleTimeString();
  document.getElementById("profileAvatar").textContent = state.profile.name[0].toUpperCase();
  showToast(`Welcome, ${state.profile.name}. Everything stays in this tab.`);
}

document.getElementById("logoutBtn").addEventListener("click", () => {
  if (!confirm("Sign out? Your session profile stays in memory until you close the tab, but you'll need your passphrase to sign back in.")) return;
  document.getElementById("app").classList.add("hidden");
  document.getElementById("authScreen").classList.remove("hidden");
});

/* ---------------- THEME TOGGLE (cyber <-> black & white) ---------------- */
const themeToggle = document.getElementById("themeToggle");
themeToggle.addEventListener("click", () => {
  const html = document.documentElement;
  const next = html.dataset.theme === "cyber" ? "bw" : "cyber";
  html.dataset.theme = next;
  showToast(next === "bw" ? "Black & white theme on" : "Cyber theme on");
});

/* ---------------- NAVIGATION ---------------- */
function setView(viewName) {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.getElementById(`view-${viewName}`).classList.add("active");
  document.querySelectorAll(".nav-link").forEach(n => {
    n.classList.toggle("active", n.dataset.view === viewName);
  });
  state.currentView = viewName;
  document.getElementById("sideMenu").classList.add("hidden");
}

document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", () => setView(link.dataset.view));
});

document.getElementById("menuToggle").addEventListener("click", () => {
  document.getElementById("sideMenu").classList.toggle("hidden");
});

/* ---------------- ANALYZER ---------------- */
const pwInput = document.getElementById("pwInput");
const charCount = document.getElementById("charCount");
let lastAnalysis = null;

const CHECK_LABELS = {
  minLength: "Minimum 8 characters",
  bonusLength: "12+ characters (bonus)",
  uppercase: "Uppercase letters (A-Z)",
  lowercase: "Lowercase letters (a-z)",
  numbers: "Numbers (0-9)",
  special: "Special characters (!@#$%^&)",
  noSpaces: "No spaces",
  noRepeats: "No repeated characters (aaaa)",
  noSequential: "No sequential characters (1234)",
  noKeyboardPattern: "No keyboard pattern (qwerty)"
};

function renderAnalysis(pw) {
  const result = analyzePassword(pw);
  lastAnalysis = { pw, result };

  charCount.textContent = `${pw.length} character${pw.length !== 1 ? "s" : ""}`;

  // strength meter
  document.querySelectorAll(".meter-segment").forEach((seg, i) => {
    seg.className = "meter-segment";
    if (i < result.strengthLevel) seg.classList.add(`lit-${result.strengthLevel}`);
  });

  const emojiMap = ["○", "🔴", "🟠", "🟡", "🟢", "💚"];
  document.getElementById("strengthEmoji").textContent = emojiMap[result.strengthLevel];
  document.getElementById("strengthText").textContent = result.strengthLabel;

  // checklist
  const ul = document.getElementById("checklist");
  ul.innerHTML = "";
  Object.entries(CHECK_LABELS).forEach(([key, label]) => {
    const pass = result.checks[key];
    const li = document.createElement("li");
    li.className = pw.length === 0 ? "" : (pass ? "pass" : "fail");
    li.innerHTML = `<span class="mark">${pw.length === 0 ? "–" : (pass ? "✔" : "✖")}</span><span>${label}</span>`;
    ul.appendChild(li);
  });

  // score
  document.getElementById("scoreNumber").textContent = result.score;
  const breakdownEl = document.getElementById("scoreBreakdown");
  breakdownEl.innerHTML = "";
  result.breakdown.forEach(b => {
    const row = document.createElement("div");
    row.className = "score-row";
    const sign = b.points > 0 ? "+" : "";
    row.innerHTML = `<span>${b.label}</span><span class="pts ${b.points > 0 ? "positive" : "negative"}">${sign}${b.points}</span>`;
    breakdownEl.appendChild(row);
  });

  // crack time
  const ctEl = document.getElementById("cracktimeDisplay");
  ctEl.textContent = pw.length === 0 ? "—" : result.crackTime.label;
  ctEl.className = "cracktime-display" + (pw.length ? ` severity-${result.crackTime.severity}` : "");
  document.getElementById("entropyValue").textContent = Math.round(result.entropy);

  // warnings
  const warningsCard = document.getElementById("warningsCard");
  const warningsList = document.getElementById("warningsList");
  warningsList.innerHTML = "";
  const warnings = [];
  if (result.isCommon) warnings.push("❌ This password is found in the list of common passwords.");
  if (result.dictWord) warnings.push("⚠ Your password contains a common dictionary word.");
  if (!result.checks.noKeyboardPattern) warnings.push("⚠ Your password contains a keyboard pattern (e.g. qwerty).");
  if (!result.checks.noSequential) warnings.push("⚠ Your password contains sequential characters (e.g. 1234).");
  if (!result.checks.noRepeats) warnings.push("⚠ Your password contains repeated characters (e.g. aaaa).");

  if (warnings.length && pw.length > 0) {
    warningsCard.style.display = "";
    warnings.forEach(w => {
      const div = document.createElement("div");
      div.className = "warning-item";
      div.textContent = w;
      warningsList.appendChild(div);
    });
  } else {
    warningsCard.style.display = "none";
  }

  // suggestions
  const sugList = document.getElementById("suggestionsList");
  sugList.innerHTML = "";
  result.suggestions.forEach(s => {
    const li = document.createElement("li");
    li.textContent = s;
    sugList.appendChild(li);
  });

  if (pw.length > 0) state.stats.analyzed++;
  updateProfileStats();
}

pwInput.addEventListener("input", () => renderAnalysis(pwInput.value));
renderAnalysis(""); // initial empty state

document.getElementById("clearBtn").addEventListener("click", () => {
  pwInput.value = "";
  renderAnalysis("");
});

/* ---- voice feedback (offline browser speech synthesis) ---- */
document.getElementById("speakBtn").addEventListener("click", () => {
  if (!lastAnalysis || !lastAnalysis.pw) {
    showToast("Type a password first.");
    return;
  }
  if (!("speechSynthesis" in window)) {
    showToast("Voice feedback isn't supported in this browser.");
    return;
  }
  const utter = new SpeechSynthesisUtterance(
    `${lastAnalysis.result.strengthLabel}. Score ${lastAnalysis.result.score} out of 100.`
  );
  window.speechSynthesis.speak(utter);
});

/* ---- export report (printable, offline, no PDF library needed) ---- */
document.getElementById("exportBtn").addEventListener("click", () => {
  if (!lastAnalysis || !lastAnalysis.pw) {
    showToast("Type a password first.");
    return;
  }
  if (!confirm("This opens a printable report in a new tab so you can save it as PDF locally. Continue?")) return;

  const r = lastAnalysis.result;
  const win = window.open("", "_blank");
  win.document.write(`
    <html><head><title>PassLab security report</title>
    <style>
      body{font-family:system-ui;padding:40px;max-width:600px;margin:0 auto;color:#111}
      h1{font-size:20px}
      table{width:100%;border-collapse:collapse;margin:16px 0}
      td{padding:6px 0;border-bottom:1px solid #ddd;font-size:13px}
      .muted{color:#777;font-size:12px}
    </style></head><body>
    <h1>PassLab security report</h1>
    <p class="muted">Generated locally on ${new Date().toLocaleString()}. The password itself is not included in this report.</p>
    <table>
      <tr><td>Strength</td><td>${r.strengthLabel}</td></tr>
      <tr><td>Score</td><td>${r.score}/100</td></tr>
      <tr><td>Length</td><td>${r.length} characters</td></tr>
      <tr><td>Entropy</td><td>${Math.round(r.entropy)} bits</td></tr>
      <tr><td>Estimated crack time</td><td>${r.crackTime.label}</td></tr>
      <tr><td>Contains dictionary word</td><td>${r.dictWord ? "Yes" : "No"}</td></tr>
      <tr><td>Found in common password list</td><td>${r.isCommon ? "Yes" : "No"}</td></tr>
    </table>
    <p class="muted">Suggestions: ${r.suggestions.join("; ")}</p>
    </body></html>
  `);
  win.document.close();
});

/* ---- save to session history (explicit opt-in checkbox) ---- */
document.getElementById("saveHistoryToggle").addEventListener("change", (e) => {
  if (e.target.checked) {
    if (!lastAnalysis || !lastAnalysis.pw) {
      showToast("Type a password first.");
      e.target.checked = false;
      return;
    }
    if (!confirm("Save this result (score + strength only, not the password itself) to your in-memory session history?")) {
      e.target.checked = false;
      return;
    }
    state.savedResults.push({
      strength: lastAnalysis.result.strengthLabel,
      score: lastAnalysis.result.score,
      at: new Date().toLocaleTimeString()
    });
    state.stats.saved++;
    updateProfileStats();
    showToast("Saved to session history.");
    e.target.checked = false;
  }
});

/* ---------------- GENERATOR ---------------- */
const genLength = document.getElementById("genLength");
const genLengthOut = document.getElementById("genLengthOut");
genLength.addEventListener("input", () => genLengthOut.textContent = genLength.value);

document.getElementById("generateBtn").addEventListener("click", () => {
  const opts = {
    length: parseInt(genLength.value, 10),
    uppercase: document.getElementById("genUpper").checked,
    lowercase: document.getElementById("genLower").checked,
    numbers: document.getElementById("genNumbers").checked,
    symbols: document.getElementById("genSymbols").checked
  };
  if (!opts.uppercase && !opts.lowercase && !opts.numbers && !opts.symbols) {
    showToast("Select at least one character type.");
    return;
  }
  const pw = generatePassword(opts);
  const analysis = analyzePassword(pw);

  document.getElementById("genResult").textContent = pw;
  document.getElementById("genResultMeta").textContent =
    `${analysis.strengthLabel} · score ${analysis.score}/100 · ${analysis.crackTime.label} to crack`;
  document.getElementById("genResultWrap").classList.remove("hidden");

  state.genHistory.unshift({ pw, label: analysis.strengthLabel, at: new Date().toLocaleTimeString() });
  state.genHistory = state.genHistory.slice(0, 8);
  renderGenHistory();

  state.stats.generated++;
  updateProfileStats();
});

function renderGenHistory() {
  const list = document.getElementById("genHistoryList");
  list.innerHTML = "";
  if (state.genHistory.length === 0) {
    list.innerHTML = `<li style="justify-content:center;color:var(--text-muted)">No passwords generated yet this session</li>`;
    return;
  }
  state.genHistory.forEach(h => {
    const li = document.createElement("li");
    const pwSpan = document.createElement("span");
    pwSpan.textContent = h.pw;
    const timeSpan = document.createElement("span");
    timeSpan.textContent = h.at;
    li.appendChild(pwSpan);
    li.appendChild(timeSpan);
    list.appendChild(li);
  });
}
renderGenHistory();

document.getElementById("copyGenBtn").addEventListener("click", async () => {
  const pw = document.getElementById("genResult").textContent;
  if (!confirm("Copy this generated password to your clipboard?")) return;
  try {
    await navigator.clipboard.writeText(pw);
    showToast("Copied to clipboard.");
  } catch {
    showToast("Clipboard access was blocked by the browser.");
  }
});

document.getElementById("analyzeGenBtn").addEventListener("click", () => {
  const pw = document.getElementById("genResult").textContent;
  setView("analyzer");
  pwInput.value = pw;
  renderAnalysis(pw);
});

/* ---------------- PROFILE ---------------- */
function updateProfileStats() {
  document.getElementById("statAnalyzed").textContent = state.stats.analyzed;
  document.getElementById("statGenerated").textContent = state.stats.generated;
  document.getElementById("statSaved").textContent = state.stats.saved;
}

document.getElementById("saveProfileBtn").addEventListener("click", () => {
  const name = document.getElementById("profileName").value.trim();
  const email = document.getElementById("profileEmail").value.trim();
  if (name.length < 2) {
    showToast("Profile name needs at least 2 characters.");
    return;
  }
  state.profile.name = name;
  state.profile.email = email;
  document.getElementById("profileAvatar").textContent = name[0].toUpperCase();
  const confirmEl = document.getElementById("saveConfirm");
  confirmEl.classList.remove("hidden");
  setTimeout(() => confirmEl.classList.add("hidden"), 2000);
});

document.getElementById("wipeBtn").addEventListener("click", () => {
  if (!confirm("This permanently erases your profile, generator history, and saved results from this tab. This cannot be undone. Continue?")) return;
  state.profile = null;
  state.stats = { analyzed: 0, generated: 0, saved: 0 };
  state.genHistory = [];
  state.savedResults = [];
  localAccount = null;
  document.getElementById("app").classList.add("hidden");
  document.getElementById("authScreen").classList.remove("hidden");
  signinForm.reset();
  signupForm.reset();
  showToast("Session data erased.");
});
