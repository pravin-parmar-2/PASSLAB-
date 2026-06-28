/* ============================================================
   PASSLAB ENGINE — fully offline password analysis
   No network calls. No data leaves the browser. Ever.
   ============================================================ */

const COMMON_WORDS = [
  "password","admin","qwerty","welcome","iloveyou","abc123","letmein",
  "monkey","dragon","master","login","princess","sunshine","football",
  "baseball","superman","trustno1","whatever","shadow","ninja","secret",
  "freedom","hello","ranger","buster","soccer","hockey","killer","george",
  "michael","jennifer","jordan","hunter","summer","fuckyou","starwars"
];

const COMMON_PASSWORDS = [
  "123456","password123","qwerty123","admin123","123456789","12345678",
  "1234567890","password1","welcome123","letmein123","monkey123","qwertyuiop",
  "1q2w3e4r","123123123","000000","111111","iloveyou1","abc12345","football1",
  "qazwsx","p@ssw0rd","passw0rd"
];

const KEYBOARD_ROWS = [
  "qwertyuiop","asdfghjkl","zxcvbnm","1234567890",
  "qwertzuiop","azertyuiop"
];

function consentLog(action) {
  // Every analysis step is logged ONLY in-memory for the user's own
  // session transparency panel. Never transmitted, never persisted
  // to disk beyond localStorage-free in-memory state.
  return { action, at: new Date().toISOString() };
}

function hasKeyboardPattern(pw) {
  const lower = pw.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i <= row.length - 4; i++) {
      const chunk = row.slice(i, i + 4);
      const rev = chunk.split("").reverse().join("");
      if (lower.includes(chunk) || lower.includes(rev)) return true;
    }
  }
  return false;
}

function hasSequential(pw) {
  // sequential numbers or letters, e.g. 1234, abcd
  for (let i = 0; i < pw.length - 3; i++) {
    const a = pw.charCodeAt(i), b = pw.charCodeAt(i+1),
          c = pw.charCodeAt(i+2), d = pw.charCodeAt(i+3);
    if (b - a === 1 && c - b === 1 && d - c === 1) return true;
    if (a - b === 1 && b - c === 1 && c - d === 1) return true;
  }
  return false;
}

function hasRepeatedChar(pw) {
  return /(.)\1{3,}/.test(pw); // same char 4+ times in a row
}

function hasDictionaryWord(pw) {
  const lower = pw.toLowerCase();
  return COMMON_WORDS.find(w => lower.includes(w)) || null;
}

function isCommonPassword(pw) {
  return COMMON_PASSWORDS.includes(pw.toLowerCase());
}

function calcEntropy(pw) {
  if (!pw) return 0;
  let poolSize = 0;
  if (/[a-z]/.test(pw)) poolSize += 26;
  if (/[A-Z]/.test(pw)) poolSize += 26;
  if (/[0-9]/.test(pw)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) poolSize += 32;
  if (poolSize === 0) return 0;
  return Math.log2(Math.pow(poolSize, pw.length));
}

function estimateCrackTime(pw, isCommon, isDictWord) {
  const entropy = calcEntropy(pw);
  // Assume a strong offline attack rate: 10 billion guesses/sec (modern GPU rig)
  const guessesPerSecond = 1e10;

  if (isCommon) return { seconds: 0, label: "Instantly", severity: "critical" };
  if (isDictWord && pw.length < 10) {
    return { seconds: 1, label: "Less than 1 second", severity: "critical" };
  }

  const totalGuesses = Math.pow(2, entropy);
  const seconds = totalGuesses / guessesPerSecond / 2; // average case

  return { seconds, label: formatDuration(seconds), severity: severityForSeconds(seconds) };
}

function severityForSeconds(s) {
  if (s < 1) return "critical";
  if (s < 60 * 60) return "critical";          // < 1 hour
  if (s < 60 * 60 * 24 * 30) return "weak";    // < 30 days
  if (s < 60 * 60 * 24 * 365 * 5) return "ok";  // < 5 years
  return "strong";
}

function pluralize(val, label) {
  return `${val.toLocaleString()} ${label}${val !== 1 ? "s" : ""}`;
}

function formatDuration(seconds) {
  if (!isFinite(seconds) || seconds < 1) return "Less than 1 second";

  const CENTURY = 3153600000;
  const centuries = seconds / CENTURY;

  // Cap absurdly large numbers at named magnitudes instead of raw centuries
  if (centuries >= 1e12) return "Longer than the age of the universe";
  if (centuries >= 1e9) return `${(centuries / 1e9).toFixed(1)} billion centuries`;
  if (centuries >= 1e6) return `${(centuries / 1e6).toFixed(1)} million centuries`;
  if (centuries >= 1e3) return `${(centuries / 1e3).toFixed(1)} thousand centuries`;
  if (centuries >= 1) {
    const val = Math.round(centuries);
    return `${val.toLocaleString()} ${val !== 1 ? "centuries" : "century"}`;
  }

  const units = [
    { label: "year", secs: 31536000 },
    { label: "month", secs: 2592000 },
    { label: "day", secs: 86400 },
    { label: "hour", secs: 3600 },
    { label: "minute", secs: 60 },
    { label: "second", secs: 1 }
  ];
  for (const u of units) {
    if (seconds >= u.secs) {
      const val = Math.round(seconds / u.secs);
      return pluralize(val, u.label);
    }
  }
  return "Less than 1 second";
}

function analyzePassword(pw) {
  const checks = {
    minLength: pw.length >= 8,
    bonusLength: pw.length >= 12,
    uppercase: /[A-Z]/.test(pw),
    lowercase: /[a-z]/.test(pw),
    numbers: /[0-9]/.test(pw),
    special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(pw),
    noSpaces: pw.length > 0 && !/\s/.test(pw),
    noRepeats: !hasRepeatedChar(pw),
    noSequential: !hasSequential(pw),
    noKeyboardPattern: !hasKeyboardPattern(pw)
  };

  const dictWord = hasDictionaryWord(pw);
  const isCommon = isCommonPassword(pw);

  // Scoring out of 100
  let score = 0;
  const breakdown = [];

  if (checks.minLength) { score += 15; breakdown.push({ label: "Length (8+)", points: 15 }); }
  if (checks.bonusLength) { score += 10; breakdown.push({ label: "Length (12+)", points: 10 }); }
  if (checks.uppercase) { score += 15; breakdown.push({ label: "Uppercase", points: 15 }); }
  if (checks.lowercase) { score += 15; breakdown.push({ label: "Lowercase", points: 15 }); }
  if (checks.numbers) { score += 15; breakdown.push({ label: "Numbers", points: 15 }); }
  if (checks.special) { score += 20; breakdown.push({ label: "Special character", points: 20 }); }
  if (checks.noSequential) { score += 5; breakdown.push({ label: "No sequential chars", points: 5 }); }
  if (checks.noKeyboardPattern) { score += 5; breakdown.push({ label: "No keyboard pattern", points: 5 }); }

  if (dictWord) { score -= 20; breakdown.push({ label: "Contains dictionary word", points: -20 }); }
  if (isCommon) { score -= 40; breakdown.push({ label: "Found in common password list", points: -40 }); }
  if (!checks.noRepeats) { score -= 15; breakdown.push({ label: "Repeated characters", points: -15 }); }

  score = Math.max(0, Math.min(100, score));
  if (pw.length === 0) score = 0;
  // Length dominates real-world crackability — passwords under the
  // minimum length can't be rated above "weak" no matter what else passes.
  if (pw.length > 0 && pw.length < 8) score = Math.min(score, 24);

  let strengthLabel, strengthLevel;
  if (pw.length === 0) { strengthLabel = "Enter a password"; strengthLevel = 0; }
  else if (score < 25) { strengthLabel = "Very weak"; strengthLevel = 1; }
  else if (score < 50) { strengthLabel = "Weak"; strengthLevel = 2; }
  else if (score < 70) { strengthLabel = "Medium"; strengthLevel = 3; }
  else if (score < 90) { strengthLabel = "Strong"; strengthLevel = 4; }
  else { strengthLabel = "Very strong"; strengthLevel = 5; }

  const crackTime = estimateCrackTime(pw, isCommon, dictWord);
  const entropy = calcEntropy(pw);

  const suggestions = [];
  if (!checks.bonusLength) suggestions.push("Increase length to 14+ characters");
  if (!checks.uppercase) suggestions.push("Add uppercase letters");
  if (!checks.lowercase) suggestions.push("Add lowercase letters");
  if (!checks.numbers) suggestions.push("Add numbers");
  if (!checks.special) suggestions.push("Use special characters (!@#$%...)");
  if (dictWord) suggestions.push("Avoid dictionary words");
  if (isCommon) suggestions.push("This exact password is publicly known — change it immediately");
  if (!checks.noRepeats) suggestions.push("Avoid repeating the same character many times");
  if (!checks.noSequential) suggestions.push("Avoid sequential characters like 1234 or abcd");
  if (!checks.noKeyboardPattern) suggestions.push("Avoid keyboard patterns like qwerty");
  if (suggestions.length === 0) suggestions.push("Great work — this password follows all best practices");

  return {
    checks, score, breakdown, strengthLabel, strengthLevel,
    dictWord, isCommon, crackTime, entropy, suggestions,
    length: pw.length
  };
}

function generatePassword(opts) {
  const { length, uppercase, lowercase, numbers, symbols } = opts;
  let pool = "";
  if (uppercase) pool += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (lowercase) pool += "abcdefghijkmnpqrstuvwxyz";
  if (numbers) pool += "23456789";
  if (symbols) pool += "!@#$%^&*()_+-=[]{}";

  if (!pool) pool = "abcdefghijkmnpqrstuvwxyz23456789";

  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += pool[array[i] % pool.length];
  }

  // Ensure at least one of each selected category appears
  const categories = [];
  if (uppercase) categories.push("ABCDEFGHJKLMNPQRSTUVWXYZ");
  if (lowercase) categories.push("abcdefghijkmnpqrstuvwxyz");
  if (numbers) categories.push("23456789");
  if (symbols) categories.push("!@#$%^&*()_+-=[]{}");

  const chars = result.split("");
  categories.forEach((cat, idx) => {
    if (idx < chars.length) {
      const randIdx = crypto.getRandomValues(new Uint32Array(1))[0] % cat.length;
      chars[idx] = cat[randIdx];
    }
  });

  // shuffle
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join("");
}
