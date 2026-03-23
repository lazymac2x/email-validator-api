const dns = require("dns");
const { promisify } = require("util");
const { DISPOSABLE_DOMAINS } = require("./disposable-domains");

const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolve4 = promisify(dns.resolve4);

// ---------- Constants ----------

/** RFC 5322 compliant email regex (simplified but thorough) */
const EMAIL_REGEX =
  /^(?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(\[(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\]))$/;

const ROLE_PREFIXES = new Set([
  "abuse", "admin", "billing", "compliance", "devnull", "dns",
  "ftp", "hostmaster", "info", "inoc", "ispfeedback", "ispsupport",
  "list", "list-request", "maildaemon", "mailerdaemon", "marketing",
  "noc", "noreply", "no-reply", "null", "phish", "phishing",
  "postmaster", "privacy", "registrar", "root", "security",
  "spam", "support", "sysadmin", "tech", "undisclosed-recipients",
  "unsubscribe", "usenet", "uucp", "webmaster", "www", "sales",
  "help", "jobs", "careers", "hr", "office", "contact", "press",
  "media", "team", "hello", "feedback", "newsletter"
]);

/** Common domain typos → correction */
const TYPO_MAP = {
  // Gmail
  "gmial.com": "gmail.com", "gmal.com": "gmail.com", "gmai.com": "gmail.com",
  "gmali.com": "gmail.com", "gamil.com": "gmail.com", "gnail.com": "gmail.com",
  "gmaill.com": "gmail.com", "gmil.com": "gmail.com", "gimail.com": "gmail.com",
  "gmail.co": "gmail.com", "gmail.con": "gmail.com", "gmail.cmo": "gmail.com",
  "gmail.cm": "gmail.com", "gmail.om": "gmail.com", "gmail.comm": "gmail.com",
  "gmail.vom": "gmail.com", "gmail.xom": "gmail.com", "gmail.coml": "gmail.com",
  "gmaul.com": "gmail.com", "gmailc.om": "gmail.com", "gmqil.com": "gmail.com",

  // Yahoo
  "yaho.com": "yahoo.com", "yahooo.com": "yahoo.com", "yhaoo.com": "yahoo.com",
  "yhoo.com": "yahoo.com", "yaoo.com": "yahoo.com", "yahoo.co": "yahoo.com",
  "yahoo.con": "yahoo.com", "yahoo.cmo": "yahoo.com", "yahoo.cm": "yahoo.com",
  "yahoo.om": "yahoo.com", "yahoo.comm": "yahoo.com", "yahpp.com": "yahoo.com",
  "yaboo.com": "yahoo.com", "yahooi.com": "yahoo.com",

  // Hotmail
  "hotmal.com": "hotmail.com", "hotmial.com": "hotmail.com",
  "hotmil.com": "hotmail.com", "hotmai.com": "hotmail.com",
  "hotamil.com": "hotmail.com", "hotmail.co": "hotmail.com",
  "hotmail.con": "hotmail.com", "hotmaill.com": "hotmail.com",
  "hotmails.com": "hotmail.com", "hotmali.com": "hotmail.com",
  "hotnail.com": "hotmail.com", "homail.com": "hotmail.com",

  // Outlook
  "outloo.com": "outlook.com", "outlok.com": "outlook.com",
  "outllok.com": "outlook.com", "outlook.co": "outlook.com",
  "outlook.con": "outlook.com", "outlookm.com": "outlook.com",
  "outloook.com": "outlook.com", "outlool.com": "outlook.com",

  // iCloud
  "iclod.com": "icloud.com", "iclould.com": "icloud.com",
  "icloud.con": "icloud.com", "icoud.com": "icloud.com",
  "icload.com": "icloud.com", "icloud.co": "icloud.com",

  // Protonmail
  "protonmal.com": "protonmail.com", "protonmial.com": "protonmail.com",
  "protonmail.con": "protonmail.com", "protonmails.com": "protonmail.com",
  "protonmail.co": "protonmail.com", "protonmil.com": "protonmail.com",

  // AOL
  "aol.con": "aol.com", "aol.co": "aol.com", "aol.cm": "aol.com",
  "ao.com": "aol.com",

  // Common TLD typos
  "live.con": "live.com", "live.co": "live.com",
  "msn.con": "msn.com", "msn.co": "msn.com",
  "zoho.con": "zoho.com", "zohomail.con": "zohomail.com",
  "fastmail.con": "fastmail.com", "fastmail.co": "fastmail.com",
  "mail.con": "mail.com", "mail.co": "mail.com",
  "yandex.con": "yandex.com",
  "gmx.con": "gmx.com", "gmx.co": "gmx.com",
};

/** Well-known free email providers (for reference scoring) */
const FREE_PROVIDERS = new Set([
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
  "icloud.com", "mail.com", "zoho.com", "protonmail.com", "yandex.com",
  "gmx.com", "fastmail.com", "tutanota.com", "live.com", "msn.com",
  "me.com", "mac.com", "pm.me", "proton.me"
]);

// ---------- Helpers ----------

async function withTimeout(promise, ms = 5000) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("DNS timeout")), ms)),
  ]);
}

// ---------- Core checks ----------

function checkSyntax(email) {
  const valid = EMAIL_REGEX.test(email);
  const reason = valid ? null : "Email does not match RFC 5322 syntax";
  return { valid, reason };
}

function extractParts(email) {
  const atIdx = email.lastIndexOf("@");
  if (atIdx === -1) return { local: "", domain: "" };
  return { local: email.slice(0, atIdx).toLowerCase(), domain: email.slice(atIdx + 1).toLowerCase() };
}

function checkRoleBased(local) {
  const isRole = ROLE_PREFIXES.has(local);
  return { is_role: isRole, role: isRole ? local : null };
}

function checkDisposable(domain) {
  return { is_disposable: DISPOSABLE_DOMAINS.has(domain) };
}

function checkTypo(domain) {
  const suggestion = TYPO_MAP[domain] || null;
  return { has_typo: !!suggestion, suggested_domain: suggestion };
}

async function checkMx(domain) {
  try {
    const records = await withTimeout(resolveMx(domain), 5000);
    const sorted = records.sort((a, b) => a.priority - b.priority);
    return {
      has_mx: true,
      mx_records: sorted.map((r) => ({ priority: r.priority, exchange: r.exchange })),
    };
  } catch {
    return { has_mx: false, mx_records: [] };
  }
}

async function checkDomainExists(domain) {
  try {
    const addrs = await withTimeout(resolve4(domain), 5000);
    return { domain_exists: addrs.length > 0 };
  } catch {
    return { domain_exists: false };
  }
}

async function checkSpf(domain) {
  try {
    const records = await withTimeout(resolveTxt(domain), 5000);
    const spf = records.flat().find((r) => r.startsWith("v=spf1"));
    return { has_spf: !!spf, spf_record: spf || null };
  } catch {
    return { has_spf: false, spf_record: null };
  }
}

async function checkDkim(domain) {
  // Check common DKIM selectors
  const selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"];
  for (const sel of selectors) {
    try {
      const records = await withTimeout(resolveTxt(`${sel}._domainkey.${domain}`), 3000);
      const dkim = records.flat().find((r) => r.includes("v=DKIM1") || r.includes("k=rsa"));
      if (dkim) return { has_dkim: true, dkim_selector: sel };
    } catch {
      // continue
    }
  }
  return { has_dkim: false, dkim_selector: null };
}

// ---------- Risk scoring ----------

function computeRiskScore(checks) {
  let score = 0; // 0 = safe, 100 = maximum risk

  if (!checks.syntax.valid) score += 40;
  if (!checks.mx.has_mx) score += 25;
  if (!checks.domain.domain_exists) score += 20;
  if (checks.disposable.is_disposable) score += 30;
  if (checks.role.is_role) score += 5;
  if (checks.typo.has_typo) score += 15;
  if (!checks.spf.has_spf) score += 5;
  if (!checks.dkim.has_dkim) score += 3;

  // Free provider slight bump (not inherently risky, but less trust than corporate)
  // Not added to score — free is fine.

  return Math.min(100, Math.max(0, score));
}

function riskLabel(score) {
  if (score <= 10) return "low";
  if (score <= 30) return "medium";
  if (score <= 60) return "high";
  return "critical";
}

// ---------- Public API ----------

async function validateEmail(email) {
  const trimmed = (email || "").trim();
  const syntax = checkSyntax(trimmed);

  if (!syntax.valid) {
    return {
      email: trimmed,
      syntax,
      role: { is_role: false, role: null },
      disposable: { is_disposable: false },
      mx: { has_mx: false, mx_records: [] },
      domain: { domain_exists: false },
      spf: { has_spf: false, spf_record: null },
      dkim: { has_dkim: false, dkim_selector: null },
      typo: checkTypo(""),
      risk: { score: 100, label: "critical" },
      deliverable: false,
    };
  }

  const { local, domain } = extractParts(trimmed);
  const role = checkRoleBased(local);
  const disposable = checkDisposable(domain);
  const typo = checkTypo(domain);

  // Parallel DNS lookups
  const [mx, domainCheck, spf, dkim] = await Promise.all([
    checkMx(domain),
    checkDomainExists(domain),
    checkSpf(domain),
    checkDkim(domain),
  ]);

  const checks = { syntax, mx, domain: domainCheck, disposable, role, typo, spf, dkim };
  const score = computeRiskScore(checks);

  return {
    email: trimmed,
    syntax,
    role,
    disposable,
    mx,
    domain: domainCheck,
    spf,
    dkim,
    typo,
    risk: { score, label: riskLabel(score) },
    deliverable: syntax.valid && mx.has_mx && domainCheck.domain_exists,
  };
}

async function validateBatch(emails) {
  const list = Array.isArray(emails) ? emails : [];
  const capped = list.slice(0, 100);
  const results = await Promise.all(capped.map((e) => validateEmail(e)));
  const valid = results.filter((r) => r.deliverable).length;
  return {
    total: capped.length,
    valid,
    invalid: capped.length - valid,
    results,
  };
}

async function checkDomain(domain) {
  const d = (domain || "").trim().toLowerCase();
  if (!d || !d.includes(".")) {
    return { domain: d, error: "Invalid domain" };
  }

  const [mx, domainCheck, spf, dkim] = await Promise.all([
    checkMx(d),
    checkDomainExists(d),
    checkSpf(d),
    checkDkim(d),
  ]);

  const disposable = checkDisposable(d);
  const isFree = FREE_PROVIDERS.has(d);

  let reputationScore = 100;
  if (!domainCheck.domain_exists) reputationScore -= 40;
  if (!mx.has_mx) reputationScore -= 30;
  if (!spf.has_spf) reputationScore -= 10;
  if (!dkim.has_dkim) reputationScore -= 5;
  if (disposable.is_disposable) reputationScore -= 40;
  reputationScore = Math.max(0, reputationScore);

  return {
    domain: d,
    exists: domainCheck.domain_exists,
    mx,
    spf,
    dkim,
    is_disposable: disposable.is_disposable,
    is_free_provider: isFree,
    reputation_score: reputationScore,
    reputation_label: reputationScore >= 80 ? "good" : reputationScore >= 50 ? "fair" : "poor",
  };
}

function suggestFix(email) {
  const trimmed = (email || "").trim();
  const { local, domain } = extractParts(trimmed);
  const typo = checkTypo(domain);

  if (typo.has_typo) {
    return {
      original: trimmed,
      has_suggestion: true,
      suggested: `${local}@${typo.suggested_domain}`,
      reason: `Domain "${domain}" appears to be a typo for "${typo.suggested_domain}"`,
    };
  }

  return {
    original: trimmed,
    has_suggestion: false,
    suggested: null,
    reason: "No typo detected",
  };
}

module.exports = { validateEmail, validateBatch, checkDomain, suggestFix };
