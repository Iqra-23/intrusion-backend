import FirewallIncident from "../models/FirewallIncident.js";
import { sendMail } from "../config/mailer.js";
import { getIO } from "./socket.js";
import { lookupGeo } from "./ipGeo.js";

export const SQLI_PATTERNS = [
  /(\bor\b|\band\b)\s+1\s*=\s*1/i,
  /union\s+select/i,
  /select\s+.*\s+from/i,
  /drop\s+table/i,
  /insert\s+into/i,
  /update\s+.+\s+set/i,
  /delete\s+from/i,
  /--/i,
];

export const XSS_PATTERNS = [
  /<script\b[^>]*>(.*?)<\/script>/i,
  /onerror\s*=/i,
  /onload\s*=/i,
  /javascript:/i,
  /<iframe\b[^>]*>/i,
];

export const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\//,
  /\.\.\\/,
  /%2e%2e%2f/i,
  /%2e%2e\\/i,
];

export const SPAM_KEYWORDS = [
  "free",
  "cheap",
  "offer",
  "discount",
  "buy",
  "click",
  "winner",
  "bonus",
  "sale",
  "limited",
];

export const getClientIp = (req) => {
  const xfwd = req.headers["x-forwarded-for"];
  if (xfwd) return xfwd.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "Unknown";
};

const flattenInput = (value) => {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);

  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
};

export const keywordDensityCheck = (text) => {
  const clean = String(text || "").toLowerCase();
  const words = clean.split(/\s+/).filter(Boolean);

  if (words.length === 0) {
    return { isSpam: false, density: 0, keyword: "" };
  }

  let maxCount = 0;
  let maxKeyword = "";

  for (const keyword of SPAM_KEYWORDS) {
    const count = words.filter((w) => w.includes(keyword)).length;
    if (count > maxCount) {
      maxCount = count;
      maxKeyword = keyword;
    }
  }

  const density = Number(((maxCount / words.length) * 100).toFixed(2));

  return {
    isSpam: maxCount >= 4 || density >= 25,
    density,
    keyword: maxKeyword,
  };
};

export const detectFirewallThreats = (req) => {
  const findings = [];

  const fullUrl = req.originalUrl || req.url || "/";

  const inputs = [
    { sourceType: "url", value: fullUrl },
    { sourceType: "query", value: flattenInput(req.query) },
    { sourceType: "body", value: flattenInput(req.body) },
    { sourceType: "params", value: flattenInput(req.params) },
    {
      sourceType: "headers",
      value: flattenInput({
        referer: req.headers["referer"],
        origin: req.headers["origin"],
      }),
    },
  ];

  for (const item of inputs) {
    const val = String(item.value || "");

    for (const pattern of SQLI_PATTERNS) {
      if (pattern.test(val)) {
        findings.push({
          attackType: "sql-injection",
          severity: "critical",
          sourceType: item.sourceType,
          matchedPattern: pattern.toString(),
          suspiciousValue: val.slice(0, 300),
          simulatedAction: "block",
        });
        break;
      }
    }

    for (const pattern of XSS_PATTERNS) {
      if (pattern.test(val)) {
        findings.push({
          attackType: "xss",
          severity: "high",
          sourceType: item.sourceType,
          matchedPattern: pattern.toString(),
          suspiciousValue: val.slice(0, 300),
          simulatedAction: "block",
        });
        break;
      }
    }

    for (const pattern of PATH_TRAVERSAL_PATTERNS) {
      if (pattern.test(val)) {
        findings.push({
          attackType: "path-traversal",
          severity: "high",
          sourceType: item.sourceType,
          matchedPattern: pattern.toString(),
          suspiciousValue: val.slice(0, 300),
          simulatedAction: "block",
        });
        break;
      }
    }

    const spam = keywordDensityCheck(val);
    if (spam.isSpam) {
      findings.push({
        attackType: "keyword-spam",
        severity: "medium",
        sourceType: item.sourceType,
        matchedPattern: "high keyword density",
        suspiciousValue: val.slice(0, 300),
        keywordDensity: spam.density,
        repeatedKeyword: spam.keyword,
        simulatedAction: "flag",
      });
    }
  }

  const unique = [];
  const seen = new Set();

  for (const f of findings) {
    const key = `${f.attackType}-${f.sourceType}-${f.matchedPattern}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(f);
    }
  }

  return unique;
};

export const saveFirewallIncidentsAndNotify = async (req, findings) => {
  if (!findings?.length) return [];

  const ip = getClientIp(req);
  const userAgent = req.headers["user-agent"] || "";
  const fullUrl = req.originalUrl || req.url || "/";
  const geo = await lookupGeo(ip);

  const docs = [];

  for (const finding of findings) {
    const doc = await FirewallIncident.create({
      ip,
      method: req.method || "GET",
      path: fullUrl,
      fullUrl,
      userAgent,
      sourceType: finding.sourceType,
      attackType: finding.attackType,
      severity: finding.severity,
      matchedPattern: finding.matchedPattern,
      suspiciousValue: finding.suspiciousValue,
      keywordDensity: finding.keywordDensity || 0,
      repeatedKeyword: finding.repeatedKeyword || "",
      blocked: finding.simulatedAction === "block",
      simulatedAction: finding.simulatedAction,
      geo: geo
        ? {
            country: geo.country,
            city: geo.city,
            region: geo.region,
          }
        : {},
    });

    docs.push(doc);

    // in-app real-time alert
    try {
      const io = getIO();

      io.emit("new-firewall-incident", {
        id: doc._id,
        attackType: doc.attackType,
        severity: doc.severity,
        path: doc.path,
        ip: doc.ip,
        simulatedAction: doc.simulatedAction,
        createdAt: doc.createdAt,
      });

      // Existing alerts ecosystem ke liye
      io.emit("new-alert", {
        id: doc._id,
        severity: doc.severity,
        title: `Firewall Alert: ${doc.attackType}`,
        description: `Suspicious request detected on ${doc.path}`,
        createdAt: doc.createdAt,
        keywords: [doc.attackType, doc.sourceType],
      });
    } catch {
      // ignore socket issue
    }

    // email alert
    const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
    if (adminEmail) {
      await sendMail({
        to: adminEmail,
        subject: `🚨 Firewall ${doc.severity.toUpperCase()} Alert - ${doc.attackType}`,
        html: `
          <div style="font-family: Arial, sans-serif; line-height:1.6">
            <h2>Access Control & Firewall Simulation Alert</h2>
            <p><strong>Attack Type:</strong> ${doc.attackType}</p>
            <p><strong>Severity:</strong> ${doc.severity.toUpperCase()}</p>
            <p><strong>IP:</strong> ${doc.ip}</p>
            <p><strong>Path:</strong> ${doc.path}</p>
            <p><strong>Source:</strong> ${doc.sourceType}</p>
            <p><strong>Simulated Action:</strong> ${doc.simulatedAction}</p>
            <p><strong>Matched Pattern:</strong> ${doc.matchedPattern}</p>
            <p><strong>Value:</strong> ${doc.suspiciousValue}</p>
            ${
              doc.keywordDensity
                ? `<p><strong>Keyword Density:</strong> ${doc.keywordDensity}% (${doc.repeatedKeyword})</p>`
                : ""
            }
          </div>
        `,
      });
    }
  }

  return docs;
};