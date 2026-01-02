import Alert from "../models/Alert.js";
import { getIO } from "./socket.js";
import { sendMail } from "../config/mailer.js";

// Tumhari list keep (same spirit, extended safe)
const SUSPICIOUS_KEYWORDS = [
  "critical",
  "vulnerability",
  "exploit",
  "sql injection",
  "xss",
  "csrf",
  "malware",
  "virus",
  "hack",
  "breach",
  "attack",
  "intrusion",
  "malicious",
  "phishing",
  "backdoor",
  "trojan",
  "ransomware",
  "ddos",
  "brute force",
  "injection",
  "shell",
  "payload",
  "penetration",
  "unauthorized",
  "high",
  "medium",
  "low",
  "error",
  "warning",
  "suspicious",
];

// ✅ MAIN: log se alert generate + socket push + email
export const checkSuspiciousActivity = async (log, userEmail = null) => {
  try {
    if (!log) return null;

    const message = (log.message || "").toLowerCase();
    const keywords = (log.keyword || []).map((k) => (k || "").toLowerCase());

    const foundKeywords = SUSPICIOUS_KEYWORDS.filter((keyword) => {
      const inMsg = message.includes(keyword);
      const inKw = keywords.some((k) => k.includes(keyword) || keyword.includes(k));
      return inMsg || inKw;
    });

    const isSuspicious =
      foundKeywords.length > 0 ||
      log.level === "suspicious" ||
      log.level === "error" ||
      log.level === "warning";

    if (!isSuspicious) return null;

    // severity calculation (same idea as your code)
    let severity = "low";

    if (
      log.level === "suspicious" ||
      foundKeywords.some((k) => ["critical", "exploit", "breach", "attack"].includes(k))
    ) {
      severity = "critical";
    } else if (
      foundKeywords.some((k) => ["sql injection", "xss", "malware", "virus", "hack"].includes(k)) ||
      log.level === "error"
    ) {
      severity = "high";
    } else if (
      foundKeywords.some((k) => ["warning", "unauthorized", "intrusion"].includes(k)) ||
      log.level === "warning"
    ) {
      severity = "medium";
    }

    // create alert in DB
    const alert = await Alert.create({
      logId: log._id,
      severity,
      title: `Suspicious Activity Detected: ${String(log.level || "").toUpperCase()}`,
      description: log.message || "",
      keywords: foundKeywords.length ? foundKeywords : [log.level || "suspicious"],
    });

    // ✅ REAL-TIME DASHBOARD PUSH (feature)
    try {
      const io = getIO();
      io.emit("new-alert", {
        id: alert._id,
        severity: alert.severity,
        title: alert.title,
        description: alert.description,
        createdAt: alert.createdAt,
        keywords: alert.keywords || [],
      });
    } catch (e) {
      // socket not ready -> ignore
    }

    // ✅ EMAIL (feature): userEmail + adminEmail dono (if available)
    await sendAlertEmail(alert, log, userEmail);

    return alert;
  } catch (error) {
    console.error("checkSuspiciousActivity error:", error);
    return null;
  }
};

const sendAlertEmail = async (alert, log, userEmail = null) => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
    const recipients = [adminEmail, userEmail].filter(Boolean);

    if (recipients.length === 0) return;

    const subject = `🚨 ${alert.severity.toUpperCase()} Security Alert - SEO Intrusion Detector`;

    const html = `
      <div style="font-family: Arial; padding: 16px;">
        <h2>🚨 Security Alert</h2>
        <p><strong>Severity:</strong> ${alert.severity.toUpperCase()}</p>
        <p><strong>Message:</strong> ${log.message || "-"}</p>
        <p><strong>Time:</strong> ${new Date(log.createdAt || Date.now()).toLocaleString()}</p>
        ${
          alert.keywords?.length
            ? `<p><strong>Keywords:</strong> ${alert.keywords.join(", ")}</p>`
            : ""
        }
        <a href="${process.env.FRONTEND_URL}/alerts">View Alerts</a>
      </div>
    `;

    // sendMail should support array OR string; if not, loop below
    for (const to of recipients) {
      await sendMail({ to, subject, html });
    }
  } catch (error) {
    console.error("sendAlertEmail error:", error);
  }
};
