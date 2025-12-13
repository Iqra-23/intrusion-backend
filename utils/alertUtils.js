// utils/alertUtils.js

import Alert from "../models/Alert.js";
import { sendMail } from "../config/mailer.js";
import { getIO } from "./socket.js";

// Suspicious keywords that trigger alerts
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

// =========================================================
// 🔥 MAIN FUNCTION: Suspicious Log Detector
// =========================================================
export const checkSuspiciousActivity = async (log, userEmail = null) => {
  try {
    if (!log) {
      console.log("⚠️ checkSuspiciousActivity called with no log");
      return null;
    }

    console.log("\n🔍 Checking suspicious activity for log:", log._id);
    console.log("Level:", log.level);
    console.log("Message:", log.message);

    const message = (log.message || "").toLowerCase();
    const keywords = (log.keyword || []).map((k) => (k || "").toLowerCase());

    const foundKeywords = SUSPICIOUS_KEYWORDS.filter((keyword) => {
      return (
        message.includes(keyword) ||
        keywords.some((k) => k.includes(keyword))
      );
    });

    // =========================================================
    // 🔥 If suspicious → create ALERT
    // =========================================================
    if (
      foundKeywords.length > 0 ||
      ["warning", "error", "suspicious"].includes(log.level)
    ) {
      let severity = "low";

      if (
        log.level === "suspicious" ||
        foundKeywords.some((k) =>
          ["critical", "exploit", "breach", "attack"].includes(k)
        )
      ) {
        severity = "critical";
      } else if (
        log.level === "error" ||
        foundKeywords.some((k) =>
          ["sql injection", "xss", "malware", "virus", "hack"].includes(k)
        )
      ) {
        severity = "high";
      } else if (
        log.level === "warning" ||
        foundKeywords.some((k) =>
          ["unauthorized", "intrusion"].includes(k)
        )
      ) {
        severity = "medium";
      }

      const alert = await Alert.create({
        logId: log._id,
        severity,
        title: `Suspicious Activity Detected: ${log.level.toUpperCase()}`,
        description: log.message,
        keywords:
          foundKeywords.length > 0 ? foundKeywords : [log.level],
      });

      console.log("✅ Alert created:", alert._id);

      // =========================================================
      // 📡 Real-time socket alert
      // =========================================================
      try {
        const io = getIO();
        io.emit("new-alert", {
          id: alert._id,
          severity: alert.severity,
          title: alert.title,
          description: alert.description,
          createdAt: alert.createdAt,
        });
      } catch {
        console.log("⚠️ Socket not ready, skipping emit");
      }

      // =========================================================
      // 📧 Email notification (GMAIL API)
      // =========================================================
      await sendAlertEmail(alert, log, userEmail);

      return alert;
    }

    return null;
  } catch (error) {
    console.error("❌ checkSuspiciousActivity error:", error);
    return null;
  }
};

// =========================================================
// 📧 SEND ALERT EMAIL (GMAIL API – NO SMTP)
// =========================================================
const sendAlertEmail = async (alert, log, userEmail = null) => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
    const toEmail = userEmail || adminEmail;

    if (!toEmail) {
      console.error("❌ No email recipient configured");
      return;
    }

    const subject = `🚨 ${alert.severity.toUpperCase()} Security Alert - SEO Intrusion Detector`;

    const html = `
      <div style="font-family: Arial; padding: 20px;">
        <h2>🚨 Security Alert</h2>
        <p><strong>Severity:</strong> ${alert.severity.toUpperCase()}</p>
        <p><strong>Message:</strong> ${log.message}</p>
        <p><strong>Time:</strong> ${new Date(
          log.createdAt
        ).toLocaleString()}</p>
        ${
          alert.keywords?.length
            ? `<p><strong>Keywords:</strong> ${alert.keywords.join(", ")}</p>`
            : ""
        }
        <a href="${process.env.FRONTEND_URL}/alerts">
          View Alert
        </a>
      </div>
    `;

    await sendMail({
      to: toEmail,
      subject,
      html,
    });

    console.log(`📧 Alert email sent to ${toEmail}`);
  } catch (error) {
    console.error("❌ sendAlertEmail error:", error);
  }
};

// =========================================================
// Placeholder for future pattern detection
// =========================================================
export const detectPatterns = async () => {
  return;
};

export default { checkSuspiciousActivity, detectPatterns };
