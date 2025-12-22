// utils/alertUtils.js
import Alert from "../models/Alert.js";

import { getIO } from "./socket.js";
import { sendMail } from "../config/mailer.js";

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

    console.log(
      "\n🔍 Checking suspicious activity for log ID:",
      log._id?.toString()
    );
    console.log("   Level:", log.level);
    console.log("   Message:", log.message);

    const message = (log.message || "").toLowerCase();
    const keywords = (log.keyword || []).map((k) => (k || "").toLowerCase());

    console.log("   Keywords:", keywords);

    // Find suspicious keywords
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter((keyword) => {
      const foundInMessage = message.includes(keyword);
      const foundInKeywords = keywords.some(
        (k) => k.includes(keyword) || keyword.includes(k)
      );
      return foundInMessage || foundInKeywords;
    });

    console.log("   Found suspicious keywords:", foundKeywords);

    // =========================================================
    // 🔥 If suspicious → create ALERT
    // =========================================================
    if (
      foundKeywords.length > 0 ||
      log.level === "suspicious" ||
      log.level === "error" ||
      log.level === "warning"
    ) {
      // Determine severity
      let severity = "low";

      if (
        log.level === "suspicious" ||
        foundKeywords.some((k) =>
          ["critical", "exploit", "breach", "attack"].includes(k)
        )
      ) {
        severity = "critical";
      } else if (
        foundKeywords.some((k) =>
          ["sql injection", "xss", "malware", "virus", "hack"].includes(k)
        ) ||
        log.level === "error"
      ) {
        severity = "high";
      } else if (
        foundKeywords.some((k) =>
          ["warning", "unauthorized", "intrusion"].includes(k)
        ) ||
        log.level === "warning"
      ) {
        severity = "medium";
      }

      console.log("   Computed alert severity:", severity);

      // Create alert in DB
      const alert = await Alert.create({
        logId: log._id,
        severity,
        title: `Suspicious Activity Detected: ${String(
          log.level || ""
        ).toUpperCase()}`,
        description: log.message || "",
        keywords:
          foundKeywords.length > 0 ? foundKeywords : [log.level || "suspicious"],
      });

      console.log("✅ Alert created with ID:", alert._id.toString());

      // =========================================================
      // 🔥 REAL-TIME ALERT EMIT — Safe Location (after initSocket)
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
        console.log("📡 Real-time alert emitted");
      } catch (emitErr) {
        console.log("⚠️ Socket not ready yet, skipping real-time emit");
      }

      // =========================================================
      // 📧 Send Email Notification
      // =========================================================
      console.log(
        "📧 Sending email notification to:",
        userEmail || process.env.ADMIN_EMAIL || process.env.EMAIL_USER
      );

      await sendAlertEmail(alert, log, userEmail);

      return alert;
    }

    console.log("ℹ️ No alert created (no suspicious activity)");
    return null;
  } catch (error) {
    console.error("❌ checkSuspiciousActivity error:", error);
    return null;
  }
};

// =========================================================
// 📧 SEND ALERT EMAIL
// =========================================================
const sendAlertEmail = async (alert, log, userEmail = null) => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL;
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
