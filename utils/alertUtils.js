import Alert from "../models/Alert.js";
import { transporter } from "../config/mailer.js";

// Suspicious keywords that trigger alerts
const SUSPICIOUS_KEYWORDS = [
  "critical", "vulnerability", "exploit", "sql injection", "xss", "csrf", 
  "malware", "virus", "hack", "breach", "attack", "intrusion", "malicious",
  "phishing", "backdoor", "trojan", "ransomware", "ddos", "brute force",
  "injection", "shell", "payload", "penetration", "unauthorized", "high",
  "medium", "low", "error", "warning", "suspicious"
];

// Check if log contains suspicious activity
export const checkSuspiciousActivity = async (log, userEmail = null) => {
  try {
    if (!log) {
      console.log("⚠️ checkSuspiciousActivity called with no log");
      return null;
    }

    console.log("🔍 Checking suspicious activity for log ID:", log._id?.toString());
    console.log("   Level:", log.level);
    console.log("   Message:", log.message);

    const message = (log.message || "").toLowerCase();
    const keywords = (log.keyword || []).map(k => (k || "").toLowerCase());

    console.log("   Keywords:", keywords);

    // Check for suspicious keywords in message and keywords array
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(keyword => {
      const foundInMessage = message.includes(keyword);
      const foundInKeywords = keywords.some(k => k.includes(keyword) || keyword.includes(k));
      return foundInMessage || foundInKeywords;
    });

    console.log("   Found suspicious keywords:", foundKeywords);

    // Create alert if suspicious keywords found OR log level is suspicious/error/warning
    if (
      foundKeywords.length > 0 ||
      log.level === "suspicious" ||
      log.level === "error" ||
      log.level === "warning"
    ) {
      // Determine severity based on keywords and log level
      let severity = "low";

      if (
        log.level === "suspicious" ||
        foundKeywords.some(k => ["critical", "exploit", "breach", "attack"].includes(k))
      ) {
        severity = "critical";
      } else if (
        foundKeywords.some(k => ["sql injection", "xss", "malware", "virus", "hack"].includes(k)) ||
        log.level === "error"
      ) {
        severity = "high";
      } else if (
        foundKeywords.some(k => ["warning", "unauthorized", "intrusion"].includes(k)) ||
        log.level === "warning"
      ) {
        severity = "medium";
      }

      console.log("   Computed alert severity:", severity);

      // Create alert in DB
      const alert = await Alert.create({
        logId: log._id,
        severity,
        title: `Suspicious Activity Detected: ${String(log.level || "").toUpperCase()}`,
        description: log.message || "",
        keywords: foundKeywords.length > 0 ? foundKeywords : [log.level || "suspicious"]
      });

      console.log("✅ Alert created with ID:", alert._id.toString());

      // 🔥 IMPORTANT CHANGE:
      // Now prefer emailing the logged-in user (userEmail) and fall back to admin/email user
      console.log("📧 Triggering alert email for severity:", severity, "target:", userEmail || process.env.ADMIN_EMAIL || process.env.EMAIL_USER);
      await sendAlertEmail(alert, log, userEmail);

      return alert;
    }

    console.log("ℹ️ No alert created - no suspicious activity detected for this log");
    return null;
  } catch (error) {
    console.error("❌ Check suspicious activity error:", error);
    return null;
  }
};

// Send alert email
const sendAlertEmail = async (alert, log, userEmail = null) => {
  try {
    if (!transporter) {
      console.error("❌ Transporter is not initialized");
      return;
    }

    const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
    const toEmail = userEmail || adminEmail;

    if (!toEmail) {
      console.error("❌ No recipient configured (userEmail or ADMIN_EMAIL / EMAIL_USER missing)");
      return;
    }

    const subject = `🚨 ${alert.severity.toUpperCase()} Security Alert - SEO Intrusion Detector`;

    console.log("📧 Preparing to send alert email:");
    console.log("   To      :", toEmail);
    console.log("   From    :", process.env.EMAIL_USER);
    console.log("   Subject :", subject);

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9fafb; border-radius: 10px;">
        <div style="background-color: ${alert.severity === 'critical' ? '#dc2626' : '#ea580c'}; color: white; padding: 20px; border-radius: 10px 10px 0 0; text-align: center;">
          <h1 style="margin: 0;">🚨 Security Alert</h1>
        </div>
        <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #dc2626; margin-top: 0;">${alert.title}</h2>
          
          <div style="background-color: #fee2e2; border-left: 4px solid #dc2626; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; font-weight: bold; color: #991b1b;">Severity: ${alert.severity.toUpperCase()}</p>
          </div>

          <h3 style="color: #374151;">Details:</h3>
          <ul style="color: #6b7280; line-height: 1.8;">
            <li><strong>Log Level:</strong> ${log.level}</li>
            <li><strong>Message:</strong> ${log.message}</li>
            <li><strong>Time:</strong> ${new Date(log.createdAt).toLocaleString()}</li>
            ${log.ipAddress ? `<li><strong>IP Address:</strong> ${log.ipAddress}</li>` : ""}
            ${log.url ? `<li><strong>URL:</strong> ${log.url}</li>` : ""}
            ${
              alert.keywords?.length
                ? `<li><strong>Detected Keywords:</strong> ${alert.keywords.join(", ")}</li>`
                : ""
            }
          </ul>

          <div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #92400e;">
              <strong>⚠️ Action Required:</strong> Please review this activity immediately in your dashboard.
            </p>
          </div>

          <a href="${process.env.FRONTEND_URL || "http://localhost:5173"}/alerts" 
             style="display: inline-block; background-color: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 10px; font-weight: bold;">
            View Alert
          </a>

          <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
          
          <p style="color: #6b7280; font-size: 12px; line-height: 1.6; margin: 0;">
            This is an automated security alert from SEO Intrusion Detector.<br>
            © 2025 SEO Intrusion Detector. All rights reserved.
          </p>
        </div>
      </div>
    `;

    const text = `
Security Alert - ${alert.severity.toUpperCase()}

${alert.title}

Details:
- Log Level: ${log.level}
- Message: ${log.message}
- Time: ${new Date(log.createdAt).toLocaleString()}
${log.ipAddress ? `- IP Address: ${log.ipAddress}` : ""}
${alert.keywords?.length ? `- Keywords: ${alert.keywords.join(", ")}` : ""}

Please review this activity immediately in your dashboard.
    `;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: toEmail,
      subject,
      html,
      text
    });

    console.log(`✅ Alert email sent successfully to ${toEmail} for ${alert.severity} severity alert`);
  } catch (error) {
    console.error("❌ Send alert email error:", error);
  }
};

// Check for patterns (placeholder)
export const detectPatterns = async (userId, eventType) => {
  // Pattern detection implementation (can be added later)
};

export default { checkSuspiciousActivity, detectPatterns };


