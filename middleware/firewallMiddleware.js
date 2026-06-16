import { detectFirewallThreats, saveFirewallIncidentsAndNotify } from "../utils/firewallUtils.js";
import Log from "../models/Log.js";
import { checkSuspiciousActivity } from "../utils/alertUtils.js";

// ── Log helper ──
const createLog = async (level, message, keyword = [], ipAddress = "System", userAgent = "System", metadata = {}) => {
  try {
    const log = await Log.create({ level, message, keyword, ipAddress, userAgent, metadata });
    if (["warning", "error", "suspicious"].includes(level)) {
      checkSuspiciousActivity(log, null).catch(() => {});
    }
  } catch (err) { console.error("createLog error:", err.message); }
};

const getClientIp = (req) => {
  const xfwd = req.headers["x-forwarded-for"];
  if (xfwd) return xfwd.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "Unknown";
};

export const firewallMiddleware = async (req, res, next) => {
  try {
    const path = req.originalUrl || "";

    // Is module ki apni APIs ko skip kar do
    if (path.startsWith("/api/firewall")) {
      return next();
    }

    const findings = detectFirewallThreats(req);

    if (findings.length > 0) {
      req.firewallFindings = findings;
      await saveFirewallIncidentsAndNotify(req, findings);

      // LOG: firewall blocked
      const ip    = getClientIp(req);
      const types = findings.map((f) => f.attackType || f.type || "threat").join(", ");
      await createLog(
        "suspicious",
        `Firewall blocked ${findings.length} threat(s) from ${ip} on ${path}: ${types}`,
        ["firewall", "blocked", ...findings.map((f) => (f.attackType || "threat").toLowerCase().replace(/\s+/g, "-"))],
        ip, req.headers["user-agent"] || "Unknown",
        { path, method: req.method, findings: findings.length, types }
      );
    }

    next();
  } catch (error) {
    console.error("Firewall middleware error:", error.message);
    next();
  }
};