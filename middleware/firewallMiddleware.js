import { detectFirewallThreats, saveFirewallIncidentsAndNotify } from "../utils/firewallUtils.js";

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
    }

    next();
  } catch (error) {
    console.error("Firewall middleware error:", error.message);
    next();
  }
};