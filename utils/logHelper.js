// utils/logHelper.js
// Central logging helper — use this in all controllers
// Automatically creates a Log entry and triggers alert if needed

import Log from "../models/Log.js";
import { checkSuspiciousActivity } from "./alertUtils.js";

/**
 * createLog(level, message, keywords, ipAddress, userAgent, metadata)
 * level: "info" | "warning" | "error" | "suspicious"
 */
export const createLog = async (
  level = "info",
  message = "",
  keywords = [],
  ipAddress = "System",
  userAgent = "System",
  metadata = {}
) => {
  try {
    const log = await Log.create({
      level,
      message,
      keyword: Array.isArray(keywords) ? keywords : [keywords],
      ipAddress: ipAddress || "System",
      userAgent: userAgent || "System",
      metadata,
    });

    // Auto-trigger alert for suspicious/warning/error logs
    if (["warning", "error", "suspicious"].includes(level)) {
      const userEmail = metadata?.userEmail || null;
      checkSuspiciousActivity(log, userEmail).catch((err) =>
        console.error("Alert check error:", err.message)
      );
    }

    return log;
  } catch (err) {
    // Never crash the main flow because of logging
    console.error("createLog error:", err.message);
    return null;
  }
};