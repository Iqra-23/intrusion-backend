import detectSpike from "../utils/detectSpike.js";
import { lookupGeo } from "../utils/ipGeo.js";
import TrafficEvent from "../models/TrafficEvent.js";
import { v4 as uuidv4 } from "uuid";

/**
 * Traffic Middleware
 * Logs:
 * - IP + Headers
 * - Session tracking
 * - Geo location
 * - Spike detection
 * - Module name (FIXED)
 */
export const trafficMiddleware = async (req, res, next) => {
  const startTime = Date.now();

  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket?.remoteAddress ||
    "Unknown";

  const method = req.method;
  const path = req.originalUrl;
  const userAgent = req.headers["user-agent"] || "-";

  // ✅ SESSION ID FIX
  let sessionId =
    req.headers["x-session-id"] ||
    req.cookies?.sessionId ||
    req.session?.id;

  if (!sessionId) {
    sessionId = uuidv4(); // fallback so frontend never shows "-"
  }

  // ✅ REFERRER FIX
  const referrer =
    req.headers["referer"] ||
    req.headers["referrer"] ||
    null;

  // ✅ MODULE FIX
  const module = detectModule(path);

  res.on("finish", async () => {
    try {
      const status = res.statusCode;
      const geo = await lookupGeo(ip);
      const isSpike = detectSpike(ip);
      const durationMs = Date.now() - startTime;

      await TrafficEvent.create({
        ip,
        method,
        path,
        status,
        module,              // ✅ FIXED
        sessionId,           // ✅ FIXED
        referrer,            // ✅ FIXED
        userAgent,
        headers: req.headers, // already used in View Details
        durationMs,
        geo,
        isSpike,
        tags: isSpike ? ["spike"] : [],
      });
    } catch (err) {
      console.log("Traffic save error:", err.message);
    }
  });

  next();
};

/**
 * Detect module name from API path
 * This fixes "Unknown Module" everywhere
 */
function detectModule(path = "") {
  if (path.startsWith("/api/auth")) return "Auth";
  if (path.startsWith("/api/logs")) return "Log Management";
  if (path.startsWith("/api/vulnerabilities")) return "Vulnerability Scanner";
  if (path.startsWith("/api/traffic")) return "Traffic Monitor";
  if (path.startsWith("/api/dashboard")) return "Dashboard";

  return "Other";
}
