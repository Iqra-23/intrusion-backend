// controllers/trafficController.js
import fs from "fs";
import TrafficEvent from "../models/TrafficEvent.js";
import { lookupGeo } from "../utils/ipGeo.js";
import { generateTrafficReport } from "../utils/trafficReportGenerator.js";

// simple in-memory request counter: { "ip:minuteKey": count }
const ipCounter = new Map();
const SPIKE_THRESHOLD = 100; // 100 requests per minute from same IP => spike

// some high-risk keywords for anomaly detection
const SUSPICIOUS_PATTERNS = [
  "select ",
  "union ",
  " or 1=1",
  "../",
  "<script",
  " onerror=",
  " drop ",
  "insert into",
  "xp_cmdshell",
  "admin",
  "config.php",
  "wp-admin",
];

const HIGH_RISK_COUNTRIES = ["CN", "RU", "KP", "IR", "SY", "PK"]; // you can adjust

// ====== HELPERS ======

const getClientIp = (req) => {
  const xfwd = req.headers["x-forwarded-for"];
  if (xfwd) {
    return xfwd.split(",")[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || "";
};

/**
 * Simple heuristic anomaly score (0–100)
 * FEATURE: Traffic anomaly detection
 */
const computeAnomalyScore = ({
  method,
  path,
  status,
  ip,
  geo,
  isSpike,
  userAgent,
}) => {
  let score = 0;
  const reasons = [];

  if (isSpike) {
    score += 40;
    reasons.push("High request rate (spike)");
  }

  if (status >= 500) {
    score += 30;
    reasons.push("5xx server error");
  } else if (status >= 400) {
    score += 20;
    reasons.push("4xx client error");
  }

  if (["PUT", "DELETE", "PATCH"].includes(method)) {
    score += 10;
    reasons.push(`High-impact HTTP method: ${method}`);
  } else if (method === "POST") {
    score += 5;
    reasons.push("Write operation (POST)");
  }

  const lowerPath = (path || "").toLowerCase();
  if (SUSPICIOUS_PATTERNS.some((p) => lowerPath.includes(p))) {
    score += 15;
    reasons.push("Suspicious pattern in path (possible injection/XSS)");
  }

  const country = geo?.country || "";
  if (country && HIGH_RISK_COUNTRIES.includes(country)) {
    score += 10;
    reasons.push(`High-risk geo region: ${country}`);
  }

  const ua = (userAgent || "").toLowerCase();
  if (!ua || ua.includes("curl") || ua.includes("bot") || ua.includes("scanner")) {
    score += 10;
    reasons.push("Non-browser / bot-like user agent");
  }

  score = Math.min(100, Math.max(0, score));
  return { score, reasons };
};

// ====== MIDDLEWARE: log every request ======
/**
 * FEATURE:
 * - Logging IP + headers
 * - Session tracking
 * - Geo lookup
 * - Anomaly detection
 * - Spike detection
 */
export const trafficLogger = async (req, res, next) => {
  const ip = getClientIp(req);
  const method = req.method;
  const path = req.originalUrl || req.url;
  const userAgent = req.headers["user-agent"] || "";
  const referrer = req.headers["referer"] || req.headers["referrer"] || "";
  const userId = req.user?._id || null;

  // Basic pseudo-session: priority = real sessionID / x-session-id / fallback
  const sessionId =
    req.sessionID ||
    req.headers["x-session-id"] ||
    `${ip}-${(userAgent || "").slice(0, 40)}`;

  // skip own traffic APIs if you want
  if (path.startsWith("/api/traffic")) {
    return next();
  }

  // status capture when response finishes
  res.on("finish", async () => {
    try {
      const status = res.statusCode;

      // 🔹 GEO LOOKUP (FEATURE)
      const geo = await lookupGeo(ip);

      // 🔹 spike detection: 1-minute bucket per IP
      const minuteKey = new Date().toISOString().slice(0, 16); // "YYYY-MM-DDTHH:MM"
      const key = `${ip}:${minuteKey}`;
      const prevCount = ipCounter.get(key) || 0;
      const newCount = prevCount + 1;
      ipCounter.set(key, newCount);

      let isSpike = false;
      const tags = [];

      if (newCount >= SPIKE_THRESHOLD) {
        isSpike = true;
        tags.push("spike");
      }
      if (status >= 500) {
        tags.push("server-error");
      } else if (status >= 400) {
        tags.push("client-error");
      }

      // 🔹 anomaly detection (FEATURE)
      const { score: anomalyScore, reasons: anomalyReasons } =
        computeAnomalyScore({
          method,
          path,
          status,
          ip,
          geo,
          isSpike,
          userAgent,
        });

      await TrafficEvent.create({
        ip,
        method,
        path,
        status,
        userAgent,
        headers: {
          // FEATURE: logging of request headers
          host: req.headers["host"],
          origin: req.headers["origin"],
          referer: referrer,
          "content-type": req.headers["content-type"],
          "accept-language": req.headers["accept-language"],
          "x-forwarded-for": req.headers["x-forwarded-for"],
        },
        userId,
        sessionId,
        geo,
        isSpike,
        tags,
        anomalyScore,
        anomalyReasons,
      });

      // NOTE: yahan chaho toh socket.io event ya log alerts bhi trigger kar sakti ho
      // e.g. spike ke waqt io.emit("traffic-spike", {...})
    } catch (err) {
      console.error("Traffic log save error:", err.message);
    } finally {
      if (ipCounter.size > 10000) {
        ipCounter.clear();
      }
    }
  });

  next();
};

/**
 * GET /api/traffic
 * Listing + filters + pagination
 */
export const getTrafficEvents = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      search = "",
      ip,
      country,
      method,
      path,
      status,
      spike,
      minAnomaly,
    } = req.query;

    const q = {};

    if (search) {
      q.$or = [
        { ip: { $regex: search, $options: "i" } },
        { path: { $regex: search, $options: "i" } },
        { userAgent: { $regex: search, $options: "i" } },
        { "geo.country": { $regex: search, $options: "i" } },
      ];
    }

    if (ip) q.ip = ip;
    if (country) q["geo.country"] = country;
    if (method) q.method = method.toUpperCase();
    if (path) q.path = { $regex: path, $options: "i" };
    if (status) q.status = Number(status);
    if (spike === "true") q.isSpike = true;
    if (minAnomaly) q.anomalyScore = { $gte: Number(minAnomaly) };

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    const [items, total] = await Promise.all([
      TrafficEvent.find(q).sort({ createdAt: -1 }).skip(skip).limit(limitNum),
      TrafficEvent.countDocuments(q),
    ]);

    res.json({
      events: items,
      pagination: {
        total,
        page: pageNum,
        pages: Math.ceil(total / limitNum),
        limit: limitNum,
      },
    });
  } catch (err) {
    console.error("getTrafficEvents error:", err.message);
    res.status(500).json({ message: "Error fetching traffic events" });
  }
};

/**
 * GET /api/traffic/stats
 * dashboard ke liye summary
 */
export const getTrafficStats = async (req, res) => {
  try {
    const total = await TrafficEvent.countDocuments();

    const uniqueIpsAgg = await TrafficEvent.aggregate([
      { $group: { _id: "$ip" } },
      { $count: "count" },
    ]);
    const uniqueIps = uniqueIpsAgg[0]?.count || 0;

    const byCountry = await TrafficEvent.aggregate([
      { $group: { _id: "$geo.country", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]);

    const byMethod = await TrafficEvent.aggregate([
      { $group: { _id: "$method", count: { $sum: 1 } } },
    ]);

    const last1hSpikes = await TrafficEvent.countDocuments({
      isSpike: true,
      createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) },
    });

    const recentSpikes = await TrafficEvent.find({ isSpike: true })
      .sort({ createdAt: -1 })
      .limit(20);

    // 🔹 anomaly stats (FEATURE: traffic anomaly detection)
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const highAnomalies24h = await TrafficEvent.countDocuments({
      createdAt: { $gte: last24h },
      anomalyScore: { $gte: 70 },
    });

    const avgAgg = await TrafficEvent.aggregate([
      { $group: { _id: null, avgScore: { $avg: "$anomalyScore" } } },
    ]);
    const avgAnomalyScore = avgAgg[0]?.avgScore || 0;

    res.json({
      total,
      uniqueIps,
      byCountry,
      byMethod,
      last1hSpikes,
      recentSpikes,
      highAnomalies24h,
      avgAnomalyScore,
    });
  } catch (err) {
    console.error("getTrafficStats error:", err.message);
    res.status(500).json({ message: "Error fetching traffic stats" });
  }
};

/**
 * GET /api/traffic/alerts
 * FEATURE: In-app notifications for traffic spikes
 */
export const getTrafficAlerts = async (req, res) => {
  try {
    const last15min = new Date(Date.now() - 15 * 60 * 1000);
    const alerts = await TrafficEvent.find({
      isSpike: true,
      createdAt: { $gte: last15min },
    })
      .sort({ createdAt: -1 })
      .limit(20);

    res.json(alerts);
  } catch (err) {
    console.error("getTrafficAlerts error:", err.message);
    res.status(500).json({ message: "Error fetching traffic alerts" });
  }
};

/**
 * GET /api/traffic/export
 * Export PDF report
 */
export const exportTrafficPdf = async (req, res) => {
  try {
    const { search = "", ip, country, method, path, status, minAnomaly } =
      req.query;

    const q = {};
    if (search) {
      q.$or = [
        { ip: { $regex: search, $options: "i" } },
        { path: { $regex: search, $options: "i" } },
        { userAgent: { $regex: search, $options: "i" } },
        { "geo.country": { $regex: search, $options: "i" } },
      ];
    }
    if (ip) q.ip = ip;
    if (country) q["geo.country"] = country;
    if (method) q.method = method.toUpperCase();
    if (path) q.path = { $regex: path, $options: "i" };
    if (status) q.status = Number(status);
    if (minAnomaly) q.anomalyScore = { $gte: Number(minAnomaly) };

    const events = await TrafficEvent.find(q)
      .sort({ createdAt: -1 })
      .limit(1000)
      .lean();

    if (!events || events.length === 0) {
      return res.status(404).json({
        message: "No traffic events found to export for the selected filters",
      });
    }

    const reportsDir = "./reports";
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    const fileName = `traffic_report_${Date.now()}.pdf`;
    const filePath = `${reportsDir}/${fileName}`;

    await generateTrafficReport(
      events,
      { search, ip, country, method, path, status, minAnomaly },
      filePath
    );

    res.download(filePath, fileName, (err) => {
      if (err) {
        console.error("❌ Traffic PDF download error:", err);
      }
      setTimeout(() => {
        try {
          if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        } catch (cleanupErr) {
          console.error("Traffic PDF cleanup error:", cleanupErr);
        }
      }, 5000);
    });
  } catch (e) {
    console.error("exportTrafficPdf error:", e.message);
    res.status(500).json({
      message: "Error generating traffic PDF report",
      error: e.message,
    });
  }
};

// DELETE /api/traffic (all or by ids)
export const deleteTrafficEvents = async (req, res) => {
  try {
    const { ids } = req.body || {};

    let filter = {};
    if (Array.isArray(ids) && ids.length > 0) {
      filter = { _id: { $in: ids } };
    }

    const result = await TrafficEvent.deleteMany(filter);

    return res.json({
      message: "Traffic events deleted successfully",
      deletedCount: result.deletedCount,
    });
  } catch (err) {
    console.error("deleteTrafficEvents error:", err.message);
    return res
      .status(500)
      .json({ message: "Error deleting traffic events" });
  }
};
