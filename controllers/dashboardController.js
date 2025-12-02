// controllers/dashboardController.js
import fs from "fs";
import Log from "../models/Log.js";
import TrafficEvent from "../models/TrafficEvent.js";
import Vulnerability from "../models/Vulnerability.js";
import Alert from "../models/Alert.js";
import ScanHistory from "../models/ScanHistory.js";
import { generateDashboardReport } from "../utils/dashboardReportGenerator.js";

// internal helper – same data used for /stats & /export
const buildDashboardData = async (userId) => {
  const now = new Date();
  const since7Days = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const since24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  // SUMMARY COUNTS
  const [
    totalLogs,
    errorLogs,
    warningLogs,
    suspiciousLogs,
    activeAlerts,
    openVulns,
    uniqueIpsAgg,
  ] = await Promise.all([
    Log.countDocuments({}),
    Log.countDocuments({ level: "error" }),
    Log.countDocuments({ level: "warning" }),
    Log.countDocuments({ level: "suspicious" }),
    Alert.countDocuments({ resolved: { $ne: true } }),
    Vulnerability.countDocuments({ status: { $ne: "Resolved" } }),
    TrafficEvent.aggregate([
      { $match: { createdAt: { $gte: since24h } } },
      { $group: { _id: "$ip" } },
      { $count: "count" },
    ]),
  ]);

  const uniqueIps = uniqueIpsAgg[0]?.count || 0;

  // TRAFFIC TREND (LAST 7 DAYS)
  const trafficAgg = await TrafficEvent.aggregate([
    { $match: { createdAt: { $gte: since7Days } } },
    {
      $group: {
        _id: {
          $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
        },
        total: { $sum: 1 },
        spikes: {
          $sum: { $cond: [{ $eq: ["$isSpike", true] }, 1, 0] },
        },
      },
    },
    { $sort: { _id: 1 } },
  ]);

  const trafficTrend = trafficAgg.map((d) => ({
    date: d._id,
    total: d.total,
    spikes: d.spikes,
  }));

  // VULNERABILITY SEVERITY COUNTS
  const vulnAgg = await Vulnerability.aggregate([
    {
      $group: {
        _id: "$severity",
        count: { $sum: 1 },
      },
    },
  ]);

  const vulnSeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  vulnAgg.forEach((v) => {
    const sev = (v._id || "").toLowerCase();
    if (sev === "critical") vulnSeverity.critical = v.count;
    if (sev === "high") vulnSeverity.high = v.count;
    if (sev === "medium") vulnSeverity.medium = v.count;
    if (sev === "low") vulnSeverity.low = v.count;
  });

  // RECENT ALERTS
  const recentAlerts = await Alert.find({})
    .sort({ createdAt: -1 })
    .limit(10)
    .lean();

  // TOP COUNTRIES (LAST 7 DAYS)
  const topCountriesAgg = await TrafficEvent.aggregate([
    { $match: { createdAt: { $gte: since7Days } } },
    {
      $group: {
        _id: "$geo.country",
        count: { $sum: 1 },
      },
    },
    { $sort: { count: -1 } },
    { $limit: 7 },
  ]);

  const topCountries = topCountriesAgg.map((c) => ({
    country: c._id || "Unknown",
    count: c.count,
  }));

  // TOP PATHS (LAST 7 DAYS)
  const topPathsAgg = await TrafficEvent.aggregate([
    { $match: { createdAt: { $gte: since7Days } } },
    {
      $group: {
        _id: "$path",
        count: { $sum: 1 },
      },
    },
    { $sort: { count: -1 } },
    { $limit: 7 },
  ]);

  const topPaths = topPathsAgg.map((p) => ({
    path: p._id || "/",
    count: p.count,
  }));

  // RECENT SCANS (CURRENT USER)
  let recentScans = await ScanHistory.find({ userId })
    .sort({ startedAt: -1 })
    .limit(5)
    .lean();

  // optional: if scan has no vulnerabilities, still show in dashboard
  // (different from vulnerability stats page where you filtered them out)

  return {
    summary: {
      totalLogs,
      errorLogs,
      warningLogs,
      suspiciousLogs,
      activeAlerts,
      openVulnerabilities: openVulns,
      uniqueIps,
    },
    trafficTrend,
    vulnSeverity,
    recentAlerts,
    topCountries,
    topPaths,
    recentScans,
    generatedAt: now,
  };
};

// ================== CONTROLLERS ==================

// GET /api/dashboard/stats
export const getDashboardStats = async (req, res) => {
  try {
    const userId = req.user?._id;
    const data = await buildDashboardData(userId);
    return res.json(data);
  } catch (err) {
    console.error("❌ getDashboardStats error:", err);
    return res.status(500).json({
      message: "Failed to load dashboard statistics",
      error: err.message,
    });
  }
};

// GET /api/dashboard/export  -> PDF
export const exportDashboardPdf = async (req, res) => {
  try {
    const userId = req.user?._id;
    const data = await buildDashboardData(userId);

    const reportsDir = "./reports";
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    const fileName = `seo_dashboard_report_${Date.now()}.pdf`;
    const filePath = `${reportsDir}/${fileName}`;

    await generateDashboardReport(data, filePath);

    res.download(filePath, fileName, (err) => {
      if (err) {
        console.error("❌ Dashboard PDF download error:", err);
      }
      setTimeout(() => {
        try {
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }
        } catch (cleanupErr) {
          console.error("Dashboard PDF cleanup error:", cleanupErr);
        }
      }, 5000);
    });
  } catch (err) {
    console.error("❌ exportDashboardPdf error:", err);
    return res.status(500).json({
      message: "Failed to export dashboard report",
      error: err.message,
    });
  }
};
