import PDFDocument from "pdfkit";
import Threat from "../models/Threat.js";
import ThreatIPList from "../models/ThreatIPList.js";
import { predictThreatByAI } from "../services/threatAiService.js";
import { getIO } from "../utils/socket.js";

const ipActivity = new Map();

const AUTO_BLOCK_CONFIDENCE = 75;
const RATE_LIMIT_THRESHOLD = 30;
const FAILED_ATTEMPT_THRESHOLD = 5;

const getClientIp = (req) => {
  const xfwd = req.headers["x-forwarded-for"];
  if (xfwd) return xfwd.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "unknown";
};

const updateIpActivity = (ip, failed = false) => {
  const now = Date.now();
  const windowMs = 60 * 1000;

  if (!ipActivity.has(ip)) {
    ipActivity.set(ip, {
      timestamps: [],
      failedAttempts: 0,
    });
  }

  const data = ipActivity.get(ip);

  data.timestamps = data.timestamps.filter((t) => now - t < windowMs);
  data.timestamps.push(now);

  if (failed) data.failedAttempts += 1;

  return {
    requestCount: data.timestamps.length,
    failedAttempts: data.failedAttempts,
  };
};

const emitThreatAlert = (threat) => {
  try {
    const io = getIO();
    io.emit("threat-alert", threat);
  } catch (err) {
    console.log("Threat socket emit skipped:", err.message);
  }
};

const autoBlacklistIp = async (ip, reason) => {
  return ThreatIPList.findOneAndUpdate(
    { ip },
    {
      ip,
      listType: "blacklist",
      reason,
    },
    { new: true, upsert: true }
  );
};

export const saveIpRule = async (req, res) => {
  try {
    const { ip, listType, reason } = req.body;

    if (!ip || !listType) {
      return res.status(400).json({
        message: "IP and listType are required",
      });
    }

    if (!["blacklist", "whitelist"].includes(listType)) {
      return res.status(400).json({
        message: "listType must be blacklist or whitelist",
      });
    }

    const record = await ThreatIPList.findOneAndUpdate(
      { ip },
      {
        ip,
        listType,
        reason: reason || "Manual access control rule added",
      },
      { new: true, upsert: true }
    );

    res.json({
      success: true,
      message: "IP rule saved successfully",
      data: record,
    });
  } catch (err) {
    console.error("saveIpRule error:", err.message);
    res.status(500).json({
      message: "Failed to save IP rule",
    });
  }
};

export const detectThreat = async (req, res) => {
  try {
    const ip = req.body.ip || getClientIp(req);
    const {
      url = "/",
      method = "GET",
      payload = "",
      failed = false,
    } = req.body;

    const listedIp = await ThreatIPList.findOne({ ip });

    if (listedIp?.listType === "whitelist") {
      return res.json({
        success: true,
        bypassed: true,
        message: "Whitelisted IP allowed",
        ipRule: listedIp,
      });
    }

    if (listedIp?.listType === "blacklist") {
      const threat = await Threat.create({
        ip,
        url,
        method,
        payload,
        attackType: "suspicious-ip",
        confidence: 100,
        threatScore: 100,
        threatLevel: "HIGH",
        action: "block",
        requestCount: 0,
        failedAttempts: 0,
        reason: "IP already exists in blacklist",
      });

      emitThreatAlert(threat);

      return res.status(403).json({
        success: false,
        message: "Blocked blacklisted IP",
        threat,
      });
    }

    const activity = updateIpActivity(ip, failed);

    let aiResult = await predictThreatByAI({
      url,
      method,
      payload,
      requestCount: activity.requestCount,
      failedAttempts: activity.failedAttempts,
    });

    let autoBlocked = false;
    let autoBlockReason = "";

    if (activity.requestCount >= RATE_LIMIT_THRESHOLD) {
      autoBlocked = true;
      autoBlockReason = `Rate limit threshold crossed: ${activity.requestCount} requests in 1 minute`;

      aiResult = {
        attackType: "rate-limit",
        confidence: 100,
        threatScore: 100,
        threatLevel: "HIGH",
        action: "block",
        reason: autoBlockReason,
      };
    }

    if (activity.failedAttempts >= FAILED_ATTEMPT_THRESHOLD) {
      autoBlocked = true;
      autoBlockReason = `Failed login threshold crossed: ${activity.failedAttempts} failed attempts`;

      aiResult = {
        attackType: "suspicious-ip",
        confidence: 100,
        threatScore: 100,
        threatLevel: "HIGH",
        action: "block",
        reason: autoBlockReason,
      };
    }

    if (
      aiResult.attackType !== "normal" &&
      aiResult.confidence >= AUTO_BLOCK_CONFIDENCE &&
      aiResult.threatLevel === "HIGH"
    ) {
      autoBlocked = true;
      autoBlockReason = `AI confidence threshold crossed: ${aiResult.confidence}% for ${aiResult.attackType}`;
      aiResult.action = "block";
      aiResult.reason = autoBlockReason;
    }

    if (autoBlocked) {
      await autoBlacklistIp(ip, autoBlockReason);
    }

    const threat = await Threat.create({
      ip,
      url,
      method,
      payload,
      attackType: aiResult.attackType,
      confidence: aiResult.confidence,
      threatScore: aiResult.threatScore,
      threatLevel: aiResult.threatLevel,
      action: aiResult.action,
      requestCount: activity.requestCount,
      failedAttempts: activity.failedAttempts,
      reason: aiResult.reason,
    });

    if (threat.threatLevel === "HIGH" || threat.action === "block") {
      emitThreatAlert(threat);
    }

    return res.json({
      success: true,
      autoBlocked,
      threat,
    });
  } catch (err) {
    console.error("detectThreat error:", err.message);
    return res.status(500).json({
      message: "Threat detection failed",
    });
  }
};

export const getThreats = async (req, res) => {
  try {
    const threats = await Threat.find().sort({ createdAt: -1 }).limit(100);
    res.json(threats);
  } catch (err) {
    console.error("getThreats error:", err.message);
    res.status(500).json({
      message: "Failed to fetch threats",
    });
  }
};

export const getThreatStats = async (req, res) => {
  try {
    const [
      total,
      high,
      medium,
      low,
      blocked,
      monitored,
      blacklisted,
      whitelisted,
    ] = await Promise.all([
      Threat.countDocuments(),
      Threat.countDocuments({ threatLevel: "HIGH" }),
      Threat.countDocuments({ threatLevel: "MEDIUM" }),
      Threat.countDocuments({ threatLevel: "LOW" }),
      Threat.countDocuments({ action: "block" }),
      Threat.countDocuments({ action: "monitor" }),
      ThreatIPList.countDocuments({ listType: "blacklist" }),
      ThreatIPList.countDocuments({ listType: "whitelist" }),
    ]);

    res.json({
      total,
      high,
      medium,
      low,
      blocked,
      monitored,
      blacklisted,
      whitelisted,
    });
  } catch (err) {
    console.error("getThreatStats error:", err.message);
    res.status(500).json({
      message: "Failed to fetch threat stats",
    });
  }
};

export const getIpLists = async (req, res) => {
  try {
    const lists = await ThreatIPList.find().sort({ createdAt: -1 });
    res.json(lists);
  } catch (err) {
    console.error("getIpLists error:", err.message);
    res.status(500).json({
      message: "Failed to fetch IP lists",
    });
  }
};

export const deleteIpFromList = async (req, res) => {
  try {
    const item = await ThreatIPList.findByIdAndDelete(req.params.id);

    if (!item) {
      return res.status(404).json({
        message: "IP rule not found",
      });
    }

    res.json({
      success: true,
      message: "IP removed from list",
    });
  } catch (err) {
    console.error("deleteIpFromList error:", err.message);
    res.status(500).json({
      message: "Failed to delete IP",
    });
  }
};

export const deleteThreat = async (req, res) => {
  try {
    const threat = await Threat.findByIdAndDelete(req.params.id);

    if (!threat) {
      return res.status(404).json({
        message: "Threat record not found",
      });
    }

    res.json({
      success: true,
      message: "Threat deleted successfully",
    });
  } catch (err) {
    console.error("deleteThreat error:", err.message);
    res.status(500).json({
      message: "Failed to delete threat",
    });
  }
};

export const bulkDeleteThreats = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        message: "No threat IDs provided",
      });
    }

    const result = await Threat.deleteMany({
      _id: { $in: ids },
    });

    res.json({
      success: true,
      message: `${result.deletedCount} threat records deleted`,
      deletedCount: result.deletedCount,
    });
  } catch (err) {
    console.error("bulkDeleteThreats error:", err.message);
    res.status(500).json({
      message: "Failed to delete selected threats",
    });
  }
};

const writeThreatPdf = (doc, threat, index = null) => {
  if (index !== null) {
    doc.fontSize(12).fillColor("#111827").text(`${index}. Threat Record`);
  } else {
    doc.fontSize(14).fillColor("#111827").text("Threat Record");
  }

  doc.moveDown(0.4);
  doc.fontSize(10).fillColor("#374151");
  doc.text(`IP Address: ${threat.ip || "-"}`);
  doc.text(`URL: ${threat.url || "-"}`);
  doc.text(`Method: ${threat.method || "-"}`);
  doc.text(`Attack Type: ${threat.attackType || "-"}`);
  doc.text(`Threat Level: ${threat.threatLevel || "-"}`);
  doc.text(`Action: ${threat.action || "-"}`);
  doc.text(`Confidence: ${threat.confidence || 0}%`);
  doc.text(`Request Count: ${threat.requestCount || 0}`);
  doc.text(`Failed Attempts: ${threat.failedAttempts || 0}`);
  doc.text(`Reason: ${threat.reason || "-"}`);
  doc.text(
    `Created At: ${
      threat.createdAt ? new Date(threat.createdAt).toLocaleString() : "-"
    }`
  );
  doc.moveDown(1);
};

export const exportThreatsPdf = async (req, res) => {
  try {
    const threats = await Threat.find().sort({ createdAt: -1 }).limit(200);

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=ai-threat-analysis-report.pdf"
    );

    const doc = new PDFDocument({
      margin: 40,
      size: "A4",
    });

    doc.pipe(res);

    doc
      .fontSize(22)
      .fillColor("#0EA5E9")
      .text("AI Threat Detection Report", { align: "center" });

    doc
      .fontSize(10)
      .fillColor("#6B7280")
      .text(`Generated: ${new Date().toLocaleString()}`, {
        align: "center",
      });

    doc.moveDown(2);

    const total = threats.length;
    const high = threats.filter((t) => t.threatLevel === "HIGH").length;
    const blocked = threats.filter((t) => t.action === "block").length;

    doc.fontSize(14).fillColor("#111827").text("Summary");
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor("#374151");
    doc.text(`Total Records: ${total}`);
    doc.text(`High Threats: ${high}`);
    doc.text(`Blocked Actions: ${blocked}`);
    doc.moveDown(1.5);

    if (threats.length === 0) {
      doc.text("No threat records found.");
    } else {
      threats.forEach((threat, index) => {
        if (doc.y > 700) doc.addPage();
        writeThreatPdf(doc, threat, index + 1);
      });
    }

    doc.end();
  } catch (err) {
    console.error("exportThreatsPdf error:", err.message);
    res.status(500).json({
      message: "Failed to export threats PDF",
    });
  }
};

export const exportSingleThreatPdf = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);

    if (!threat) {
      return res.status(404).json({
        message: "Threat record not found",
      });
    }

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=threat-${threat.ip || "record"}.pdf`
    );

    const doc = new PDFDocument({
      margin: 40,
      size: "A4",
    });

    doc.pipe(res);

    doc
      .fontSize(22)
      .fillColor("#0EA5E9")
      .text("Single Threat Analysis Report", { align: "center" });

    doc
      .fontSize(10)
      .fillColor("#6B7280")
      .text(`Generated: ${new Date().toLocaleString()}`, {
        align: "center",
      });

    doc.moveDown(2);

    writeThreatPdf(doc, threat);

    doc.end();
  } catch (err) {
    console.error("exportSingleThreatPdf error:", err.message);
    res.status(500).json({
      message: "Failed to export single threat PDF",
    });
  }
};