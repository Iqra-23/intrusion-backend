// controllers/logController.js
import Log from "../models/Log.js";
import Alert from "../models/Alert.js";
import { checkSuspiciousActivity } from "../utils/alertUtils.js";

// ✅ Create log with automatic suspicious activity detection
export const createLog = async (req, res) => {
  try {
    const {
      level,
      message,
      keyword,
      ipAddress,
      userAgent,
      url,
      method,
      statusCode,
      metadata,
    } = req.body;

    console.log("📝 Creating log:", { level, message });

    const log = await Log.create({
      level,
      message,
      keyword,
      ipAddress,
      userAgent,
      url,
      method,
      statusCode,
      userId: req.user?._id,
      metadata,
    });

    console.log("✅ Log created:", log._id);

    console.log("🔍 Checking for suspicious activity...");
    if (level === "suspicious" || level === "error" || level === "warning") {
      console.log(
        "⚠️ Level triggers alert check, calling checkSuspiciousActivity..."
      );
      const alert = await checkSuspiciousActivity(log);
      console.log("📢 Alert result:", alert ? "Created" : "Not created");
    }

    res.status(201).json(log);
  } catch (error) {
    console.error("❌ Create log error:", error);
    res.status(500).json({ message: "Failed to create log" });
  }
};

// ✅ Get logs
export const getLogs = async (req, res) => {
  try {
    const {
      q,
      level,
      startDate,
      endDate,
      archived,
      page = 1,
      limit = 50,
    } = req.query;

    const filter = {};

    if (q) {
      filter.$or = [
        { message: new RegExp(q, "i") },
        { keyword: new RegExp(q, "i") },
      ];
    }

    if (level && level !== "all") {
      filter.level = level;
    }

    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }

    if (archived === "true") {
      filter.archived = true;
    } else {
      filter.archived = false;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const logs = await Log.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate("userId", "name email");

    const total = await Log.countDocuments(filter);

    res.json({
      logs,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / parseInt(limit)),
        limit: parseInt(limit),
      },
    });
  } catch (error) {
    console.error("❌ Get logs error:", error);
    res.status(500).json({ message: "Failed to fetch logs" });
  }
};

// ✅ Get stats
export const getLogStats = async (req, res) => {
  try {
    const [total, errors, warnings, suspicious, archived] = await Promise.all([
      Log.countDocuments({ archived: false }),
      Log.countDocuments({ level: "error", archived: false }),
      Log.countDocuments({ level: "warning", archived: false }),
      Log.countDocuments({ level: "suspicious", archived: false }),
      Log.countDocuments({ archived: true }),
    ]);

    res.json({
      total,
      errors,
      warnings,
      suspicious,
      archived,
    });
  } catch (error) {
    console.error("❌ Get stats error:", error);
    res.status(500).json({ message: "Failed to fetch statistics" });
  }
};

// ✅ Archive logs
export const archiveLogs = async (req, res) => {
  try {
    const { logIds, autoArchive } = req.body;

    let result;
    if (autoArchive) {
      result = await Log.archiveOldLogs();
    } else if (logIds && logIds.length > 0) {
      result = await Log.updateMany(
        { _id: { $in: logIds } },
        { $set: { archived: true, archivedAt: new Date() } }
      );
    } else {
      return res.status(400).json({ message: "No logs specified" });
    }

    res.json({
      message: "Logs archived successfully",
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("❌ Archive error:", error);
    res.status(500).json({ message: "Failed to archive logs" });
  }
};

// ✅ Restore logs
export const restoreLogs = async (req, res) => {
  try {
    const { logIds } = req.body;

    const result = await Log.updateMany(
      { _id: { $in: logIds } },
      { $set: { archived: false }, $unset: { archivedAt: 1 } }
    );

    res.json({
      message: "Logs restored successfully",
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("❌ Restore error:", error);
    res.status(500).json({ message: "Failed to restore logs" });
  }
};

// ✅ Delete old logs
export const cleanupLogs = async (req, res) => {
  try {
    const result = await Log.deleteOldArchivedLogs();

    res.json({
      message: "Logs deleted successfully",
      deletedCount: result.deletedCount,
    });
  } catch (error) {
    console.error("❌ Cleanup error:", error);
    res.status(500).json({ message: "Failed to cleanup logs" });
  }
};

// ✅ Bulk delete logs
export const bulkDeleteLogs = async (req, res) => {
  try {
    const { ids } = req.body;

    console.log("📦 Bulk delete logs request:", { idsCount: ids?.length });

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No log IDs provided",
      });
    }

    const mongoose = await import("mongoose");
    const validIds = ids.filter((id) => mongoose.Types.ObjectId.isValid(id));

    if (validIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No valid log IDs provided",
      });
    }

    const logs = await Log.find({
      _id: { $in: validIds },
    }).select("level message");

    const result = await Log.deleteMany({
      _id: { $in: validIds },
    });

    console.log(
      `✅ Bulk delete: ${result.deletedCount} logs deleted by user ${req.user._id}`
    );

    res.json({
      success: true,
      message: `${result.deletedCount} logs deleted successfully`,
      deletedCount: result.deletedCount,
      requestedCount: ids.length,
    });
  } catch (err) {
    console.error("❌ Bulk Delete Logs Error:", err);
    res.status(500).json({
      success: false,
      message: "Error deleting logs",
      error: err.message,
    });
  }
};

// ✅ Delete a specific log
export const deleteLog = async (req, res) => {
  try {
    console.log("🗑️ Single delete log request for ID:", req.params.id);

    const log = await Log.findById(req.params.id);

    if (!log) {
      return res.status(404).json({
        success: false,
        message: "Log not found",
      });
    }

    const logInfo = {
      id: log._id,
      level: log.level,
      message: log.message,
      createdAt: log.createdAt,
    };

    await log.deleteOne();

    console.log(`✅ Log ${logInfo.id} deleted by user ${req.user._id}`);

    res.json({
      success: true,
      message: "Log deleted successfully",
    });
  } catch (err) {
    console.error("❌ Delete Log Error:", err);
    res.status(500).json({
      success: false,
      message: "Error deleting log",
      error: err.message,
    });
  }
};

// ✅ Get alerts
export const getAlerts = async (req, res) => {
  try {
    console.log("📢 Fetching alerts...");

    const { acknowledged, severity } = req.query;

    const filter = {};
    if (acknowledged !== undefined) {
      filter.acknowledged = acknowledged === "true";
    }
    if (severity) {
      filter.severity = severity;
    }

    console.log("🔍 Alert filter:", filter);

    const alerts = await Alert.find(filter)
      .sort({ createdAt: -1 })
      .populate("logId")
      .populate("acknowledgedBy", "name email")
      .limit(100);

    console.log("✅ Found alerts:", alerts.length);

    res.json(alerts);
  } catch (error) {
    console.error("❌ Get alerts error:", error);
    res.status(500).json({ message: "Failed to fetch alerts" });
  }
};

// ✅ Acknowledge alert
export const acknowledgeAlert = async (req, res) => {
  try {
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      {
        acknowledged: true,
        acknowledgedBy: req.user._id,
        acknowledgedAt: new Date(),
      },
      { new: true }
    );

    if (!alert) {
      return res.status(404).json({ message: "Alert not found" });
    }

    res.json(alert);
  } catch (error) {
    console.error("❌ Acknowledge error:", error);
    res.status(500).json({ message: "Failed to acknowledge alert" });
  }
};

// ✅ Resolve alert
export const resolveAlert = async (req, res) => {
  try {
    const alert = await Alert.findByIdAndUpdate(
      req.params.id,
      {
        resolved: true,
        resolvedAt: new Date(),
      },
      { new: true }
    );

    if (!alert) {
      return res.status(404).json({ message: "Alert not found" });
    }

    res.json(alert);
  } catch (error) {
    console.error("❌ Resolve error:", error);
    res.status(500).json({ message: "Failed to resolve alert" });
  }
};

// ✅ Delete alert
export const deleteAlert = async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);

    if (!alert) {
      return res.status(404).json({ message: "Alert not found" });
    }

    await alert.deleteOne();

    res.json({
      success: true,
      message: "Alert deleted successfully",
    });
  } catch (error) {
    console.error("❌ Delete alert error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete alert",
      error: error.message,
    });
  }
};
