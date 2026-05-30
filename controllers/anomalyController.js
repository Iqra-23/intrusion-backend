import PDFDocument from "pdfkit";
import BaselineProfile from "../models/BaselineProfile.js";
import AnomalyRecord from "../models/AnomalyRecord.js";
import {
  calculateDeviation,
  calculateSeverity,
  calculateAnomalyScore,
  detectSeoKeywordHits,
  buildAnomalyReason,
} from "../services/anomalyService.js";
import { getIO } from "../utils/socket.js";

const emitAnomalyAlert = (record) => {
  try {
    const io = getIO();

    io.emit("anomaly-alert", {
      message: record.reason,
      anomalyType: record.anomalyType,
      severity: record.severity,
      ip: record.ip,
      createdAt: record.createdAt,
    });

    io.emit("new-alert", {
      title: "Anomaly Detected",
      severity: record.severity?.toLowerCase() || "medium",
      description: record.reason,
      createdAt: new Date(),
    });
  } catch (error) {
    console.log("Anomaly socket skipped:", error.message);
  }
};

const getOrCreateBaseline = async () => {
  let baseline = await BaselineProfile.findOne().sort({ createdAt: -1 });

  if (!baseline) {
    baseline = await BaselineProfile.create({
      label: "Normal Traffic Baseline",
      avgRequestsPerMinute: 10,
      avgLoginAttempts: 3,
      avgFailedLogins: 1,
      avgSeoKeywordHits: 3,
      thresholdMultiplier: 2,
    });
  }

  return baseline;
};

export const getBaseline = async (req, res) => {
  try {
    const baseline = await getOrCreateBaseline();

    res.json({
      success: true,
      baseline,
    });
  } catch (error) {
    console.error("getBaseline error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to fetch baseline",
    });
  }
};

export const updateBaseline = async (req, res) => {
  try {
    const {
      avgRequestsPerMinute,
      avgLoginAttempts,
      avgFailedLogins,
      avgSeoKeywordHits,
      thresholdMultiplier,
    } = req.body;

    const baseline = await BaselineProfile.findOneAndUpdate(
      {},
      {
        label: "Normal Traffic Baseline",
        avgRequestsPerMinute,
        avgLoginAttempts,
        avgFailedLogins,
        avgSeoKeywordHits,
        thresholdMultiplier,
      },
      { new: true, upsert: true }
    );

    res.json({
      success: true,
      message: "Baseline updated successfully",
      baseline,
    });
  } catch (error) {
    console.error("updateBaseline error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to update baseline",
    });
  }
};

export const analyzeAnomaly = async (req, res) => {
  try {
    const {
      ip = "127.0.0.1",
      requestCount = 0,
      loginAttempts = 0,
      failedLogins = 0,
      payload = "",
      url = "/",
      method = "GET",
    } = req.body;

    const baseline = await getOrCreateBaseline();

    const createdRecords = [];

    const loginCurrent = Number(loginAttempts) + Number(failedLogins);
    const loginBaseline =
      baseline.avgLoginAttempts + baseline.avgFailedLogins;

    const loginDeviation = calculateDeviation(loginCurrent, loginBaseline);

    if (loginCurrent > loginBaseline * baseline.thresholdMultiplier) {
      const score = calculateAnomalyScore({
        currentValue: loginCurrent,
        baselineValue: loginBaseline,
        deviation: loginDeviation,
        extraRisk: Number(failedLogins) > baseline.avgFailedLogins ? 15 : 0,
      });

      const record = await AnomalyRecord.create({
        ip,
        anomalyType: "unusual-login",
        severity: calculateSeverity(score),
        score,
        currentValue: loginCurrent,
        baselineValue: loginBaseline,
        deviation: loginDeviation,
        reason: buildAnomalyReason({
          type: "unusual-login",
          currentValue: loginCurrent,
          baselineValue: loginBaseline,
          deviation: loginDeviation,
        }),
        emailAlertSent: score >= 70,
        details: {
          loginAttempts,
          failedLogins,
          url,
          method,
        },
      });

      createdRecords.push(record);

      if (record.emailAlertSent) emitAnomalyAlert(record);
    }

    const reqCurrent = Number(requestCount);
    const reqBaseline = baseline.avgRequestsPerMinute;

    const reqDeviation = calculateDeviation(reqCurrent, reqBaseline);

    if (reqCurrent > reqBaseline * baseline.thresholdMultiplier) {
      const score = calculateAnomalyScore({
        currentValue: reqCurrent,
        baselineValue: reqBaseline,
        deviation: reqDeviation,
        extraRisk: 10,
      });

      const record = await AnomalyRecord.create({
        ip,
        anomalyType: "abnormal-request-frequency",
        severity: calculateSeverity(score),
        score,
        currentValue: reqCurrent,
        baselineValue: reqBaseline,
        deviation: reqDeviation,
        reason: buildAnomalyReason({
          type: "abnormal-request-frequency",
          currentValue: reqCurrent,
          baselineValue: reqBaseline,
          deviation: reqDeviation,
        }),
        emailAlertSent: score >= 70,
        details: {
          requestCount,
          url,
          method,
        },
      });

      createdRecords.push(record);

      if (record.emailAlertSent) emitAnomalyAlert(record);
    }

    const seoHits = detectSeoKeywordHits(payload);
    const seoBaseline = baseline.avgSeoKeywordHits;

    const seoDeviation = calculateDeviation(seoHits, seoBaseline);

    if (seoHits > seoBaseline) {
      const score = calculateAnomalyScore({
        currentValue: seoHits,
        baselineValue: seoBaseline,
        deviation: seoDeviation,
        extraRisk: 20,
      });

      const record = await AnomalyRecord.create({
        ip,
        anomalyType: "negative-seo-traffic",
        severity: calculateSeverity(score),
        score,
        currentValue: seoHits,
        baselineValue: seoBaseline,
        deviation: seoDeviation,
        reason: buildAnomalyReason({
          type: "negative-seo-traffic",
          currentValue: seoHits,
          baselineValue: seoBaseline,
          deviation: seoDeviation,
        }),
        emailAlertSent: score >= 70,
        details: {
          payload,
          url,
          method,
          seoHits,
        },
      });

      createdRecords.push(record);

      if (record.emailAlertSent) emitAnomalyAlert(record);
    }

    if (createdRecords.length === 0) {
      const record = await AnomalyRecord.create({
        ip,
        anomalyType: "normal-traffic",
        severity: "LOW",
        score: 10,
        currentValue: reqCurrent,
        baselineValue: reqBaseline,
        deviation: reqDeviation,
        reason: "Traffic behavior is within normal baseline.",
        emailAlertSent: false,
        details: {
          requestCount,
          loginAttempts,
          failedLogins,
          payload,
          url,
          method,
        },
      });

      createdRecords.push(record);
    }

    res.json({
      success: true,
      message: "Anomaly analysis completed",
      baseline,
      records: createdRecords,
    });
  } catch (error) {
    console.error("analyzeAnomaly error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to analyze anomaly",
    });
  }
};

export const getAnomalies = async (req, res) => {
  try {
    const records = await AnomalyRecord.find().sort({ createdAt: -1 }).limit(100);

    res.json({
      success: true,
      records,
    });
  } catch (error) {
    console.error("getAnomalies error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to fetch anomalies",
    });
  }
};

export const getAnomalyStats = async (req, res) => {
  try {
    const [
      total,
      unusualLogin,
      abnormalFrequency,
      negativeSeo,
      normalTraffic,
      high,
      alerts,
    ] = await Promise.all([
      AnomalyRecord.countDocuments(),
      AnomalyRecord.countDocuments({ anomalyType: "unusual-login" }),
      AnomalyRecord.countDocuments({ anomalyType: "abnormal-request-frequency" }),
      AnomalyRecord.countDocuments({ anomalyType: "negative-seo-traffic" }),
      AnomalyRecord.countDocuments({ anomalyType: "normal-traffic" }),
      AnomalyRecord.countDocuments({ severity: { $in: ["HIGH", "CRITICAL"] } }),
      AnomalyRecord.countDocuments({ emailAlertSent: true }),
    ]);

    res.json({
      total,
      unusualLogin,
      abnormalFrequency,
      negativeSeo,
      normalTraffic,
      high,
      alerts,
    });
  } catch (error) {
    console.error("getAnomalyStats error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to fetch anomaly stats",
    });
  }
};

export const deleteAnomaly = async (req, res) => {
  try {
    const record = await AnomalyRecord.findByIdAndDelete(req.params.id);

    if (!record) {
      return res.status(404).json({
        success: false,
        message: "Anomaly record not found",
      });
    }

    res.json({
      success: true,
      message: "Anomaly deleted successfully",
    });
  } catch (error) {
    console.error("deleteAnomaly error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to delete anomaly",
    });
  }
};

export const bulkDeleteAnomalies = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No anomaly IDs provided",
      });
    }

    const result = await AnomalyRecord.deleteMany({
      _id: { $in: ids },
    });

    res.json({
      success: true,
      message: `${result.deletedCount} anomaly records deleted`,
    });
  } catch (error) {
    console.error("bulkDeleteAnomalies error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to delete selected anomalies",
    });
  }
};

export const exportAnomalyPDF = async (req, res) => {
  try {
    const records = await AnomalyRecord.find().sort({ createdAt: -1 }).limit(200);

    const doc = new PDFDocument({ margin: 30, size: "A4" });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=anomaly-detection-report.pdf"
    );

    doc.pipe(res);

    doc.fontSize(20).text("Anomaly Detection Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`);
    doc.moveDown();

    doc.fontSize(14).text("Summary", { underline: true });
    doc.fontSize(11).text(`Total Records: ${records.length}`);
    doc.text(
      `High/Critical Records: ${
        records.filter((r) => ["HIGH", "CRITICAL"].includes(r.severity)).length
      }`
    );
    doc.text(
      `Email Alerts: ${records.filter((r) => r.emailAlertSent).length}`
    );
    doc.moveDown();

    records.forEach((item, index) => {
      if (doc.y > 700) doc.addPage();

      doc.fontSize(13).text(`${index + 1}. ${item.anomalyType}`, {
        underline: true,
      });

      doc.fontSize(11).text(`IP: ${item.ip}`);
      doc.text(`Severity: ${item.severity}`);
      doc.text(`Score: ${item.score}`);
      doc.text(`Current Value: ${item.currentValue}`);
      doc.text(`Baseline Value: ${item.baselineValue}`);
      doc.text(`Deviation: ${item.deviation}%`);
      doc.text(`Email Alert Sent: ${item.emailAlertSent ? "Yes" : "No"}`);
      doc.text(`Reason: ${item.reason}`);
      doc.text(`Time: ${new Date(item.createdAt).toLocaleString()}`);
      doc.moveDown();
    });

    doc.end();
  } catch (error) {
    console.error("exportAnomalyPDF error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to export anomaly PDF",
    });
  }
};