import Threat from "../models/threatModel.js";
import { analyzeThreat } from "../services/threatService.js";
import { getIO } from "../utils/socket.js";
import PDFDocument from "pdfkit";

export const detectThreat = async (req, res) => {
  try {
    const log = req.body;

    if (!log || !log.url || !log.method || !log.ip) {
      return res.status(400).json({
        success: false,
        message: "ip, url, and method are required",
      });
    }

    const result = analyzeThreat(log);

    const threat = await Threat.create({
      ip: log.ip,
      url: log.url,
      method: log.method,
      threatScore: result.score,
      threatLevel: result.level,
      reason: result.reason,
    });

    if (result.level === "HIGH") {
      const io = getIO();
      io.emit("threat-alert", threat);
    }

    res.status(201).json({
      success: true,
      threat,
    });
  } catch (err) {
    console.error("detectThreat error:", err);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
};

export const getThreats = async (req, res) => {
  try {
    const { search = "", level = "all", method = "all" } = req.query;

    const query = {};

    if (level !== "all") query.threatLevel = level;
    if (method !== "all") query.method = method;

    if (search) {
      query.$or = [
        { ip: { $regex: search, $options: "i" } },
        { url: { $regex: search, $options: "i" } },
        { reason: { $regex: search, $options: "i" } },
      ];
    }

    const threats = await Threat.find(query).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      threats,
    });
  } catch (error) {
    console.error("getThreats error:", error);
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

export const deleteThreat = async (req, res) => {
  try {
    const deleted = await Threat.findByIdAndDelete(req.params.id);

    if (!deleted) {
      return res.status(404).json({
        success: false,
        message: "Threat not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Threat deleted successfully",
    });
  } catch (error) {
    console.error("deleteThreat error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete threat",
    });
  }
};

export const bulkDeleteThreats = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No threat IDs provided",
      });
    }

    const result = await Threat.deleteMany({ _id: { $in: ids } });

    res.status(200).json({
      success: true,
      message: `${result.deletedCount} threats deleted successfully`,
    });
  } catch (error) {
    console.error("bulkDeleteThreats error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to bulk delete threats",
    });
  }
};

export const exportThreatsPDF = async (req, res) => {
  try {
    const threats = await Threat.find().sort({ createdAt: -1 });

    const doc = new PDFDocument({ margin: 40, size: "A4" });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=threat-report-${Date.now()}.pdf`
    );

    doc.pipe(res);

    doc.fontSize(20).text("Threat Detection Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(11).text(`Generated: ${new Date().toLocaleString()}`);
    doc.moveDown();

    if (threats.length === 0) {
      doc.fontSize(12).text("No threats found.");
    } else {
      threats.forEach((threat, index) => {
        doc
          .fontSize(13)
          .text(`${index + 1}. ${threat.threatLevel} Threat`, { underline: true });
        doc.fontSize(11).text(`IP: ${threat.ip}`);
        doc.text(`URL: ${threat.url}`);
        doc.text(`Method: ${threat.method}`);
        doc.text(`Score: ${threat.threatScore}`);
        doc.text(`Reason: ${threat.reason || "No reason"}`);
        doc.text(`Time: ${new Date(threat.createdAt).toLocaleString()}`);
        doc.moveDown();

        if (doc.y > 720) {
          doc.addPage();
        }
      });
    }

    doc.end();
  } catch (error) {
    console.error("exportThreatsPDF error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to export threat PDF",
    });
  }
};