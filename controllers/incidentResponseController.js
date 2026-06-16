import PDFDocument from "pdfkit";
import IncidentResponse from "../models/IncidentResponse.js";
import ThreatIPList from "../models/ThreatIPList.js";
import { getIO } from "../utils/socket.js";
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

// ================= CREATE =================
export const createIncident = async (req, res) => {
  try {
    const { attackType, ipAddress, severity, mitigationSteps } = req.body;

    if (!attackType || !ipAddress) {
      return res.status(400).json({
        success: false,
        message: "attackType and ipAddress are required",
      });
    }

    const autoBlocked = severity === "critical" || severity === "high";

    const incident = await IncidentResponse.create({
      attackType,
      ipAddress,
      severity,
      status: autoBlocked ? "blocked" : "detected",
      autoBlocked,
      incidentAlert: true,
      mitigationSteps: mitigationSteps || "Default mitigation applied",
    });

    // FIX: if high/critical — also add to ThreatIPList blacklist immediately
    if (autoBlocked) {
      await ThreatIPList.findOneAndUpdate(
        { ip: ipAddress },
        {
          ip: ipAddress,
          listType: "blacklist",
          reason: `Auto-blocked: ${attackType} incident (${severity})`,
        },
        { new: true, upsert: true }
      );
    }

    // LOG: incident created
    await createLog(
      severity === "critical" ? "suspicious" : "warning",
      `Incident created: ${attackType} from ${ipAddress} — severity: ${severity?.toUpperCase()}${autoBlocked ? " — IP auto-blacklisted" : ""}`,
      ["incident", "response", attackType.toLowerCase().replace(/\s+/g, "-")],
      ipAddress, "Incident Response",
      { attackType, severity, autoBlocked }
    );

    const io = getIO?.();
    if (io) {
      io.emit("incident-alert", {
        message: "Incident detected",
        attackType,
        severity,
        ipAddress,
        autoBlocked,
        createdAt: new Date(),
      });
    }

    res.status(201).json({ success: true, incident });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to create incident" });
  }
};

// ================= GET ALL =================
export const getIncidents = async (req, res) => {
  try {
    const incidents = await IncidentResponse.find().sort({ createdAt: -1 });
    res.json({ success: true, incidents });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to fetch incidents" });
  }
};

// ================= STATS =================
export const getIncidentStats = async (req, res) => {
  try {
    const [total, blocked, recovered, alerts] = await Promise.all([
      IncidentResponse.countDocuments(),
      IncidentResponse.countDocuments({ autoBlocked: true }),
      IncidentResponse.countDocuments({ status: "recovered" }),
      IncidentResponse.countDocuments({ incidentAlert: true }),
    ]);
    res.json({ total, blocked, recovered, alerts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to fetch stats" });
  }
};

// ================= BLOCK =================
export const autoBlockAttacker = async (req, res) => {
  try {
    const incident = await IncidentResponse.findByIdAndUpdate(
      req.params.id,
      { autoBlocked: true, status: "blocked" },
      { new: true }
    );

    if (!incident) {
      return res.status(404).json({ success: false, message: "Incident not found" });
    }

    await ThreatIPList.findOneAndUpdate(
      { ip: incident.ipAddress },
      {
        ip: incident.ipAddress,
        listType: "blacklist",
        reason: `Blocked via Incident Response: ${incident.attackType} (${incident.severity})`,
      },
      { new: true, upsert: true }
    );

    // LOG: IP blocked
    await createLog(
      "suspicious",
      `IP ${incident.ipAddress} manually blocked and blacklisted — ${incident.attackType} (${incident.severity})`,
      ["incident", "blocked", "blacklist"],
      incident.ipAddress, "Admin",
      { attackType: incident.attackType, severity: incident.severity }
    );

    try {
      const io = getIO?.();
      if (io) {
        io.emit("new-alert", {
          title: `IP Blocked: ${incident.ipAddress}`,
          severity: "high",
          description: `${incident.attackType} attacker blocked and added to firewall blacklist`,
          createdAt: new Date(),
        });
      }
    } catch (_) {}

    res.json({
      success: true,
      incident,
      message: `IP ${incident.ipAddress} has been blacklisted in firewall`,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to block incident" });
  }
};

// ================= RECOVERY =================
export const addRecoveryProcedure = async (req, res) => {
  try {
    const { recoveryProcedure } = req.body;

    const incident = await IncidentResponse.findByIdAndUpdate(
      req.params.id,
      { recoveryProcedure, status: "recovered" },
      { new: true }
    );

    if (!incident) {
      return res.status(404).json({ success: false, message: "Incident not found" });
    }

    // LOG: recovery
    await createLog(
      "info",
      `Recovery logged for ${incident.attackType} from ${incident.ipAddress}`,
      ["incident", "recovery"],
      incident.ipAddress, "Admin"
    );

    res.json({ success: true, incident });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to add recovery procedure" });
  }
};

// ================= EXPORT PDF =================
export const exportIncidentPDF = async (req, res) => {
  try {
    const records = await IncidentResponse.find().sort({ createdAt: -1 });

    const doc = new PDFDocument({ margin: 40 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=incident-report-${Date.now()}.pdf`);
    doc.pipe(res);

    doc.fontSize(22).font("Helvetica-Bold").text("Incident Response Report", { align: "center" });
    doc.moveDown(0.5);
    doc.fontSize(10).font("Helvetica").fillColor("gray")
      .text(`Generated: ${new Date().toLocaleString()}`, { align: "center" });
    doc.moveDown(1);

    if (records.length === 0) {
      doc.fontSize(12).fillColor("black").text("No incidents found.", { align: "center" });
    } else {
      records.forEach((item, index) => {
        doc.fontSize(13).font("Helvetica-Bold").fillColor("black")
          .text(`${index + 1}. ${item.attackType}`);
        doc.fontSize(10).font("Helvetica").fillColor("#333333");
        doc.text(`IP Address   : ${item.ipAddress}`);
        doc.text(`Severity     : ${item.severity?.toUpperCase()}`);
        doc.text(`Status       : ${item.status}`);
        doc.text(`Auto Blocked : ${item.autoBlocked ? "Yes — IP added to firewall blacklist" : "No"}`);
        doc.text(`Mitigation   : ${item.mitigationSteps || "—"}`);
        doc.text(`Recovery     : ${item.recoveryProcedure || "Not logged"}`);
        doc.text(`Created At   : ${new Date(item.createdAt).toLocaleString()}`);
        doc.moveDown(1);
        if (index < records.length - 1) {
          doc.moveTo(40, doc.y).lineTo(555, doc.y).strokeColor("#cccccc").stroke();
          doc.moveDown(0.5);
        }
      });
    }

    doc.end();
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to export PDF" });
  }
};

// ================= DELETE ONE =================
export const deleteIncident = async (req, res) => {
  try {
    const incident = await IncidentResponse.findByIdAndDelete(req.params.id);
    if (!incident) {
      return res.status(404).json({ success: false, message: "Incident not found" });
    }
    res.json({ success: true, message: "Incident deleted" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to delete incident" });
  }
};

// ================= BULK DELETE =================
export const bulkDeleteIncidents = async (req, res) => {
  try {
    const { ids } = req.body;
    if (!ids || !ids.length) {
      return res.status(400).json({ success: false, message: "No IDs provided" });
    }
    await IncidentResponse.deleteMany({ _id: { $in: ids } });
    res.json({ success: true, message: `${ids.length} incidents deleted` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to bulk delete" });
  }
};