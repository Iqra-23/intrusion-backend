import PDFDocument from "pdfkit";
import ExcelJS    from "exceljs";

import IncidentReport  from "../models/IncidentReport.js";
import AuditLog        from "../models/AuditLog.js";
import IncidentResponse from "../models/IncidentResponse.js";

// ── helpers ──────────────────────────────────────────────
const classifyAttack = (attackType = "") => {
  const t = attackType.toLowerCase();
  if (t.includes("ddos") || t.includes("dos"))                        return "DoS";
  if (t.includes("sql") || t.includes("injection") || t.includes("xss")) return "Injection";
  if (t.includes("malware") || t.includes("ransomware"))               return "Malware";
  return "Other";
};

const getDateRange = (type) => {
  const now   = new Date();
  const start = new Date();
  if (type === "daily")   start.setDate(now.getDate() - 1);
  if (type === "weekly")  start.setDate(now.getDate() - 7);
  if (type === "monthly") start.setMonth(now.getMonth() - 1);
  return { start, end: now };
};

// ── GENERATE REPORT ──────────────────────────────────────
export const generateReport = async (req, res) => {
  try {
    const { reportType } = req.body;

    if (!["daily", "weekly", "monthly"].includes(reportType)) {
      return res.status(400).json({ success: false, message: "Invalid report type" });
    }

    const { start, end } = getDateRange(reportType);

    const incidents = await IncidentResponse.find({
      createdAt: { $gte: start, $lte: end },
    });

    const breakdown = { DoS: 0, Injection: 0, Malware: 0, Other: 0 };
    incidents.forEach((i) => {
      const cat = classifyAttack(i.attackType);
      breakdown[cat]++;
    });

    const report = await IncidentReport.create({
      reportType,
      totalIncidents: incidents.length,
      blocked:        incidents.filter((i) => i.autoBlocked).length,
      recovered:      incidents.filter((i) => i.status === "recovered").length,
      alerts:         incidents.filter((i) => i.incidentAlert).length,
      attackBreakdown: breakdown,
      incidents:      incidents.map((i) => i._id),
    });

    // Audit log
    await AuditLog.create({
      action:      "GENERATE_REPORT",
      performedBy: "Admin",
      targetId:    report._id.toString(),
      details:     `${reportType} report generated with ${incidents.length} incidents`,
    });

    res.status(201).json({ success: true, report });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to generate report" });
  }
};

// ── GET ALL REPORTS ──────────────────────────────────────
export const getReports = async (req, res) => {
  try {
    const reports = await IncidentReport.find().sort({ generatedAt: -1 });
    res.json({ success: true, reports });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to fetch reports" });
  }
};

// ── GET AUDIT LOGS ───────────────────────────────────────
export const getAuditLogs = async (req, res) => {
  try {
    const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(100);
    res.json({ success: true, logs });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to fetch audit logs" });
  }
};

// ── ATTACK CLASSIFICATION ────────────────────────────────
export const getAttackClassification = async (req, res) => {
  try {
    const incidents = await IncidentResponse.find();
    const breakdown = { DoS: 0, Injection: 0, Malware: 0, Other: 0 };
    incidents.forEach((i) => {
      const cat = classifyAttack(i.attackType);
      breakdown[cat]++;
    });
    res.json({ success: true, breakdown, total: incidents.length });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to classify attacks" });
  }
};

// ── EXPORT PDF ───────────────────────────────────────────
export const exportReportPDF = async (req, res) => {
  try {
    const report = await IncidentReport.findById(req.params.id)
      .populate("incidents");

    if (!report) return res.status(404).json({ success: false, message: "Report not found" });

    const doc = new PDFDocument({ margin: 40 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=report-${report._id}.pdf`);
    doc.pipe(res);

    // Title
    doc.fontSize(22).font("Helvetica-Bold")
      .text("Incident Analysis Report", { align: "center" });
    doc.fontSize(11).font("Helvetica").fillColor("gray")
      .text(`Type: ${report.reportType.toUpperCase()}   |   Generated: ${new Date(report.generatedAt).toLocaleString()}`, { align: "center" });
    doc.moveDown(1);

    // Summary
    doc.fontSize(14).font("Helvetica-Bold").fillColor("black").text("Summary");
    doc.moveTo(40, doc.y).lineTo(555, doc.y).strokeColor("#cccccc").stroke();
    doc.moveDown(0.3);
    doc.fontSize(11).font("Helvetica").fillColor("#333");
    doc.text(`Total Incidents : ${report.totalIncidents}`);
    doc.text(`Blocked         : ${report.blocked}`);
    doc.text(`Recovered       : ${report.recovered}`);
    doc.text(`Alerts          : ${report.alerts}`);
    doc.moveDown(1);

    // Attack Breakdown
    doc.fontSize(14).font("Helvetica-Bold").fillColor("black").text("Attack Classification");
    doc.moveTo(40, doc.y).lineTo(555, doc.y).strokeColor("#cccccc").stroke();
    doc.moveDown(0.3);
    doc.fontSize(11).font("Helvetica").fillColor("#333");
    Object.entries(report.attackBreakdown).forEach(([cat, count]) => {
      doc.text(`${cat} : ${count}`);
    });
    doc.moveDown(1);

    // Incidents
    if (report.incidents?.length) {
      doc.fontSize(14).font("Helvetica-Bold").fillColor("black").text("Incident Details");
      doc.moveTo(40, doc.y).lineTo(555, doc.y).strokeColor("#cccccc").stroke();
      doc.moveDown(0.3);
      report.incidents.forEach((inc, idx) => {
        doc.fontSize(11).font("Helvetica-Bold").fillColor("black")
          .text(`${idx + 1}. ${inc.attackType}`);
        doc.fontSize(10).font("Helvetica").fillColor("#444");
        doc.text(`   IP: ${inc.ipAddress}  |  Severity: ${inc.severity?.toUpperCase()}  |  Status: ${inc.status}`);
        doc.moveDown(0.4);
      });
    }

    doc.end();

    await AuditLog.create({
      action: "EXPORT_PDF", performedBy: "Admin",
      targetId: report._id.toString(),
      details: `PDF exported for ${report.reportType} report`,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to export PDF" });
  }
};

// ── EXPORT EXCEL ─────────────────────────────────────────
export const exportReportExcel = async (req, res) => {
  try {
    const report = await IncidentReport.findById(req.params.id)
      .populate("incidents");

    if (!report) return res.status(404).json({ success: false, message: "Report not found" });

    const workbook  = new ExcelJS.Workbook();

    // Sheet 1 — Summary
    const summary = workbook.addWorksheet("Summary");
    summary.columns = [
      { header: "Field", key: "field", width: 25 },
      { header: "Value", key: "value", width: 25 },
    ];
    summary.addRows([
      { field: "Report Type",      value: report.reportType },
      { field: "Generated At",     value: new Date(report.generatedAt).toLocaleString() },
      { field: "Total Incidents",  value: report.totalIncidents },
      { field: "Blocked",          value: report.blocked },
      { field: "Recovered",        value: report.recovered },
      { field: "Alerts",           value: report.alerts },
      { field: "DoS",              value: report.attackBreakdown.DoS },
      { field: "Injection",        value: report.attackBreakdown.Injection },
      { field: "Malware",          value: report.attackBreakdown.Malware },
      { field: "Other",            value: report.attackBreakdown.Other },
    ]);

    // Sheet 2 — Incidents
    const sheet = workbook.addWorksheet("Incidents");
    sheet.columns = [
      { header: "Attack Type",  key: "attackType",  width: 20 },
      { header: "IP Address",   key: "ipAddress",   width: 18 },
      { header: "Severity",     key: "severity",    width: 12 },
      { header: "Status",       key: "status",      width: 14 },
      { header: "Auto Blocked", key: "autoBlocked", width: 14 },
      { header: "Mitigation",   key: "mitigation",  width: 35 },
      { header: "Created At",   key: "createdAt",   width: 22 },
    ];
    report.incidents?.forEach((inc) => {
      sheet.addRow({
        attackType:  inc.attackType,
        ipAddress:   inc.ipAddress,
        severity:    inc.severity?.toUpperCase(),
        status:      inc.status,
        autoBlocked: inc.autoBlocked ? "Yes" : "No",
        mitigation:  inc.mitigationSteps || "—",
        createdAt:   new Date(inc.createdAt).toLocaleString(),
      });
    });

    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename=report-${report._id}.xlsx`);
    await workbook.xlsx.write(res);
    res.end();

    await AuditLog.create({
      action: "EXPORT_EXCEL", performedBy: "Admin",
      targetId: report._id.toString(),
      details: `Excel exported for ${report.reportType} report`,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to export Excel" });
  }
};

// ── DELETE REPORT ────────────────────────────────────────
// FIX: stray "W" character removed from function signature
export const deleteReport = async (req, res) => {
  try {
    const report = await IncidentReport.findByIdAndDelete(req.params.id);
    if (!report) return res.status(404).json({ success: false, message: "Report not found" });

    await AuditLog.create({
      action: "DELETE_REPORT", performedBy: "Admin",
      targetId: req.params.id,
      details: `${report.reportType} report deleted`,
    });

    res.json({ success: true, message: "Report deleted" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Failed to delete report" });
  }
}; 