import FirewallIncident from "../models/FirewallIncident.js";
import PDFDocument from "pdfkit";

export const getFirewallIncidents = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      attackType,
      severity,
      blocked,
      search = "",
    } = req.query;

    const query = {};

    if (attackType && attackType !== "all") query.attackType = attackType;
    if (severity && severity !== "all") query.severity = severity;

    if (blocked === "true") query.simulatedAction = "block";
    if (blocked === "false") query.simulatedAction = "alert";

    if (search) {
      query.$or = [
        { ip: { $regex: search, $options: "i" } },
        { path: { $regex: search, $options: "i" } },
        { suspiciousValue: { $regex: search, $options: "i" } },
      ];
    }

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    const [incidents, total] = await Promise.all([
      FirewallIncident.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum),
      FirewallIncident.countDocuments(query),
    ]);

    res.json({
      incidents,
      pagination: {
        total,
        page: pageNum,
        pages: Math.ceil(total / limitNum),
        limit: limitNum,
      },
    });
  } catch (error) {
    console.error("getFirewallIncidents error:", error);
    res.status(500).json({ message: "Failed to fetch firewall incidents" });
  }
};

export const getFirewallStats = async (req, res) => {
  try {
    const [
      total,
      sqlInjection,
      xss,
      pathTraversal,
      keywordSpam,
      blocked,
    ] = await Promise.all([
      FirewallIncident.countDocuments(),
      FirewallIncident.countDocuments({ attackType: "sql-injection" }),
      FirewallIncident.countDocuments({ attackType: "xss" }),
      FirewallIncident.countDocuments({ attackType: "path-traversal" }),
      FirewallIncident.countDocuments({ attackType: "keyword-spam" }),
      FirewallIncident.countDocuments({ simulatedAction: "block" }),
    ]);

    const recent = await FirewallIncident.find()
      .sort({ createdAt: -1 })
      .limit(8);

    res.json({
      total,
      byType: {
        sqlInjection,
        xss,
        pathTraversal,
        keywordSpam,
      },
      blocked,
      recent,
    });
  } catch (error) {
    console.error("getFirewallStats error:", error);
    res.status(500).json({ message: "Failed to fetch firewall stats" });
  }
};

export const deleteFirewallIncident = async (req, res) => {
  try {
    const doc = await FirewallIncident.findByIdAndDelete(req.params.id);

    if (!doc) {
      return res.status(404).json({ message: "Incident not found" });
    }

    res.json({ success: true, message: "Incident deleted successfully" });
  } catch (error) {
    console.error("deleteFirewallIncident error:", error);
    res.status(500).json({ message: "Failed to delete incident" });
  }
};

export const bulkDeleteFirewallIncidents = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ message: "No incident IDs provided" });
    }

    const result = await FirewallIncident.deleteMany({ _id: { $in: ids } });

    res.json({
      success: true,
      message: `${result.deletedCount} incidents deleted successfully`,
    });
  } catch (error) {
    console.error("bulkDeleteFirewallIncidents error:", error);
    res.status(500).json({ message: "Failed to bulk delete incidents" });
  }
};

export const exportFirewallPDF = async (req, res) => {
  try {
    const incidents = await FirewallIncident.find().sort({ createdAt: -1 });

    const doc = new PDFDocument({ margin: 30, size: "A4" });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=firewall-report.pdf"
    );

    doc.pipe(res);

    doc.fontSize(20).text("Firewall Incident Report", { align: "center" });
    doc.moveDown();

    doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`);
    doc.moveDown();

    incidents.forEach((item, index) => {
      doc
        .fontSize(13)
        .text(`${index + 1}. ${item.attackType || "Unknown Attack"}`, {
          underline: true,
        });

      doc.fontSize(11).text(`Severity: ${item.severity || "N/A"}`);
      doc.text(`IP: ${item.ip || "N/A"}`);
      doc.text(`Path: ${item.path || "N/A"}`);
      doc.text(`Source: ${item.sourceType || "N/A"}`);
      doc.text(`Action: ${item.simulatedAction || "N/A"}`);
      doc.text(`Keyword Density: ${item.keywordDensity ?? "N/A"}`);
      doc.text(`Repeated Keyword: ${item.repeatedKeyword || "N/A"}`);
      doc.text(
        `Suspicious Value: ${item.suspiciousValue || "N/A"}`
      );
      doc.text(`Time: ${new Date(item.createdAt).toLocaleString()}`);
      doc.moveDown();
    });

    doc.end();
  } catch (error) {
    console.error("exportFirewallPDF error:", error);
    res.status(500).json({ message: "Failed to export firewall PDF" });
  }
};