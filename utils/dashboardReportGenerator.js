// utils/dashboardReportGenerator.js
import fs from "fs";
import PDFDocument from "pdfkit";

/**
 * Very simple PDF summary generator for dashboard.
 * For more fancy layout later, you can extend this.
 */
export const generateDashboardReport = (data, filePath) => {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 40 });

      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      const {
        summary,
        trafficTrend,
        vulnSeverity,
        topCountries,
        topPaths,
        recentAlerts,
        recentScans,
        generatedAt,
      } = data;

      // HEADER
      doc
        .fontSize(20)
        .fillColor("#111111")
        .text("SEO Intrusion Detector", { align: "left" });
      doc
        .fontSize(14)
        .fillColor("#333333")
        .text("Cyber Security Dashboard Report", { align: "left" });
      doc
        .moveDown(0.5)
        .fontSize(10)
        .fillColor("#555555")
        .text(`Generated: ${generatedAt.toLocaleString()}`, { align: "left" });

      doc.moveDown(1.5);

      // SUMMARY SECTION
      doc
        .fontSize(12)
        .fillColor("#111111")
        .text("1. Summary", { underline: true });
      doc.moveDown(0.5);

      doc.fontSize(10).fillColor("#333333");
      doc.text(`Total Logs: ${summary.totalLogs || 0}`);
      doc.text(`Error Logs: ${summary.errorLogs || 0}`);
      doc.text(`Warning Logs: ${summary.warningLogs || 0}`);
      doc.text(`Suspicious Logs: ${summary.suspiciousLogs || 0}`);
      doc.text(`Active Alerts: ${summary.activeAlerts || 0}`);
      doc.text(
        `Open Vulnerabilities: ${summary.openVulnerabilities || 0}`
      );
      doc.text(`Unique IPs (24h): ${summary.uniqueIps || 0}`);

      doc.moveDown(1);

      // TRAFFIC TREND
      doc
        .fontSize(12)
        .fillColor("#111111")
        .text("2. Traffic Trend (Last 7 Days)", { underline: true });
      doc.moveDown(0.5);

      if (!trafficTrend || trafficTrend.length === 0) {
        doc.fontSize(10).fillColor("#555555").text("No traffic data found.");
      } else {
        doc.fontSize(10).fillColor("#333333");
        trafficTrend.forEach((d) => {
          doc.text(
            `${d.date}: total=${d.total || 0}, spikes=${d.spikes || 0}`
          );
        });
      }

      doc.moveDown(1);

      // VULN SEVERITY
      doc
        .fontSize(12)
        .fillColor("#111111")
        .text("3. Vulnerability Severity", { underline: true });
      doc.moveDown(0.5);

      doc.fontSize(10).fillColor("#333333");
      doc.text(`Critical: ${vulnSeverity.critical || 0}`);
      doc.text(`High: ${vulnSeverity.high || 0}`);
      doc.text(`Medium: ${vulnSeverity.medium || 0}`);
      doc.text(`Low: ${vulnSeverity.low || 0}`);

      doc.moveDown(1);

      // TOP COUNTRIES
      doc
        .fontSize(12)
        .fillColor("#111111")
        .text("4. Top Source Countries", { underline: true });
      doc.moveDown(0.5);

      if (!topCountries || topCountries.length === 0) {
        doc.fontSize(10).fillColor("#555555").text("No geo data available.");
      } else {
        doc.fontSize(10).fillColor("#333333");
        topCountries.forEach((c, index) => {
          doc.text(`${index + 1}. ${c.country}: ${c.count} requests`);
        });
      }

      doc.moveDown(1);

      // TOP PATHS
      doc
        .fontSize(12)
        .fillColor("#111111")
        .text("5. Top Targeted Paths", { underline: true });
      doc.moveDown(0.5);

      if (!topPaths || topPaths.length === 0) {
        doc.fontSize(10).fillColor("#555555").text("No path data available.");
      } else {
        doc.fontSize(10).fillColor("#333333");
        topPaths.forEach((p, index) => {
          doc.text(`${index + 1}. ${p.path}: ${p.count} hits`);
        });
      }

      doc.moveDown(1);

      // RECENT ALERTS
      doc
        .fontSize(12)
        .fillColor("#111111")
        .text("6. Recent Alerts", { underline: true });
      doc.moveDown(0.5);

      if (!recentAlerts || recentAlerts.length === 0) {
        doc.fontSize(10).fillColor("#555555").text("No alerts recorded.");
      } else {
        doc.fontSize(10).fillColor("#333333");
        recentAlerts.forEach((a, index) => {
          const when = a.createdAt
            ? new Date(a.createdAt).toLocaleString()
            : "N/A";
          doc.text(
            `${index + 1}. [${(a.severity || "unknown").toUpperCase()}] ${
              a.title || "Security Alert"
            } (${when})`
          );
        });
      }

      doc.moveDown(1);

      // RECENT SCANS
      doc
        .fontSize(12)
        .fillColor("#111111")
        .text("7. Recent Vulnerability Scans", { underline: true });
      doc.moveDown(0.5);

      if (!recentScans || recentScans.length === 0) {
        doc.fontSize(10).fillColor("#555555").text("No scan history found.");
      } else {
        doc.fontSize(10).fillColor("#333333");
        recentScans.forEach((scan, index) => {
          const when = scan.startedAt
            ? new Date(scan.startedAt).toLocaleString()
            : "N/A";
          doc.text(
            `${index + 1}. ${scan.siteUrl} — ${scan.status} (${when})`
          );
        });
      }

      doc.end();

      stream.on("finish", () => resolve());
      stream.on("error", (err) => reject(err));
    } catch (err) {
      return reject(err);
    }
  });
};

export default { generateDashboardReport };
