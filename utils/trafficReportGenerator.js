// utils/trafficReportGenerator.js
import PDFDocument from "pdfkit";
import fs from "fs";

export const generateTrafficReport = (
  events,
  filters = {},
  filePath = "traffic_report.pdf"
) => {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 40, size: "A4" });
      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      // HEADER
      doc
        .fontSize(22)
        .fillColor("#0EA5E9")
        .text("Traffic Monitor Report", { align: "center" });
      doc.moveDown(0.5);
      doc
        .fontSize(11)
        .fillColor("#6B7280")
        .text("SEO Intrusion Detection System - Traffic Module", {
          align: "center",
        });
      doc.moveDown(1.5);

      // FILTER SUMMARY
      doc.fontSize(14).fillColor("#111827").text("Filter Summary");
      doc.moveDown(0.3);
      doc.fontSize(10).fillColor("#374151");
      [
        `Search: ${filters.search || "-"}`,
        `IP: ${filters.ip || "-"}`,
        `Country: ${filters.country || "-"}`,
        `Method: ${filters.method || "-"}`,
        `Status: ${filters.status || "-"}`,
        `Min Anomaly: ${filters.minAnomaly || "-"}`,
      ].forEach((line) => {
        doc.text(line);
        doc.moveDown(0.1);
      });
      doc.moveDown(1);

      // SUMMARY
      doc.fontSize(14).fillColor("#111827").text("Summary");
      doc.moveDown(0.3);
      doc
        .fontSize(10)
        .fillColor("#374151")
        .text(`Total events in this export: ${events.length}`);
      doc.moveDown(1);

      // DETAILED EVENTS
      doc.fontSize(14).fillColor("#111827").text("Traffic Events (Latest First)");
      doc.moveDown(0.5);

      if (!events || events.length === 0) {
        doc
          .fontSize(11)
          .fillColor("#6B7280")
          .text("No traffic events found for the selected filters.");
      } else {
        events.forEach((ev, index) => {
          if (doc.y > 720) doc.addPage();

          const time = new Date(ev.createdAt).toLocaleString();
          const lineHeader = `${index + 1}. [${ev.method}] ${
            ev.path || "/"
          } (${ev.status || "-"})`;
          const ipLine = `IP: ${ev.ip || "-"}  | Country: ${
            ev.geo?.country || "-"
          }  | City: ${ev.geo?.city || "-"}`;
          const uaLine = `User-Agent: ${ev.userAgent || "-"}`;
          const anomalyLine = `Anomaly Score: ${
            ev.anomalyScore ?? 0
          }  | Reasons: ${
            ev.anomalyReasons && ev.anomalyReasons.length
              ? ev.anomalyReasons.join(", ")
              : "none"
          }`;
          const tagLine =
            "Tags: " +
            (ev.isSpike ? "spike, " : "") +
            (Array.isArray(ev.tags) && ev.tags.length
              ? ev.tags.join(", ")
              : ev.isSpike
              ? ""
              : "none");

          doc.fontSize(10).fillColor("#111827").text(lineHeader, {
            underline: true,
          });
          doc.fontSize(9).fillColor("#4B5563").text(`Time: ${time}`);
          doc.text(ipLine);
          doc.text(uaLine);
          doc.text(anomalyLine);
          doc.text(tagLine);
          doc.moveDown(0.7);
        });
      }

      // FOOTER
      doc.moveDown(2);
      doc
        .fontSize(9)
        .fillColor("#9CA3AF")
        .text(`Generated on ${new Date().toLocaleString()}`, {
          align: "center",
        });

      doc.end();

      stream.on("finish", () => resolve(filePath));
      stream.on("error", (err) => reject(err));
    } catch (err) {
      reject(err);
    }
  });
};
