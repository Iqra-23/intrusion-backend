import express from "express";
import {
  generateReport,
  getReports,
  getAuditLogs,
  exportReportPDF,
  exportReportExcel,
  getAttackClassification,
  deleteReport,
} from "../controllers/incidentAnalysisController.js";

const router = express.Router();

// ✅ Static routes pehle
router.get("/audit-logs",          getAuditLogs);
router.get("/attack-classification", getAttackClassification);
router.get("/export/pdf/:id",      exportReportPDF);
router.get("/export/excel/:id",    exportReportExcel);
router.get("/",                    getReports);
router.post("/generate",           generateReport);
router.delete("/:id",              deleteReport);

export default router;