import express from "express";

import {
  getBaseline,
  updateBaseline,
  analyzeAnomaly,
  getAnomalies,
  getAnomalyStats,
  deleteAnomaly,
  bulkDeleteAnomalies,
  exportAnomalyPDF,
} from "../controllers/anomalyController.js";

const router = express.Router();

// ================= BASELINE =================
router.get("/baseline", getBaseline);

router.put("/baseline", updateBaseline);

// ================= ANALYZE =================
router.post("/analyze", analyzeAnomaly);

// ================= RECORDS =================
router.get("/", getAnomalies);

router.get("/stats", getAnomalyStats);

// ================= EXPORT =================
router.get("/export/pdf", exportAnomalyPDF);

// ================= DELETE =================
router.delete("/bulk", bulkDeleteAnomalies);

router.delete("/:id", deleteAnomaly);

export default router;