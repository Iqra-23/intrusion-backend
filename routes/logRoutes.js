// routes/logRoutes.js
import express from "express";
import { protect } from "../middleware/authMiddleware.js";
import {
  createLog,
  getLogs,
  getLogStats,
  archiveLogs,
  restoreLogs,
  cleanupLogs,
  bulkDeleteLogs,
  deleteLog,
  getAlerts,
  acknowledgeAlert,
  resolveAlert,
  deleteAlert,
  bulkDeleteAlerts,   // ⬅️ NEW
} from "../controllers/logController.js";

const router = express.Router();

// Logs
router.post("/", protect, createLog);
router.get("/", protect, getLogs);
router.get("/stats", protect, getLogStats);
router.post("/archive", protect, archiveLogs);
router.post("/restore", protect, restoreLogs);
router.delete("/cleanup", protect, cleanupLogs);
router.delete("/bulk", protect, bulkDeleteLogs);
router.delete("/:id", protect, deleteLog);

// Alerts (Real-time module)
router.get("/alerts", protect, getAlerts);
router.patch("/alerts/:id/acknowledge", protect, acknowledgeAlert);
router.patch("/alerts/:id/resolve", protect, resolveAlert);
router.delete("/alerts/bulk", protect, bulkDeleteAlerts);  // ⬅️ bulk delete
router.delete("/alerts/:id", protect, deleteAlert);

export default router;
