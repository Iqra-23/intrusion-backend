// routes/dashboardRoutes.js
import express from "express";
import { protect } from "../middleware/authMiddleware.js";
import {
  getDashboardStats,
  exportDashboardPdf,
} from "../controllers/dashboardController.js";

const router = express.Router();

// All dashboard routes are protected
router.get("/stats", protect, getDashboardStats);
router.get("/export", protect, exportDashboardPdf);

export default router;
