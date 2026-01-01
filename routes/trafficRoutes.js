// routes/trafficRoutes.js
import express from "express";
import {
  getTrafficEvents,
  getTrafficStats,
  getTrafficAlerts,
  exportTrafficPdf,
  exportSingleTrafficPdf,  // ✅ NEW
  deleteTrafficEvents,
  getTrafficEventById,
} from "../controllers/trafficController.js";
import { trafficMiddleware } from "../middleware/trafficMiddleware.js";

const router = express.Router();

router.use(trafficMiddleware);

router.get("/", getTrafficEvents);
router.get("/stats", getTrafficStats);
router.get("/alerts", getTrafficAlerts);

// overall export
router.get("/export", exportTrafficPdf);

// ✅ single export MUST be before /:id
router.get("/export/:id", exportSingleTrafficPdf);

// details
router.get("/:id", getTrafficEventById);

router.delete("/", deleteTrafficEvents);

export default router;
