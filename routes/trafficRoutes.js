// routes/trafficRoutes.js
import express from "express";
import {
  getTrafficEvents,
  getTrafficStats,
  getTrafficAlerts,
  exportTrafficPdf,
  deleteTrafficEvents,
  getTrafficEventById,
} from "../controllers/trafficController.js";
import { trafficMiddleware } from "../middleware/trafficMiddleware.js";

const router = express.Router();

router.use(trafficMiddleware);

router.get("/", getTrafficEvents);
router.get("/stats", getTrafficStats);
router.get("/alerts", getTrafficAlerts);
router.get("/export", exportTrafficPdf);
router.get("/:id", getTrafficEventById);

router.delete("/", deleteTrafficEvents);

export default router;
