import express from "express";
import {
  getFirewallIncidents,
  getFirewallStats,
  deleteFirewallIncident,
  bulkDeleteFirewallIncidents,
  exportFirewallPDF,
} from "../controllers/firewallController.js";

const router = express.Router();

router.get("/stats", getFirewallStats);
router.get("/export/pdf", exportFirewallPDF);
router.get("/", getFirewallIncidents);
router.delete("/bulk", bulkDeleteFirewallIncidents);
router.delete("/:id", deleteFirewallIncident);
router.get("/export/pdf", exportFirewallPDF);
export default router;