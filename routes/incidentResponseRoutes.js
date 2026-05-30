import express from "express";

import {
  createIncident,
  getIncidents,
  getIncidentStats,
  autoBlockAttacker,
  addRecoveryProcedure,
  exportIncidentPDF,
  deleteIncident,
  bulkDeleteIncidents,
} from "../controllers/incidentResponseController.js";

const router = express.Router();

// ✅ Static routes PEHLE (warna :id inhe pakad leta)
router.get("/stats", getIncidentStats);

router.get("/export/pdf", exportIncidentPDF);

router.get("/", getIncidents);

router.post("/", createIncident);

router.put("/block/:id", autoBlockAttacker);

router.put("/recovery/:id", addRecoveryProcedure);

router.delete("/bulk", bulkDeleteIncidents);

router.delete("/:id", deleteIncident);

export default router;