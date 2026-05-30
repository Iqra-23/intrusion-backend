import express from "express";
import {
  detectThreat,
  getThreats,
  getThreatStats,
  getIpLists,
  saveIpRule,
  deleteIpFromList,
  deleteThreat,
  bulkDeleteThreats,
  exportThreatsPdf,
  exportSingleThreatPdf,
} from "../controllers/threatController.js";

const router = express.Router();

router.post("/detect", detectThreat);

router.get("/", getThreats);
router.get("/stats", getThreatStats);

router.get("/export", exportThreatsPdf);
router.get("/export/:id", exportSingleThreatPdf);

router.get("/ip-list", getIpLists);
router.post("/ip-list", saveIpRule);
router.delete("/ip-list/:id", deleteIpFromList);

router.delete("/bulk", bulkDeleteThreats);
router.delete("/:id", deleteThreat);

export default router;