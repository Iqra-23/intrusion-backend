import express from "express";
import {
  detectThreat,
  getThreats,
  deleteThreat,
  bulkDeleteThreats,
  exportThreatsPDF,
} from "../controllers/threatController.js";

const router = express.Router();

router.post("/", detectThreat);
router.get("/", getThreats);
router.get("/export/pdf", exportThreatsPDF);
router.delete("/bulk", bulkDeleteThreats);
router.delete("/:id", deleteThreat);

export default router;