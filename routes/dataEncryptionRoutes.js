import express from "express";
import {
  createEncryptedRecord,
  getEncryptedRecords,
  decryptEncryptedRecord,
  getEncryptionStats,
  deleteEncryptedRecord,
  bulkDeleteEncryptedRecords,
  exportEncryptionPDF,
} from "../controllers/dataEncryptionController.js";

const router = express.Router();

router.get("/stats", getEncryptionStats);
router.get("/export/pdf", exportEncryptionPDF);
router.get("/", getEncryptedRecords);
router.get("/decrypt/:id", decryptEncryptedRecord);
router.post("/", createEncryptedRecord);
router.delete("/bulk", bulkDeleteEncryptedRecords);
router.delete("/:id", deleteEncryptedRecord);

export default router;