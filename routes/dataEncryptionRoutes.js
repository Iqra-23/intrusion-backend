import express from "express";
import {
  createEncryptedRecord,
  getEncryptedRecords,
  decryptEncryptedRecord,
  getEncryptionStats,
  deleteEncryptedRecord,
  bulkDeleteEncryptedRecords,
  exportEncryptionPDF,
  createSecureSession,
  clearSecureSession,
  hashPasswordRecord,
  simulateEncryptionFailure,
  checkTlsStatus,
} from "../controllers/dataEncryptionController.js";

const router = express.Router();

router.get("/stats", getEncryptionStats);
router.get("/export/pdf", exportEncryptionPDF);

router.post("/secure-session", createSecureSession);
router.delete("/secure-session", clearSecureSession);

router.post("/hash-password", hashPasswordRecord);
router.post("/simulate-failure", simulateEncryptionFailure);
router.get("/tls-status", checkTlsStatus);

router.get("/", getEncryptedRecords);
router.get("/decrypt/:id", decryptEncryptedRecord);
router.post("/", createEncryptedRecord);

router.delete("/bulk", bulkDeleteEncryptedRecords);
router.delete("/:id", deleteEncryptedRecord);

export default router;