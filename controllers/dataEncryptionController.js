import PDFDocument from "pdfkit";
import DataEncryptionRecord from "../models/DataEncryptionRecord.js";
import {
  encryptText,
  decryptText,
  getTlsStatus,
} from "../services/dataEncryptionService.js";
import { getIO } from "../utils/socket.js";

export const createEncryptedRecord = async (req, res) => {
  try {
    const { title, plainText } = req.body;

    if (!title || !plainText) {
      return res.status(400).json({
        success: false,
        message: "Title and plainText are required",
      });
    }

    const encrypted = encryptText(plainText);
    const tls = getTlsStatus();

    const record = await DataEncryptionRecord.create({
      title,
      encryptedData: encrypted.encryptedData,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      algorithm: encrypted.algorithm,
      status: "encrypted",
      tlsStatus: tls.status,
    });

    res.status(201).json({
      success: true,
      record,
    });
  } catch (error) {
    console.error("createEncryptedRecord error:", error);

    const io = getIO?.();
    if (io) {
      io.emit("encryption-failure", {
        message: "Encryption failed",
        reason: error.message,
        createdAt: new Date(),
      });
    }

    const failedRecord = await DataEncryptionRecord.create({
      title: req.body.title || "Untitled",
      encryptedData: "FAILED",
      iv: "FAILED",
      authTag: "FAILED",
      status: "failed",
      tlsStatus: "warning",
      failureReason: error.message,
    });

    res.status(500).json({
      success: false,
      message: "Failed to encrypt record",
      failedRecord,
    });
  }
};

export const getEncryptedRecords = async (req, res) => {
  try {
    const records = await DataEncryptionRecord.find().sort({ createdAt: -1 });

    res.json({
      success: true,
      records,
    });
  } catch (error) {
    console.error("getEncryptedRecords error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch encrypted records",
    });
  }
};

export const decryptEncryptedRecord = async (req, res) => {
  try {
    const record = await DataEncryptionRecord.findById(req.params.id);

    if (!record) {
      return res.status(404).json({
        success: false,
        message: "Record not found",
      });
    }

    if (record.status === "failed") {
      return res.status(400).json({
        success: false,
        message: "This record failed encryption and cannot be decrypted",
      });
    }

    const plainText = decryptText({
      encryptedData: record.encryptedData,
      iv: record.iv,
      authTag: record.authTag,
    });

    res.json({
      success: true,
      plainText,
    });
  } catch (error) {
    console.error("decryptEncryptedRecord error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to decrypt record",
    });
  }
};

export const getEncryptionStats = async (req, res) => {
  try {
    const [total, encrypted, failed, secureTls, warningTls] = await Promise.all([
      DataEncryptionRecord.countDocuments(),
      DataEncryptionRecord.countDocuments({ status: "encrypted" }),
      DataEncryptionRecord.countDocuments({ status: "failed" }),
      DataEncryptionRecord.countDocuments({ tlsStatus: "secure" }),
      DataEncryptionRecord.countDocuments({ tlsStatus: "warning" }),
    ]);

    res.json({
      total,
      encrypted,
      failed,
      secureTls,
      warningTls,
    });
  } catch (error) {
    console.error("getEncryptionStats error:", error);
    res.status(500).json({
      message: "Failed to fetch encryption stats",
    });
  }
};

export const deleteEncryptedRecord = async (req, res) => {
  try {
    const doc = await DataEncryptionRecord.findByIdAndDelete(req.params.id);

    if (!doc) {
      return res.status(404).json({
        success: false,
        message: "Record not found",
      });
    }

    res.json({
      success: true,
      message: "Record deleted successfully",
    });
  } catch (error) {
    console.error("deleteEncryptedRecord error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete record",
    });
  }
};

export const bulkDeleteEncryptedRecords = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No record IDs provided",
      });
    }

    const result = await DataEncryptionRecord.deleteMany({
      _id: { $in: ids },
    });

    res.json({
      success: true,
      message: `${result.deletedCount} records deleted successfully`,
    });
  } catch (error) {
    console.error("bulkDeleteEncryptedRecords error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to bulk delete records",
    });
  }
};

export const exportEncryptionPDF = async (req, res) => {
  try {
    const records = await DataEncryptionRecord.find().sort({ createdAt: -1 });

    const doc = new PDFDocument({ margin: 30, size: "A4" });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=data-encryption-report.pdf"
    );

    doc.pipe(res);

    doc.fontSize(20).text("Data Encryption Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`Generated: ${new Date().toLocaleString()}`);
    doc.moveDown();

    records.forEach((item, index) => {
      doc
        .fontSize(13)
        .text(`${index + 1}. ${item.title}`, { underline: true });

      doc.fontSize(11).text(`Status: ${item.status}`);
      doc.text(`Algorithm: ${item.algorithm}`);
      doc.text(`TLS Status: ${item.tlsStatus}`);
      doc.text(`Failure Reason: ${item.failureReason || "N/A"}`);
      doc.text(`Created By: ${item.createdBy || "Admin"}`);
      doc.text(`Time: ${new Date(item.createdAt).toLocaleString()}`);
      doc.moveDown();
    });

    doc.end();
  } catch (error) {
    console.error("exportEncryptionPDF error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to export PDF",
    });
  }
};