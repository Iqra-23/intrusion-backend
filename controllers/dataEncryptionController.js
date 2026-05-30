import PDFDocument from "pdfkit";
import bcrypt from "bcryptjs";
import DataEncryptionRecord from "../models/DataEncryptionRecord.js";
import {
  encryptText,
  decryptText,
  getTlsStatus,
} from "../services/dataEncryptionService.js";
import { getIO } from "../utils/socket.js";

const emitEncryptionAlert = (payload) => {
  try {
    const io = getIO();

    io.emit("encryption-failure", {
      message: payload.message,
      reason: payload.reason || payload.failureReason || "Encryption issue detected",
      createdAt: new Date(),
    });

    io.emit("new-alert", {
      title: "Data Encryption Alert",
      severity: "high",
      description: payload.message,
      createdAt: new Date(),
    });
  } catch (error) {
    console.log("Encryption socket alert skipped:", error.message);
  }
};

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
    const tls = getTlsStatus(req);

    const record = await DataEncryptionRecord.create({
      title,
      encryptedData: encrypted.encryptedData,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      algorithm: encrypted.algorithm,
      status: "encrypted",
      tlsStatus: tls.status,
      failureReason: "",
      createdBy: req.user?.name || "Admin",
    });

    res.status(201).json({
      success: true,
      message: "Data encrypted successfully",
      record,
    });
  } catch (error) {
    console.error("createEncryptedRecord error:", error);

    const failedRecord = await DataEncryptionRecord.create({
      title: req.body?.title || "Untitled",
      encryptedData: "FAILED",
      iv: "FAILED",
      authTag: "FAILED",
      algorithm: "aes-256-gcm",
      status: "failed",
      tlsStatus: "warning",
      failureReason: error.message,
      createdBy: req.user?.name || "Admin",
    });

    emitEncryptionAlert({
      message: "Encryption failed",
      reason: error.message,
    });

    res.status(500).json({
      success: false,
      message: "Failed to encrypt record",
      failedRecord,
    });
  }
};

export const createSecureSession = async (req, res) => {
  try {
    const sessionPayload = {
      userId: req.body?.userId || "demo-user",
      role: req.body?.role || "admin",
      createdAt: new Date().toISOString(),
    };

    const encrypted = encryptText(JSON.stringify(sessionPayload));
    const tls = getTlsStatus(req);

    res.cookie("secure_session", JSON.stringify(encrypted), {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      maxAge: 60 * 60 * 1000,
    });

    const record = await DataEncryptionRecord.create({
      title: "Secure Session Cookie",
      encryptedData: encrypted.encryptedData,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      algorithm: encrypted.algorithm,
      status: "encrypted",
      tlsStatus: tls.status,
      failureReason: "",
      createdBy: req.user?.name || "Admin",
    });

    res.json({
      success: true,
      message: "Secure encrypted HTTP-only session cookie created",
      cookieSecurity: {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
      },
      record,
    });
  } catch (error) {
    console.error("createSecureSession error:", error);

    emitEncryptionAlert({
      message: "Secure session encryption failed",
      reason: error.message,
    });

    res.status(500).json({
      success: false,
      message: "Failed to create secure session",
    });
  }
};

export const clearSecureSession = async (req, res) => {
  try {
    res.clearCookie("secure_session");

    res.json({
      success: true,
      message: "Secure session cookie cleared",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to clear secure session",
    });
  }
};

export const hashPasswordRecord = async (req, res) => {
  try {
    const { password = "Admin@12345" } = req.body;

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);
    const tls = getTlsStatus(req);

    const record = await DataEncryptionRecord.create({
      title: "Password Hashing And Salting",
      encryptedData: hashedPassword,
      iv: "bcrypt-salt-managed",
      authTag: "not-required-for-bcrypt",
      algorithm: "bcryptjs-12-rounds",
      status: "encrypted",
      tlsStatus: tls.status,
      failureReason: "",
      createdBy: req.user?.name || "Admin",
    });

    res.json({
      success: true,
      message: "Password hashed and salted successfully",
      hashPreview: hashedPassword.slice(0, 30) + "...",
      record,
    });
  } catch (error) {
    console.error("hashPasswordRecord error:", error);

    emitEncryptionAlert({
      message: "Password hashing failed",
      reason: error.message,
    });

    res.status(500).json({
      success: false,
      message: "Password hashing failed",
    });
  }
};

export const simulateEncryptionFailure = async (req, res) => {
  try {
    const record = await DataEncryptionRecord.create({
      title: "Simulated Encryption Failure",
      encryptedData: "FAILED",
      iv: "FAILED",
      authTag: "FAILED",
      algorithm: "aes-256-gcm",
      status: "failed",
      tlsStatus: "warning",
      failureReason: "Simulated encryption key mismatch or secure operation failure",
      createdBy: req.user?.name || "Admin",
    });

    emitEncryptionAlert({
      message: "Encryption failure detected",
      reason: record.failureReason,
    });

    res.json({
      success: true,
      message: "Encryption failure simulated and alert generated",
      record,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to simulate encryption failure",
    });
  }
};

export const checkTlsStatus = async (req, res) => {
  try {
    const tls = getTlsStatus(req);

    const record = await DataEncryptionRecord.create({
      title: "HTTPS/TLS Secure Communication Check",
      encryptedData: "TLS-CHECK",
      iv: "TLS-CHECK",
      authTag: "TLS-CHECK",
      algorithm: "HTTPS/TLS",
      status: tls.status === "secure" ? "encrypted" : "failed",
      tlsStatus: tls.status,
      failureReason:
        tls.status === "secure"
          ? ""
          : "Localhost is running on HTTP. TLS will be secure after HTTPS deployment.",
      createdBy: req.user?.name || "Admin",
    });

    res.json({
      success: true,
      tlsEnabled: tls.status === "secure",
      tlsStatus: tls.status,
      message:
        tls.status === "secure"
          ? "HTTPS/TLS secure communication is active"
          : "Localhost uses HTTP. TLS will be active after deployment.",
      record,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "TLS status check failed",
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

    if (record.algorithm?.startsWith("bcrypt")) {
      return res.status(400).json({
        success: false,
        message: "Password hashes cannot be decrypted. Hashing is one-way protection.",
      });
    }

    if (record.algorithm === "HTTPS/TLS") {
      return res.status(400).json({
        success: false,
        message: "TLS check record is not decryptable data.",
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

    const encrypted = records.filter((r) => r.status === "encrypted").length;
    const failed = records.filter((r) => r.status === "failed").length;
    const secureTls = records.filter((r) => r.tlsStatus === "secure").length;
    const warningTls = records.filter((r) => r.tlsStatus === "warning").length;

    doc.fontSize(14).text("Summary", { underline: true });
    doc.fontSize(11).text(`Total Records: ${records.length}`);
    doc.text(`Encrypted Records: ${encrypted}`);
    doc.text(`Failed Records: ${failed}`);
    doc.text(`Secure TLS Records: ${secureTls}`);
    doc.text(`TLS Warnings: ${warningTls}`);
    doc.moveDown();

    records.forEach((item, index) => {
      if (doc.y > 700) doc.addPage();

      doc
        .fontSize(13)
        .text(`${index + 1}. ${item.title}`, { underline: true });

      doc.fontSize(11).text(`Status: ${item.status}`);
      doc.text(`Algorithm: ${item.algorithm || "-"}`);
      doc.text(`TLS Status: ${item.tlsStatus || "-"}`);
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