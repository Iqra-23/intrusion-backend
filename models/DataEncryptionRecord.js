import mongoose from "mongoose";

const dataEncryptionRecordSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    encryptedData: {
      type: String,
      required: true,
    },
    iv: {
      type: String,
      required: true,
    },
    authTag: {
      type: String,
      required: true,
    },
    algorithm: {
      type: String,
      default: "aes-256-gcm",
    },
    status: {
      type: String,
      enum: ["encrypted", "failed"],
      default: "encrypted",
    },
    tlsStatus: {
      type: String,
      enum: ["secure", "warning"],
      default: "secure",
    },
    failureReason: {
      type: String,
      default: "",
    },
    createdBy: {
      type: String,
      default: "Admin",
    },
  },
  { timestamps: true }
);

const DataEncryptionRecord = mongoose.model(
  "DataEncryptionRecord",
  dataEncryptionRecordSchema
);

export default DataEncryptionRecord;