import mongoose from "mongoose";

const dataEncryptionLogSchema = new mongoose.Schema(
  {
    feature: {
      type: String,
      enum: ["secure-session", "password-hashing", "encryption-alert", "tls-check"],
      required: true,
    },
    status: {
      type: String,
      enum: ["success", "failed", "warning"],
      default: "success",
    },
    message: { type: String, default: "" },
    details: { type: Object, default: {} },
  },
  { timestamps: true }
);

export default mongoose.model("DataEncryptionLog", dataEncryptionLogSchema);