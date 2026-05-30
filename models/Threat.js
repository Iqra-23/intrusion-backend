import mongoose from "mongoose";

const threatSchema = new mongoose.Schema(
  {
    ip: { type: String, index: true },
    url: String,
    method: String,
    payload: String,

    attackType: {
      type: String,
      enum: [
        "normal",
        "sql-injection",
        "xss",
        "path-traversal",
        "keyword-spam",
        "suspicious-ip",
        "rate-limit",
      ],
      default: "normal",
      index: true,
    },

    confidence: { type: Number, default: 0 },
    threatScore: { type: Number, default: 0 },

    threatLevel: {
      type: String,
      enum: ["LOW", "MEDIUM", "HIGH"],
      default: "LOW",
      index: true,
    },

    action: {
      type: String,
      enum: ["allow", "monitor", "block"],
      default: "allow",
    },

    requestCount: { type: Number, default: 0 },
    failedAttempts: { type: Number, default: 0 },
    reason: String,
  },
  { timestamps: true }
);

export default mongoose.model("Threat", threatSchema);