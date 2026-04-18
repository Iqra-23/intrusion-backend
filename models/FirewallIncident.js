import mongoose from "mongoose";

const firewallIncidentSchema = new mongoose.Schema(
  {
    ip: { type: String, index: true },
    method: { type: String, default: "GET" },
    path: { type: String, index: true },
    fullUrl: { type: String, default: "" },
    userAgent: { type: String, default: "" },

    sourceType: {
      type: String,
      enum: ["query", "body", "params", "url", "headers", "manual"],
      default: "url",
    },

    attackType: {
      type: String,
      enum: ["sql-injection", "xss", "path-traversal", "keyword-spam"],
      required: true,
      index: true,
    },

    severity: {
      type: String,
      enum: ["critical", "high", "medium", "low"],
      default: "medium",
      index: true,
    },

    matchedPattern: { type: String, default: "" },
    suspiciousValue: { type: String, default: "" },

    keywordDensity: { type: Number, default: 0 },
    repeatedKeyword: { type: String, default: "" },

    blocked: { type: Boolean, default: false },
    simulatedAction: {
      type: String,
      enum: ["allow", "flag", "block"],
      default: "flag",
    },

    geo: {
      country: String,
      city: String,
      region: String,
    },

    acknowledged: { type: Boolean, default: false },
    resolved: { type: Boolean, default: false },
  },
  { timestamps: true }
);

firewallIncidentSchema.index({ createdAt: -1, attackType: 1, severity: 1 });

export default mongoose.model("FirewallIncident", firewallIncidentSchema);