import mongoose from "mongoose";

const anomalyRecordSchema = new mongoose.Schema(
  {
    ip: {
      type: String,
      required: true,
    },
    anomalyType: {
      type: String,
      enum: [
        "unusual-login",
        "abnormal-request-frequency",
        "negative-seo-traffic",
        "normal-traffic",
      ],
      required: true,
    },
    severity: {
      type: String,
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      default: "LOW",
    },
    score: {
      type: Number,
      default: 0,
    },
    currentValue: {
      type: Number,
      default: 0,
    },
    baselineValue: {
      type: Number,
      default: 0,
    },
    deviation: {
      type: Number,
      default: 0,
    },
    reason: {
      type: String,
      default: "",
    },
    emailAlertSent: {
      type: Boolean,
      default: false,
    },
    details: {
      type: Object,
      default: {},
    },
  },
  { timestamps: true }
);

export default mongoose.model("AnomalyRecord", anomalyRecordSchema);