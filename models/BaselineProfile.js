import mongoose from "mongoose";

const baselineProfileSchema = new mongoose.Schema(
  {
    label: {
      type: String,
      default: "Normal Traffic Baseline",
    },
    avgRequestsPerMinute: {
      type: Number,
      default: 10,
    },
    avgLoginAttempts: {
      type: Number,
      default: 3,
    },
    avgFailedLogins: {
      type: Number,
      default: 1,
    },
    avgSeoKeywordHits: {
      type: Number,
      default: 3,
    },
    thresholdMultiplier: {
      type: Number,
      default: 2,
    },
  },
  { timestamps: true }
);

export default mongoose.model("BaselineProfile", baselineProfileSchema);