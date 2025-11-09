// backend/models/Alert.js

import mongoose from "mongoose";

const alertSchema = new mongoose.Schema(
  {
    // Kis log se alert trigger hua
    logId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Log",
      required: true,
    },

    // Severity: critical / high / medium / low
    severity: {
      type: String,
      enum: ["critical", "high", "medium", "low"],
      required: true,
      index: true,
    },

    // Alert ka title
    title: {
      type: String,
      required: true,
      trim: true,
    },

    // Detail message (usually log.message)
    description: {
      type: String,
      required: true,
    },

    // Keywords (optional)
    keywords: [
      {
        type: String,
        trim: true,
      },
    ],

    // Acknowledgement
    acknowledged: {
      type: Boolean,
      default: false,
      index: true,
    },
    acknowledgedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    acknowledgedAt: Date,

    // Resolution
    resolved: {
      type: Boolean,
      default: false,
      index: true,
    },
    resolvedAt: Date,
  },
  {
    timestamps: true, // createdAt, updatedAt
  }
);

// Helpful indexes
alertSchema.index({ severity: 1, createdAt: -1 });
alertSchema.index({ acknowledged: 1, resolved: 1, createdAt: -1 });

export default mongoose.model("Alert", alertSchema);


