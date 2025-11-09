import mongoose from "mongoose";

const scanHistorySchema = new mongoose.Schema({
  scanId: { type: String, required: true, unique: true, index: true },
  siteUrl: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  status: {
    type: String,
    enum: ["In Progress", "Completed", "Failed"],
    default: "In Progress"
  },
  totalVulnerabilities: { type: Number, default: 0 },
  criticalCount: { type: Number, default: 0 },
  highCount: { type: Number, default: 0 },
  mediumCount: { type: Number, default: 0 },
  lowCount: { type: Number, default: 0 },
  duration: Number, // Scan duration in seconds
  startedAt: { type: Date, default: Date.now },
  completedAt: Date,
  errorMessage: String
});

scanHistorySchema.index({ userId: 1, startedAt: -1 });
scanHistorySchema.index({ siteUrl: 1, startedAt: -1 });

export default mongoose.model("ScanHistory", scanHistorySchema);