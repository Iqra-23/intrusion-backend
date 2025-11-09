import mongoose from "mongoose";

const logSchema = new mongoose.Schema({
  level: { 
    type: String, 
    enum: ["error", "warning", "suspicious", "info"], 
    default: "info",
    index: true 
  },
  message: { type: String, required: true, index: true },
  keyword: [String],
  ipAddress: String,
  userAgent: String,
  url: String,
  method: String,
  statusCode: Number,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  metadata: mongoose.Schema.Types.Mixed, // Additional context
  archived: { type: Boolean, default: false, index: true },
  archivedAt: Date,
  createdAt: { type: Date, default: Date.now, index: true }
});

// Index for fast searching
logSchema.index({ message: "text", keyword: "text" });
logSchema.index({ level: 1, createdAt: -1 });
logSchema.index({ archived: 1, createdAt: -1 });

// Method to archive old logs (older than 30 days)
logSchema.statics.archiveOldLogs = async function() {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  
  const result = await this.updateMany(
    { createdAt: { $lt: thirtyDaysAgo }, archived: false },
    { $set: { archived: true, archivedAt: new Date() } }
  );
  
  return result;
};

// Method to delete archived logs older than 90 days
logSchema.statics.deleteOldArchivedLogs = async function() {
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  
  const result = await this.deleteMany({
    archived: true,
    archivedAt: { $lt: ninetyDaysAgo }
  });
  
  return result;
};

export default mongoose.model("Log", logSchema);