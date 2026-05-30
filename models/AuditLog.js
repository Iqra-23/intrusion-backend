import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true,
  },
  performedBy: {
    type: String,
    default: "Admin",
  },
  targetId: {
    type: String,
    default: "",
  },
  details: {
    type: String,
    default: "",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("AuditLog", auditLogSchema);