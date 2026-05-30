import mongoose from "mongoose";

const incidentResponseSchema = new mongoose.Schema({
  attackType: {
    type: String,
    required: true,
  },
  ipAddress: {
    type: String,
    required: true,
  },
  severity: {
    type: String,
    enum: ["low", "medium", "high", "critical"],
    default: "medium",
  },
  status: {
    type: String,
    enum: ["detected", "blocked", "recovered"],
    default: "detected",
  },
  autoBlocked: {
    type: Boolean,
    default: false,
  },
  recoveryProcedure: {
    type: String,
    default: "",
  },
  incidentAlert: {
    type: Boolean,
    default: false,
  },
  mitigationSteps: {
    type: String,
    default: "",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("IncidentResponse", incidentResponseSchema);