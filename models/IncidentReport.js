import mongoose from "mongoose";

const incidentReportSchema = new mongoose.Schema({
  reportType: {
    type: String,
    enum: ["daily", "weekly", "monthly"],
    required: true,
  },
  generatedAt: {
    type: Date,
    default: Date.now,
  },
  totalIncidents: { type: Number, default: 0 },
  blocked:        { type: Number, default: 0 },
  recovered:      { type: Number, default: 0 },
  alerts:         { type: Number, default: 0 },
  attackBreakdown: {
    DoS:       { type: Number, default: 0 },
    Injection: { type: Number, default: 0 },
    Malware:   { type: Number, default: 0 },
    Other:     { type: Number, default: 0 },
  },
  incidents: [{ type: mongoose.Schema.Types.ObjectId, ref: "IncidentResponse" }],
});

export default mongoose.model("IncidentReport", incidentReportSchema);