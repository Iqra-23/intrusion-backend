import mongoose from "mongoose";

const threatIPListSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true, unique: true, index: true },
    listType: {
      type: String,
      enum: ["blacklist", "whitelist"],
      required: true,
    },
    reason: { type: String, default: "" },
  },
  { timestamps: true }
);

export default mongoose.model("ThreatIPList", threatIPListSchema);