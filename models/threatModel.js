import mongoose from "mongoose";

const threatSchema = new mongoose.Schema(
  {
    ip: {
      type: String,
      required: true,
      trim: true,
    },
    url: {
      type: String,
      required: true,
      trim: true,
    },
    method: {
      type: String,
      required: true,
      trim: true,
      uppercase: true,
    },
    threatScore: {
      type: Number,
      default: 0,
    },
    threatLevel: {
      type: String,
      enum: ["LOW", "MEDIUM", "HIGH"],
      default: "LOW",
    },
    reason: {
      type: String,
      default: "",
    },
  },
  { timestamps: true }
);

const Threat = mongoose.model("Threat", threatSchema);

export default Threat;