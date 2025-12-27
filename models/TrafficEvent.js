// models/TrafficEvent.js
import mongoose from "mongoose";

const geoSchema = new mongoose.Schema(
  {
    country: String,
    city: String,
    region: String,
    isp: String,
    lat: Number,
    lon: Number,
  },
  { _id: false }
);

const trafficEventSchema = new mongoose.Schema(
  {
    ip: { type: String, index: true },
    method: String,
    path: { type: String, index: true },
    status: Number,
    userAgent: String,
    referrer: String,

    // ✅ NEW: which module generated this request (Dashboard, Logs, Auth...)
    module: { type: String, index: true, default: "Other" },

    // ✅ FULL RAW HEADERS LOGGED (FEATURE 1)
    headers: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // ✅ SESSION TRACKING (FEATURE 2)
    sessionId: { type: String, index: true },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    // ✅ GEO LOCATION (FEATURE 3)
    geo: geoSchema,

    // ✅ SPIKE DETECTION (FEATURE 5)
    isSpike: { type: Boolean, default: false },
    tags: [{ type: String }],

    // ✅ ANOMALY DETECTION (FEATURE 4)
    anomalyScore: { type: Number, default: 0, min: 0, max: 100 },
    anomalyReasons: [{ type: String }],

    // ✅ useful for UI (response time)
    durationMs: { type: Number, default: 0 },
  },
  { timestamps: true }
);

const TrafficEvent = mongoose.model("TrafficEvent", trafficEventSchema);
export default TrafficEvent;
