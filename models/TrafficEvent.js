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
    ip: String,
    method: String,
    path: String,
    status: Number,
    userAgent: String,

    // 🔹 FULL RAW HEADERS LOGGED (FEATURE: Logging of request headers + IP)
    headers: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // 🔹 BASIC SESSION TRACKING (same sessionId for same user/session)
    sessionId: {
      type: String,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    // 🔹 GEO LOCATION (FEATURE: Geo-location lookup)
    geo: geoSchema,

    // 🔹 SPIKE + TAGGING
    isSpike: { type: Boolean, default: false },
    tags: [{ type: String }],

    // 🔹 TRAFFIC ANOMALY DETECTION SCORE (0–100)
    anomalyScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    anomalyReasons: [
      {
        type: String,
      },
    ],
  },
  { timestamps: true }
);

const TrafficEvent = mongoose.model("TrafficEvent", trafficEventSchema);
export default TrafficEvent;
