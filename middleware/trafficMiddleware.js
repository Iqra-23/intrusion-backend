import detectSpike from "../utils/detectSpike.js";
import { lookupGeo } from "../utils/ipGeo.js";
import TrafficEvent from "../models/TrafficEvent.js";

export const trafficMiddleware = async (req, res, next) => {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress ||
    "Unknown";

  const method = req.method;
  const path = req.originalUrl;
  const userAgent = req.headers["user-agent"] || "-";

  res.on("finish", async () => {
    try {
      const status = res.statusCode;
      const geo = await lookupGeo(ip);
      const isSpike = detectSpike(ip);

      await TrafficEvent.create({
        ip,
        method,
        path,
        status,
        userAgent,
        geo,
        isSpike,
        tags: isSpike ? ["spike"] : [],
      });
    } catch (err) {
      console.log("Traffic save error:", err.message);
    }
  });

  next();
};
