// controllers/trafficController.js
import fs from "fs";
import TrafficEvent from "../models/TrafficEvent.js";
import AnomalyRecord from "../models/AnomalyRecord.js";
import BaselineProfile from "../models/BaselineProfile.js";
import { lookupGeo } from "../utils/ipGeo.js";
import { generateTrafficReport } from "../utils/trafficReportGenerator.js";
import { getIO } from "../utils/socket.js";

const ipCounter = new Map();

const SPIKE_THRESHOLD = 5;
console.log("🔥 SPIKE THRESHOLD ACTIVE:", SPIKE_THRESHOLD);

const SUSPICIOUS_PATTERNS = [
  "select ", "union ", " or 1=1", "../", "<script",
  " onerror=", " drop ", "insert into", "xp_cmdshell",
  "config.php", "wp-admin",
];

const HIGH_RISK_COUNTRIES = ["CN", "RU", "KP", "IR", "SY"];

// ─── helpers ──────────────────────────────────────────────────────────────────

const getClientIp = (req) => {
  const xfwd = req.headers["x-forwarded-for"];
  if (xfwd) return xfwd.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "";
};

const deriveModule = (path = "") => {
  const p = String(path);
  if (p.startsWith("/api/auth"))            return "Auth";
  if (p.startsWith("/api/logs"))            return "Log Management";
  if (p.startsWith("/api/vulnerabilities")) return "Vulnerability Scanner";
  if (p.startsWith("/api/dashboard"))       return "Dashboard";
  if (p.startsWith("/api/traffic"))         return "Traffic Monitor";
  return "Other";
};

const computeAnomalyScore = ({ method, path, status, geo, isSpike, userAgent }) => {
  let score = 0;
  const reasons = [];

  if (isSpike)          { score += 40; reasons.push("High request rate (spike)"); }
  if (status >= 500)    { score += 30; reasons.push("5xx server error"); }
  else if (status>=400) { score += 20; reasons.push("4xx client error"); }

  if (["PUT","DELETE","PATCH"].includes(method)) { score += 10; reasons.push(`High-impact method: ${method}`); }
  else if (method==="POST")                       { score +=  5; reasons.push("Write operation (POST)"); }

  const lp = (path||"").toLowerCase();
  if (SUSPICIOUS_PATTERNS.some((p)=>lp.includes(p))) { score += 15; reasons.push("Suspicious pattern in path"); }

  const country = geo?.country || "";
  if (country && HIGH_RISK_COUNTRIES.includes(country)) { score += 10; reasons.push(`High-risk geo: ${country}`); }

  const ua = (userAgent||"").toLowerCase();
  if (!ua || ua.includes("curl") || ua.includes("bot") || ua.includes("scanner")) {
    score += 10; reasons.push("Non-browser / bot user agent");
  }

  return { offerScore: Math.min(100, Math.max(0, score)), reasons };
};

// ─── anomaly auto-trigger ─────────────────────────────────────────────────────
// FIX: threshold raised to 70 — only real HIGH/CRITICAL threats trigger anomaly
// Previously 40 caused every normal API request to create an anomaly record
// Also: only spikes OR suspicious patterns trigger — not regular 4xx/POST calls
const autoTriggerAnomaly = async ({ ip, anomalyScore, anomalyReasons, isSpike, requestCount, method, path }) => {
  try {
    // Only trigger for genuinely suspicious traffic
    // Score 70+ means either: spike + error, or suspicious pattern, or high-risk geo + method
    if (anomalyScore < 70) return;

    // Extra guard: must have a real reason (spike or suspicious pattern)
    const hasRealReason = isSpike ||
      anomalyReasons.some((r) =>
        r.includes("Suspicious pattern") ||
        r.includes("High-risk geo") ||
        r.includes("bot") ||
        r.includes("5xx")
      );
    if (!hasRealReason) return;

    const baseline = await BaselineProfile.findOne().sort({ createdAt: -1 });
    const baselineVal = baseline?.avgRequestsPerMinute || 10;

    let anomalyType = "abnormal-request-frequency";
    if (anomalyReasons.some((r) => r.includes("Suspicious pattern"))) {
      anomalyType = "negative-seo-traffic";
    }

    let severity = "HIGH";
    if (anomalyScore >= 90) severity = "CRITICAL";

    const reason = `Auto-detected: ${anomalyReasons.slice(0, 2).join(", ")}`;
    const deviation = baselineVal > 0
      ? Math.round(((requestCount - baselineVal) / baselineVal) * 100)
      : 0;

    const record = await AnomalyRecord.create({
      ip,
      anomalyType,
      severity,
      score: anomalyScore,
      currentValue: requestCount || 1,
      baselineValue: baselineVal,
      deviation,
      reason,
      emailAlertSent: anomalyScore >= 70,
      details: { method, path, autoTriggered: true },
    });

    try {
      const io = getIO();
      io.emit("anomaly-alert", {
        message: record.reason,
        anomalyType: record.anomalyType,
        severity: record.severity,
        ip: record.ip,
        createdAt: record.createdAt,
      });
      io.emit("new-alert", {
        title: "Anomaly Auto-Detected",
        severity: record.severity?.toLowerCase() || "high",
        description: record.reason,
        createdAt: new Date(),
      });
    } catch (_) {
      // socket not ready — ignore
    }
  } catch (err) {
    console.error("autoTriggerAnomaly error:", err.message);
  }
};

// ─── middleware ───────────────────────────────────────────────────────────────

export const trafficLogger = async (req, res, next) => {
  const start = Date.now();
  const ip        = getClientIp(req);
  const method    = req.method;
  const path      = req.originalUrl || req.url;
  const userAgent = req.headers["user-agent"] || "";
  const referrer  = req.headers["referer"] || req.headers["referrer"] || "";
  const userId    = req.user?._id || null;
  const module    = deriveModule(path);
  const sessionId = req.sessionID || req.headers["x-session-id"] || `${ip}-${String(userAgent).slice(0,40)}`;

  res.on("finish", async () => {
    try {
      const status    = res.statusCode;
      const durationMs = Date.now() - start;
      const geo       = await lookupGeo(ip);

      const minuteKey = new Date().toISOString().slice(0, 16);
      const key       = `${ip}:${minuteKey}`;
      const newCount  = (ipCounter.get(key) || 0) + 1;
      ipCounter.set(key, newCount);

      const isSpike = newCount >= SPIKE_THRESHOLD;
      const tags    = [];
      if (isSpike)       tags.push("spike");
      if (status >= 500) tags.push("server-error");
      else if (status >= 400) tags.push("client-error");

      const { offerScore: anomalyScore, reasons: anomalyReasons } = computeAnomalyScore({
        method, path, status, geo, isSpike, userAgent,
      });

      if (isSpike && !anomalyReasons.includes("High request rate (spike)")) {
        anomalyReasons.push("High request rate (spike)");
      }

      await TrafficEvent.create({
        ip, method, path, status, userAgent, referrer, module,
        headers: {
          host: req.headers["host"],
          origin: req.headers["origin"],
          referer: referrer,
          "content-type": req.headers["content-type"],
          "accept-language": req.headers["accept-language"],
          "x-forwarded-for": req.headers["x-forwarded-for"],
        },
        userId, sessionId, geo, isSpike, tags, anomalyScore, anomalyReasons, durationMs,
      });

      // Auto-trigger only for genuinely suspicious traffic (score >= 70)
      if (anomalyScore >= 70) {
        autoTriggerAnomaly({ ip, anomalyScore, anomalyReasons, isSpike, requestCount: newCount, method, path })
          .catch(() => {});
      }
    } catch (err) {
      console.error("Traffic log save error:", err.message);
    } finally {
      if (ipCounter.size > 10000) ipCounter.clear();
    }
  });

  next();
};

// ─── APIs ─────────────────────────────────────────────────────────────────────

export const getTrafficEvents = async (req, res) => {
  try {
    const { page=1, limit=50, search="", ip, country, method, path, status, spike, minAnomaly, module } = req.query;
    const q = {};
    if (search) {
      q.$or = [
        { ip: { $regex: search, $options:"i" } },
        { path: { $regex: search, $options:"i" } },
        { userAgent: { $regex: search, $options:"i" } },
        { "geo.country": { $regex: search, $options:"i" } },
        { module: { $regex: search, $options:"i" } },
      ];
    }
    if (ip)                    q.ip              = ip;
    if (country)               q["geo.country"]  = country;
    if (method)                q.method          = method.toUpperCase();
    if (path)                  q.path            = { $regex: path, $options:"i" };
    if (status)                q.status          = Number(status);
    if (spike==="true")        q.isSpike         = true;
    if (minAnomaly)            q.anomalyScore    = { $gte: Number(minAnomaly) };
    if (module && module!=="ALL") q.module       = module;

    const pageNum  = parseInt(page);
    const limitNum = parseInt(limit);
    const skip     = (pageNum - 1) * limitNum;

    const [items, total] = await Promise.all([
      TrafficEvent.find(q).sort({ createdAt: -1 }).skip(skip).limit(limitNum),
      TrafficEvent.countDocuments(q),
    ]);

    res.json({ events: items, pagination: { total, page: pageNum, pages: Math.ceil(total/limitNum), limit: limitNum } });
  } catch (err) {
    console.error("getTrafficEvents error:", err.message);
    res.status(500).json({ message: "Error fetching traffic events" });
  }
};

export const getTrafficEventById = async (req, res) => {
  try {
    const item = await TrafficEvent.findById(req.params.id);
    if (!item) return res.status(404).json({ message: "Traffic event not found" });
    return res.json(item);
  } catch (err) {
    return res.status(500).json({ message: "Error fetching traffic event" });
  }
};

export const getTrafficStats = async (req, res) => {
  try {
    const total        = await TrafficEvent.countDocuments();
    const uniqueIpsAgg = await TrafficEvent.aggregate([{ $group:{_id:"$ip"} },{ $count:"count" }]);
    const uniqueIps    = uniqueIpsAgg[0]?.count || 0;
    const byCountry    = await TrafficEvent.aggregate([{ $group:{_id:"$geo.country",count:{$sum:1}} },{ $sort:{count:-1} },{ $limit:10 }]);
    const byMethod     = await TrafficEvent.aggregate([{ $group:{_id:"$method",count:{$sum:1}} }]);
    const byModule     = await TrafficEvent.aggregate([{ $group:{_id:"$module",count:{$sum:1}} },{ $sort:{count:-1} },{ $limit:8 }]);
    const last1hSpikes = await TrafficEvent.countDocuments({ isSpike:true, createdAt:{ $gte:new Date(Date.now()-3600000) } });
    const recentSpikes = await TrafficEvent.find({ isSpike:true }).sort({ createdAt:-1 }).limit(20);
    const last15min    = new Date(Date.now()-900000);
    const sessionsAgg  = await TrafficEvent.aggregate([{ $match:{createdAt:{$gte:last15min}} },{ $group:{_id:"$sessionId",count:{$sum:1}} }]);
    const activeSessions = sessionsAgg.length;
    const avgRequestsPerSession = activeSessions>0 ? sessionsAgg.reduce((a,b)=>a+(b.count||0),0)/activeSessions : 0;
    const last24h       = new Date(Date.now()-86400000);
    const highAnomalies24h = await TrafficEvent.countDocuments({ createdAt:{$gte:last24h}, anomalyScore:{$gte:70} });
    const avgAgg        = await TrafficEvent.aggregate([{ $group:{_id:null,avgScore:{$avg:"$anomalyScore"}} }]);
    const avgAnomalyScore = avgAgg[0]?.avgScore || 0;
    const anomalyBuckets  = await TrafficEvent.aggregate([{ $group:{ _id:{ $cond:[{ $gte:["$anomalyScore",70] },"High",{ $cond:[{ $gte:["$anomalyScore",35] },"Medium","Low"] }] }, count:{$sum:1} } }]);

    res.json({ total, uniqueIps, byCountry, byMethod, byModule, last1hSpikes, recentSpikes, activeSessions, avgRequestsPerSession, highAnomalies24h, avgAnomalyScore, anomalyBuckets });
  } catch (err) {
    console.error("getTrafficStats error:", err.message);
    res.status(500).json({ message: "Error fetching traffic stats" });
  }
};

export const getTrafficAlerts = async (req, res) => {
  try {
    const last15min = new Date(Date.now()-900000);
    const alerts    = await TrafficEvent.find({ isSpike:true, createdAt:{$gte:last15min} }).sort({ createdAt:-1 }).limit(20);
    res.json(alerts);
  } catch (err) {
    console.error("getTrafficAlerts error:", err.message);
    res.status(500).json({ message: "Error fetching traffic alerts" });
  }
};

export const exportTrafficPdf = async (req, res) => {
  try {
    const { search="", ip, country, method, path, status, minAnomaly, module } = req.query;
    const q = {};
    if (search) { q.$or=[{ ip:{$regex:search,$options:"i"} },{ path:{$regex:search,$options:"i"} },{ userAgent:{$regex:search,$options:"i"} },{ "geo.country":{$regex:search,$options:"i"} },{ module:{$regex:search,$options:"i"} }]; }
    if (ip)      q.ip            = ip;
    if (country) q["geo.country"]= country;
    if (method)  q.method        = method.toUpperCase();
    if (path)    q.path          = { $regex:path,$options:"i" };
    if (status)  q.status        = Number(status);
    if (minAnomaly) q.anomalyScore = { $gte:Number(minAnomaly) };
    if (module && module!=="ALL") q.module = module;

    const events = await TrafficEvent.find(q).sort({ createdAt:-1 }).limit(1000).lean();
    if (!events||events.length===0) return res.status(404).json({ message:"No traffic events found to export" });

    const reportsDir = "./reports";
    if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir,{ recursive:true });
    const fileName = `traffic_report_${Date.now()}.pdf`;
    const filePath = `${reportsDir}/${fileName}`;
    await generateTrafficReport(events,{ search,ip,country,method,path,status,minAnomaly,module },filePath);
    res.download(filePath,fileName,(err)=>{
      if (err) console.error("Traffic PDF download error:",err);
      setTimeout(()=>{ try{ if(fs.existsSync(filePath))fs.unlinkSync(filePath); }catch(e){} },5000);
    });
  } catch (e) {
    console.error("exportTrafficPdf error:",e.message);
    res.status(500).json({ message:"Error generating traffic PDF",error:e.message });
  }
};

export const exportSingleTrafficPdf = async (req, res) => {
  try {
    const event = await TrafficEvent.findById(req.params.id).lean();
    if (!event) return res.status(404).json({ message:"Traffic event not found" });
    const reportsDir = "./reports";
    if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir,{ recursive:true });
    const fileName = `traffic_event_${req.params.id}.pdf`;
    const filePath = `${reportsDir}/${fileName}`;
    await generateTrafficReport([event],{ single:true,id:req.params.id },filePath);
    res.download(filePath,fileName,(err)=>{
      if (err) console.error("Single Traffic PDF error:",err);
      setTimeout(()=>{ try{ if(fs.existsSync(filePath))fs.unlinkSync(filePath); }catch(e){} },5000);
    });
  } catch (e) {
    console.error("exportSingleTrafficPdf error:",e.message);
    res.status(500).json({ message:"Error generating single traffic PDF" });
  }
};

export const deleteTrafficEvents = async (req, res) => {
  try {
    const { ids } = req.body || {};
    const filter  = Array.isArray(ids)&&ids.length>0 ? { _id:{$in:ids} } : {};
    const result  = await TrafficEvent.deleteMany(filter);
    return res.json({ message:"Traffic events deleted successfully", deletedCount:result.deletedCount });
  } catch (err) {
    console.error("deleteTrafficEvents error:",err.message);
    return res.status(500).json({ message:"Error deleting traffic events" });
  }
};