// ================== ENV LOAD (IMPORTANT) ==================
import "dotenv/config";

// ================== CORE ==================
import express from "express";
import cors from "cors";
import morgan from "morgan";
import http from "http";
import { Server } from "socket.io";

// ================== INTERNAL ==================
import { connectDB } from "./config/db.js";

import authRoutes from "./routes/authRoutes.js";
import logRoutes from "./routes/logRoutes.js";
import vulnerabilityRoutes from "./routes/vulnerabilityRoutes.js";
import trafficRoutes from "./routes/trafficRoutes.js";
import dashboardRoutes from "./routes/dashboardRoutes.js";
import alertRoutes from "./routes/alertRoutes.js";
import threatRoutes from "./routes/threatRoutes.js";
import firewallRoutes from "./routes/firewallRoutes.js";
import dataEncryptionRoutes from "./routes/dataEncryptionRoutes.js";
import anomalyRoutes from "./routes/anomalyRoutes.js";
import incidentResponseRoutes from "./routes/incidentResponseRoutes.js";
import incidentAnalysisRoutes from "./routes/incidentAnalysisRoutes.js";
import profileRoutes from "./routes/profileRoutes.js"; // ✅ NEW

import {
  startLogArchiveCron,
  startLogCleanupCron,
} from "./utils/cronJobs.js";

import { trafficLogger } from "./controllers/trafficController.js";
import { initSocket } from "./utils/socket.js";
import { firewallMiddleware } from "./middleware/firewallMiddleware.js";

// ================== APP ==================
const app = express();
const server = http.createServer(app);

// ================== SOCKET ==================
const io = new Server(server, {
  cors: {
    origin: [
      "http://localhost:5173",
      "https://seo-intrusion-frontend.vercel.app",
    ],
    credentials: true,
  },
});

initSocket(io);

// ================== DB ==================
connectDB();

// ================== MIDDLEWARE ==================
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://seo-intrusion-frontend.vercel.app",
    ],
    credentials: true,
  })
);

app.use(express.json());
app.use(morgan("dev"));

// ================== FIREWALL ==================
app.use(firewallMiddleware);

// ================== TRAFFIC LOGGER ==================
const TRAFFIC_EXCLUDED = ["/api/traffic"];

app.use((req, res, next) => {
  const path = req.originalUrl || "";
  const isExcluded = TRAFFIC_EXCLUDED.some((p) => path.startsWith(p));
  if (isExcluded) return next();
  return trafficLogger(req, res, next);
});

// ================== ROUTES ==================
app.use("/api/auth", authRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/traffic", trafficRoutes);
app.use("/api/logs", logRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/threats", threatRoutes);
app.use("/api/firewall", firewallRoutes);
app.use("/api/data-encryption", dataEncryptionRoutes);
app.use("/api/anomaly", anomalyRoutes);
app.use("/api/incident-response", incidentResponseRoutes);
app.use("/api/incident-analysis", incidentAnalysisRoutes);
app.use("/api/profile", profileRoutes); // ✅ NEW

// ================== ROOT ==================
app.get("/", (req, res) => {
  res.send("🚀 SEO Intrusion Backend Running...");
});

// ================== CRON ==================
startLogArchiveCron();
startLogCleanupCron();

// ================== SOCKET EVENTS ==================
io.on("connection", (socket) => {
  console.log("⚡ Socket Connected:", socket.id);
  socket.on("disconnect", () => {
    console.log("⚡ Socket Disconnected:", socket.id);
  });
});

// ================== SERVER ==================
const PORT = process.env.PORT || 4000;

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});