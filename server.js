import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import http from "http";
import { Server } from "socket.io";

import { connectDB } from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";
import logRoutes from "./routes/logRoutes.js";
import vulnerabilityRoutes from "./routes/vulnerabilityRoutes.js";
import trafficRoutes from "./routes/trafficRoutes.js";
import dashboardRoutes from "./routes/dashboardRoutes.js";
import alertRoutes from "./routes/alertRoutes.js";


import { startLogArchiveCron, startLogCleanupCron } from "./utils/cronJobs.js";
import { trafficLogger } from "./controllers/trafficController.js";
import { initSocket } from "./utils/socket.js";



dotenv.config();
const app = express();

/* ================== DB ================== */
connectDB();

/* ================== MIDDLEWARE ================== */
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

/* ================== ROUTES ================== */
// ❗ DO NOT log internal system APIs
app.use("/api/auth", authRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/traffic", trafficRoutes);
app.use("/api/logs", logRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/logs", alertRoutes);

/* ================== TRAFFIC LOGGER (SAFE) ================== */
// 🔥 ONLY log REAL USER TRAFFIC
app.use((req, res, next) => {
  if (
    req.originalUrl.startsWith("/api/auth") ||
    req.originalUrl.startsWith("/api/dashboard") ||
    req.originalUrl.startsWith("/api/traffic") ||
    req.originalUrl.startsWith("/api/logs") ||
    req.originalUrl.startsWith("/api/vulnerabilities")
  ) {
    return next(); // ❌ don't log system APIs
  }
  trafficLogger(req, res, next);
});

/* ================== CRONS ================== */
startLogArchiveCron();
startLogCleanupCron();

/* ================== SERVER + SOCKET ================== */
const server = http.createServer(app);
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

io.on("connection", () => {
  console.log("⚡ Socket Connected");
});

/* ================== START ================== */
server.listen(process.env.PORT, () => {
  console.log(`🚀 Server running on port ${process.env.PORT}`);
});

app.get("/", (req, res) => {
  res.send("Server running 🚀");
});
