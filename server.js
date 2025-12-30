// server.js
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

import { startLogArchiveCron, startLogCleanupCron } from "./utils/cronJobs.js";
import { trafficLogger } from "./controllers/trafficController.js";
import { initSocket } from "./utils/socket.js";

dotenv.config();

const app = express();

/* ===================== DATABASE ===================== */
connectDB();

/* ===================== CORS ===================== */
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://seo-intrusion-frontend.vercel.app",
    ],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

/* ===================== MIDDLEWARE ===================== */
app.use(express.json());
app.use(morgan("dev"));

/* ===================== ROUTES (AUTH FIRST) ===================== */
// ❗ AUTH ROUTES FIRST — no traffic logger here
app.use("/api/auth", authRoutes);

// ❗ OTHER MODULES
app.use("/api/logs", logRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/dashboard", dashboardRoutes);

/* ===================== TRAFFIC LOGGER ===================== */
// ✅ AFTER auth — so login / google login never breaks
app.use(trafficLogger);
app.use("/api/traffic", trafficRoutes);

/* ===================== CRON JOBS ===================== */
startLogArchiveCron();
startLogCleanupCron();

/* ===================== SERVER + SOCKET ===================== */
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: [
      "http://localhost:5173",
      "https://seo-intrusion-frontend.vercel.app",
    ],
    methods: ["GET", "POST", "PATCH", "DELETE"],
    credentials: true,
  },
});

initSocket(io);

io.on("connection", (socket) => {
  console.log("⚡ Socket connected:", socket.id);
});

/* ===================== HEALTH CHECK ===================== */
app.get("/", (req, res) => {
  res.send("<h1>SEO Intrusion Backend is running 🚀</h1>");
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
