// // ================== ENV (MUST BE FIRST) ==================
// import dotenv from "dotenv";
// dotenv.config();

// // ================== CORE IMPORTS ==================
// import express from "express";
// import cors from "cors";
// import morgan from "morgan";
// import http from "http";
// import { Server } from "socket.io";

// // ================== INTERNAL IMPORTS ==================
// import { connectDB } from "./config/db.js";

// import authRoutes from "./routes/authRoutes.js";
// import logRoutes from "./routes/logRoutes.js";
// import vulnerabilityRoutes from "./routes/vulnerabilityRoutes.js";
// import trafficRoutes from "./routes/trafficRoutes.js";
// import dashboardRoutes from "./routes/dashboardRoutes.js";
// import alertRoutes from "./routes/alertRoutes.js";
// import threatRoutes from "./routes/threatRoutes.js";
// import firewallRoutes from "./routes/firewallRoutes.js";

// import dataEncryptionRoutes from "./routes/dataEncryptionRoutes.js";





// import { startLogArchiveCron, startLogCleanupCron } from "./utils/cronJobs.js";
// import { trafficLogger } from "./controllers/trafficController.js";
// import { initSocket } from "./utils/socket.js";
// import { firewallMiddleware } from "./middleware/firewallMiddleware.js";

// // ================== APP INIT ==================
// const app = express();

// /* ================== DATABASE ================== */
// connectDB();

// /* ================== MIDDLEWARE ================== */
// app.use(
//   cors({
//     origin: [
//       "http://localhost:5173",
//       "https://seo-intrusion-frontend.vercel.app",
//     ],
//     credentials: true,
//   })
// );

// app.use(express.json());
// app.use(morgan("dev"));

// // ✅ Firewall middleware
// app.use(firewallMiddleware);

// /* ================== ROUTES ================== */
// // ❗ Internal APIs should NOT be logged as traffic
// app.use("/api/auth", authRoutes);
// app.use("/api/dashboard", dashboardRoutes);
// app.use("/api/traffic", trafficRoutes);
// app.use("/api/logs", logRoutes);
// app.use("/api/vulnerabilities", vulnerabilityRoutes);
// app.use("/api/logs", alertRoutes);
// app.use("/api/threats", threatRoutes);
// app.use("/api/firewall", firewallRoutes);
// app.use("/api/encryption", dataEncryptionRoutes);

// /* ================== TRAFFIC LOGGER ================== */
// // 🔥 Only log REAL USER traffic (not internal APIs)
// app.use((req, res, next) => {
//   if (
//     req.originalUrl.startsWith("/api/auth") ||
//     req.originalUrl.startsWith("/api/dashboard") ||
//     req.originalUrl.startsWith("/api/traffic") ||
//     req.originalUrl.startsWith("/api/logs") ||
//     req.originalUrl.startsWith("/api/vulnerabilities") ||
//     req.originalUrl.startsWith("/api/firewall") ||
//     req.originalUrl.startsWith("/api/threats")
//   ) {
//     return next();
//   }
//   trafficLogger(req, res, next);
// });

// /* ================== CRON JOBS ================== */
// startLogArchiveCron();
// startLogCleanupCron();

// /* ================== ROOT ================== */
// app.get("/", (req, res) => {
//   res.send("Server running 🚀");
// });

// /* ================== SERVER & SOCKET ================== */
// const server = http.createServer(app);

// const io = new Server(server, {
//   cors: {
//     origin: [
//       "http://localhost:5173",
//       "https://seo-intrusion-frontend.vercel.app",
//     ],
//     credentials: true,
//   },
// });

// initSocket(io);

// io.on("connection", () => {
//   console.log("⚡ Socket Connected");
// });

// /* ================== START SERVER ================== */
// const PORT = process.env.PORT || 4000;

// server.listen(PORT, () => {
//   console.log(`🚀 Server running on port ${PORT}`);
// });

// ================== ENV (MUST BE FIRST) ==================
import "dotenv/config";

// ================== CORE IMPORTS ==================
import express from "express";
import cors from "cors";
import morgan from "morgan";
import http from "http";
import { Server } from "socket.io";

// ================== INTERNAL IMPORTS ==================
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

import { startLogArchiveCron, startLogCleanupCron } from "./utils/cronJobs.js";
import { trafficLogger } from "./controllers/trafficController.js";
import { initSocket } from "./utils/socket.js";
import { firewallMiddleware } from "./middleware/firewallMiddleware.js";

// ================== APP INIT ==================
const app = express();
const server = http.createServer(app);

// ================== SOCKET.IO ==================
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "*",
    methods: ["GET", "POST"],
  },
});

initSocket(io);

// ================== MIDDLEWARE ==================
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

// custom middlewares
app.use(firewallMiddleware);
app.use(trafficLogger);


// ================== ROUTES ==================
app.use("/api/auth", authRoutes);
app.use("/api/logs", logRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/traffic", trafficRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/threats", threatRoutes);
app.use("/api/firewall", firewallRoutes);
app.use("/api/encryption", dataEncryptionRoutes);

// ================== HEALTH CHECK ==================
app.get("/", (req, res) => {
  res.send("🚀 SEO Intrusion Backend Running...");
});

// ================== CRON JOBS ==================
startLogArchiveCron();
startLogCleanupCron();

// ================== DB CONNECTION ==================
connectDB();

// ================== SERVER START ==================
const PORT = process.env.PORT || 4000;

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});