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

/* ===============================
   🔗 DATABASE
================================ */
connectDB();

/* ===============================
   🌐 CORS — VERY IMPORTANT FIX
================================ */
const allowedOrigins = [
  "http://localhost:5173",
  "https://seo-intrusion-frontend.vercel.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // allow server-to-server & Postman
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Accept",
    ],
    exposedHeaders: ["Content-Disposition"],
    credentials: true,
  })
);

// 🔴 REQUIRED for DELETE / OPTIONS preflight
app.options("*", cors());

/* ===============================
   🧠 MIDDLEWARES
================================ */
app.use(express.json({ limit: "10mb" }));
app.use(morgan("dev"));

/* ===============================
   🚦 TRAFFIC LOGGER (GLOBAL)
================================ */
app.use(trafficLogger);

/* ===============================
   🛣 ROUTES
================================ */
app.use("/api/auth", authRoutes);
app.use("/api/logs", logRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/traffic", trafficRoutes);
app.use("/api/dashboard", dashboardRoutes);

/* ===============================
   ⏱ CRON JOBS
================================ */
startLogArchiveCron();
startLogCleanupCron();

/* ===============================
   ⚡ SOCKET.IO
================================ */
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    credentials: true,
  },
});

initSocket(io);

io.on("connection", (socket) => {
  console.log("⚡ Socket connected:", socket.id);
});

/* ===============================
   🚀 START SERVER
================================ */
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

/* ===============================
   🧪 HEALTH CHECK
================================ */
app.get("/", (req, res) => {
  res.send("<h1>SEO Intrusion Backend is running 🚀</h1>");
});
