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

/* ================= DB ================= */
connectDB();

/* ================= CORS ================= */
const allowedOrigins = [
  "http://localhost:5173",
  "https://seo-intrusion-frontend.vercel.app",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["Content-Disposition"],
  })
);

// 🔴 VERY IMPORTANT
app.options("*", cors());

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(morgan("dev"));

/* ================= TRAFFIC LOGGER ================= */
app.use(trafficLogger);

/* ================= ROUTES ================= */
app.use("/api/auth", authRoutes);
app.use("/api/logs", logRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/traffic", trafficRoutes);
app.use("/api/dashboard", dashboardRoutes);

/* ================= CRON ================= */
startLogArchiveCron();
startLogCleanupCron();

/* ================= SOCKET ================= */
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    credentials: true,
  },
});

initSocket(io);

io.on("connection", (socket) => {
  console.log("⚡ Socket connected:", socket.id);
});

/* ================= START ================= */
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Backend running on ${PORT}`);
});

app.get("/", (req, res) => {
  res.send("Backend running 🚀");
});
