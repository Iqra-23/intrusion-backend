import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import { connectDB } from "./config/db.js";

import authRoutes from "./routes/authRoutes.js";
import logRoutes from "./routes/logRoutes.js";
import vulnerabilityRoutes from "./routes/vulnerabilityRoutes.js";
import trafficRoutes from "./routes/trafficRoutes.js";

import { startLogArchiveCron, startLogCleanupCron } from "./utils/cronJobs.js";
import { trafficLogger } from "./controllers/trafficController.js";

import { Server } from "socket.io";
import http from "http";
import { initSocket } from "./utils/socket.js";

import dashboardRoutes from "./routes/dashboardRoutes.js";

dotenv.config();
const app = express();

// Connect to DB
connectDB();

// Middlewares
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://seo-intrusion-frontend.vercel.app"
    ],
    methods: ["GET", "POST", "PATCH", "DELETE"],
    credentials: true,
  })
);


app.use(express.json());
app.use(morgan("dev"));

// Traffic logger
app.use(trafficLogger);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/logs", logRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/traffic", trafficRoutes);
app.use("/api/dashboard", dashboardRoutes);

// Cron jobs
startLogArchiveCron();
startLogCleanupCron();

// Server + socket.io
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: [
      "https://seo-intrusion-frontend.vercel.app",
      "http://localhost:5173"
    ],
    methods: ["GET", "POST", "PATCH", "DELETE"],
    credentials: true
  }
});


// Register global socket instance
initSocket(io);

io.on("connection", () => {
  console.log("⚡ Socket Connected");
});

// Start server
server.listen(process.env.PORT, () => {
  console.log(`🚀 Server running with Socket.io at port ${process.env.PORT}`);
});
app.get('/', (req, res) => {
  res.send('<h1>Server is running successfully 🚀</h1>');
});