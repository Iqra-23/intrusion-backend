import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import { connectDB } from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";
import logRoutes from "./routes/logRoutes.js";
import vulnerabilityRoutes from "./routes/vulnerabilityRoutes.js";
import { startLogArchiveCron, startLogCleanupCron } from "./utils/cronJobs.js";

dotenv.config();
const app = express();

// Connect to Database
connectDB();

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/logs", logRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);

// Start Cron Jobs for automatic log management
startLogArchiveCron();   // Runs daily at midnight
startLogCleanupCron();   // Runs weekly on Sunday at 2 AM

// Start Server
app.listen(process.env.PORT, () =>
  console.log(`🚀 Server running on port ${process.env.PORT}`)
);
// 