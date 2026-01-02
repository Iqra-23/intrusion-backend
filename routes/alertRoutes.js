import express from "express";
import { getAlerts, deleteAlert } from "../controllers/alertController.js";

const router = express.Router();

router.get("/alerts", getAlerts);
router.delete("/alerts/:id", deleteAlert);

export default router;
