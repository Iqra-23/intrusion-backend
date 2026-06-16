// routes/profileRoutes.js
import express from "express";
import { getAdminProfile, updateAdminProfile } from "../controllers/profileController.js";
import { protect } from "../middleware/authMiddleware.js";

const router = express.Router();

router.get("/",       protect, getAdminProfile);
router.put("/update", protect, updateAdminProfile);

export default router;