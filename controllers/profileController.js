// controllers/profileController.js
import User from "../models/User.js";
import Log from "../models/Log.js";
import Threat from "../models/Threat.js";
import AnomalyRecord from "../models/AnomalyRecord.js";
import IncidentResponse from "../models/IncidentResponse.js";

export const getAdminProfile = async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id;
    const user   = await User.findById(userId).select("-password -googleId");

    if (!user) return res.status(404).json({ message: "User not found" });

    // Gather activity stats for this admin
    const [totalLogs, suspiciousLogs, totalThreats, totalAnomalies, totalIncidents] = await Promise.all([
      Log.countDocuments(),
      Log.countDocuments({ level: "suspicious" }),
      Threat.countDocuments(),
      AnomalyRecord.countDocuments(),
      IncidentResponse.countDocuments(),
    ]);

    // Recent logs (last 5)
    const recentActivity = await Log.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select("level message createdAt");

    res.json({
      success: true,
      user: {
        name:           user.name,
        email:          user.email,
        emailVerified:  user.emailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        lastLogin:      user.lastLogin,
        createdAt:      user.createdAt,
        loginAttempts:  user.loginAttempts || 0,
      },
      stats: {
        totalLogs,
        suspiciousLogs,
        totalThreats,
        totalAnomalies,
        totalIncidents,
      },
      recentActivity,
    });
  } catch (err) {
    console.error("getAdminProfile error:", err.message);
    res.status(500).json({ message: "Failed to fetch profile" });
  }
};

export const updateAdminProfile = async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id;
    const { name } = req.body;

    if (!name || name.trim().length < 2) {
      return res.status(400).json({ message: "Name must be at least 2 characters" });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { name: name.trim() },
      { new: true }
    ).select("-password");

    res.json({ success: true, user });
  } catch (err) {
    console.error("updateAdminProfile error:", err.message);
    res.status(500).json({ message: "Failed to update profile" });
  }
};