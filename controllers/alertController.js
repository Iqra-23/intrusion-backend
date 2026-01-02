import Alert from "../models/Alert.js";

// GET /api/logs/alerts?severity=high&acknowledged=false
export const getAlerts = async (req, res) => {
  try {
    const { severity, acknowledged } = req.query;

    const query = {};
    if (severity) query.severity = severity;

    if (acknowledged === "false") query.acknowledged = false;
    if (acknowledged === "true") query.acknowledged = true;

    const alerts = await Alert.find(query)
      .populate("logId")
      .sort({ createdAt: -1 });

    return res.status(200).json({ alerts });
  } catch (err) {
    console.error("getAlerts error:", err);
    return res.status(500).json({ message: "Failed to fetch alerts" });
  }
};

// DELETE /api/logs/alerts/:id
export const deleteAlert = async (req, res) => {
  try {
    const { id } = req.params;

    const deleted = await Alert.findByIdAndDelete(id);
    if (!deleted) return res.status(404).json({ message: "Alert not found" });

    return res.status(200).json({ message: "Alert deleted" });
  } catch (err) {
    console.error("deleteAlert error:", err);
    return res.status(500).json({ message: "Failed to delete alert" });
  }
};
