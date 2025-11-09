import cron from "node-cron";
import Log from "../models/Log.js";

// Run daily at midnight to archive old logs
export const startLogArchiveCron = () => {
  cron.schedule("0 0 * * *", async () => {
    try {
      console.log("🕐 Running automatic log archive...");
      const result = await Log.archiveOldLogs();
      console.log(`✅ Archived ${result.modifiedCount} logs older than 30 days`);
    } catch (error) {
      console.error("❌ Log archive cron error:", error);
    }
  });

  console.log("✅ Log archive cron job scheduled (daily at midnight)");
};

// Run weekly to delete old archived logs
export const startLogCleanupCron = () => {
  cron.schedule("0 2 * * 0", async () => {
    try {
      console.log("🗑️  Running automatic log cleanup...");
      const result = await Log.deleteOldArchivedLogs();
      console.log(`✅ Deleted ${result.deletedCount} archived logs older than 90 days`);
    } catch (error) {
      console.error("❌ Log cleanup cron error:", error);
    }
  });

  console.log("✅ Log cleanup cron job scheduled (weekly on Sunday at 2 AM)");
};

export default { startLogArchiveCron, startLogCleanupCron };