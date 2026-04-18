export const analyzeThreat = (log) => {
  let score = 0;
  let reason = [];

  const url = (log.url || "").toLowerCase();
  const method = (log.method || "").toUpperCase();
  const ip = (log.ip || "").toLowerCase();

  if (url.includes("admin")) {
    score += 30;
    reason.push("Admin URL access");
  }

  if (url.includes("login")) {
    score += 20;
    reason.push("Login attempt");
  }

  if (method === "POST") {
    score += 10;
    reason.push("POST request");
  }

  if (ip === "unknown") {
    score += 25;
    reason.push("Unknown IP");
  }

  if (url.length > 50) {
    score += 15;
    reason.push("Suspicious long URL");
  }

  let level = "LOW";
  if (score > 60) level = "HIGH";
  else if (score > 30) level = "MEDIUM";

  return {
    score,
    level,
    reason: reason.join(", "),
  };
};