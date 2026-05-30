const seoSpamWords = [
  "cheap seo",
  "buy backlinks",
  "free traffic",
  "rank fast",
  "click here",
  "buy now",
  "backlinks",
  "free visitors",
];

export const calculateDeviation = (current, baseline) => {
  if (!baseline || baseline <= 0) return 0;
  return Number((((current - baseline) / baseline) * 100).toFixed(2));
};

export const calculateSeverity = (score) => {
  if (score >= 90) return "CRITICAL";
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
};

export const detectSeoKeywordHits = (text = "") => {
  const lowerText = text.toLowerCase();

  let hits = 0;

  seoSpamWords.forEach((word) => {
    if (lowerText.includes(word)) {
      hits += 1;
    }
  });

  return hits;
};

export const calculateAnomalyScore = ({
  currentValue,
  baselineValue,
  deviation,
  extraRisk = 0,
}) => {
  let score = 0;

  if (currentValue > baselineValue) score += 30;
  if (deviation >= 50) score += 20;
  if (deviation >= 100) score += 25;
  if (deviation >= 200) score += 15;

  score += extraRisk;

  return Math.min(score, 100);
};

export const buildAnomalyReason = ({
  type,
  currentValue,
  baselineValue,
  deviation,
}) => {
  if (type === "unusual-login") {
    return `Login attempts are higher than baseline. Current attempts: ${currentValue}, baseline: ${baselineValue}, deviation: ${deviation}%.`;
  }

  if (type === "abnormal-request-frequency") {
    return `Request frequency is higher than normal traffic baseline. Current requests: ${currentValue}, baseline: ${baselineValue}, deviation: ${deviation}%.`;
  }

  if (type === "negative-seo-traffic") {
    return `Negative SEO keyword pattern detected. Keyword hits: ${currentValue}, baseline: ${baselineValue}, deviation: ${deviation}%.`;
  }

  return "Traffic behavior is within normal baseline.";
};