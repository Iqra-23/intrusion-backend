import * as tf from "@tensorflow/tfjs";

const labels = [
  "normal",
  "sql-injection",
  "xss",
  "path-traversal",
  "keyword-spam",
  "suspicious-ip",
  "rate-limit",
];

const trainingData = [
  // normal
  { text: "home dashboard profile normal request get page", label: "normal" },
  { text: "user opens dashboard traffic stats normal", label: "normal" },
  { text: "get logs list normal activity", label: "normal" },

  // sql injection
  { text: "or 1 equals 1 union select password from users", label: "sql-injection" },
  { text: "admin login union select database table", label: "sql-injection" },
  { text: "drop table users select from admin where password", label: "sql-injection" },

  // xss
  { text: "script alert javascript onerror payload", label: "xss" },
  { text: "img src onerror alert script attack", label: "xss" },
  { text: "iframe javascript cookie steal script", label: "xss" },

  // path traversal
  { text: "../ etc passwd config env file access", label: "path-traversal" },
  { text: "../../ admin private config file", label: "path-traversal" },
  { text: "dot dot slash server file access", label: "path-traversal" },

  // keyword spam
  { text: "free free free buy cheap discount offer winner", label: "keyword-spam" },
  { text: "click bonus sale limited cheap offer buy now", label: "keyword-spam" },
  { text: "spam keyword repeated discount free winner", label: "keyword-spam" },

  // suspicious-ip
  { text: "unknown ip repeated failed login attempt", label: "suspicious-ip" },
  { text: "same ip many failed login suspicious behavior", label: "suspicious-ip" },
  { text: "untrusted source repeated attack attempts", label: "suspicious-ip" },

  // rate limit
  { text: "too many requests high request frequency repeated calls", label: "rate-limit" },
  { text: "request flood rate limit exceeded burst traffic", label: "rate-limit" },
  { text: "rapid repeated requests from same ip", label: "rate-limit" },
];

const vocabulary = [
  ...new Set(
    trainingData
      .map((item) => item.text.toLowerCase().split(/\s+/))
      .flat()
  ),
];

let model = null;

const vectorize = (text) => {
  const words = String(text || "").toLowerCase().split(/\s+/);
  return vocabulary.map((word) => (words.includes(word) ? 1 : 0));
};

const labelIndex = (label) => labels.indexOf(label);

export const trainThreatModel = async () => {
  if (model) return model;

  const xs = tf.tensor2d(trainingData.map((item) => vectorize(item.text)));

  const ys = tf.oneHot(
    tf.tensor1d(trainingData.map((item) => labelIndex(item.label)), "int32"),
    labels.length
  );

  model = tf.sequential();

  model.add(
    tf.layers.dense({
      inputShape: [vocabulary.length],
      units: 24,
      activation: "relu",
    })
  );

  model.add(
    tf.layers.dense({
      units: 16,
      activation: "relu",
    })
  );

  model.add(
    tf.layers.dense({
      units: labels.length,
      activation: "softmax",
    })
  );

  model.compile({
    optimizer: "adam",
    loss: "categoricalCrossentropy",
    metrics: ["accuracy"],
  });

  await model.fit(xs, ys, {
    epochs: 100,
    verbose: 0,
  });

  console.log("✅ AI Threat Detection model trained");
  return model;
};

export const predictThreatByAI = async ({ url, method, payload, requestCount, failedAttempts }) => {
  await trainThreatModel();

  const aiInput = `
    ${method || ""}
    ${url || ""}
    ${payload || ""}
    request count ${requestCount || 0}
    failed attempts ${failedAttempts || 0}
  `;

  const input = tf.tensor2d([vectorize(aiInput)]);
  const prediction = model.predict(input);
  const values = await prediction.data();

  const confidence = Math.max(...values);
  const predictedIndex = values.indexOf(confidence);
  const attackType = labels[predictedIndex];

  const confidencePercent = Number((confidence * 100).toFixed(2));

  let threatLevel = "LOW";
  let action = "allow";

  if (attackType !== "normal" && confidencePercent >= 75) {
    threatLevel = "HIGH";
    action = "block";
  } else if (attackType !== "normal" && confidencePercent >= 50) {
    threatLevel = "MEDIUM";
    action = "monitor";
  }

  return {
    attackType,
    confidence: confidencePercent,
    threatScore: attackType === "normal" ? 0 : confidencePercent,
    threatLevel,
    action,
    reason:
      attackType === "normal"
        ? "AI classified this request as normal traffic"
        : `AI classified this request as ${attackType} with ${confidencePercent}% confidence`,
  };
};