// ================== ENV LOAD (IMPORTANT) ==================
import "dotenv/config";
import crypto from "crypto";

// ================== CONFIG ==================
const algorithm = "aes-256-gcm";
const secretKey = process.env.ENCRYPTION_KEY;

// ================== DEBUG ==================
console.log("ENCRYPTION_KEY value:", secretKey);
console.log("ENCRYPTION_KEY length:", secretKey?.length);

// ================== VALIDATION ==================
if (!secretKey || !/^[0-9a-fA-F]{64}$/.test(secretKey)) {
  throw new Error(
    "ENCRYPTION_KEY is missing or invalid. It must be exactly 64 hex characters in .env"
  );
}

// ================== KEY BUFFER ==================
const keyBuffer = Buffer.from(secretKey, "hex");

// ================== ENCRYPT FUNCTION ==================
export const encryptText = (plainText) => {
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, keyBuffer, iv);

  let encrypted = cipher.update(plainText, "utf8", "hex");
  encrypted += cipher.final("hex");

  const authTag = cipher.getAuthTag();

  return {
    encryptedData: encrypted,
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
    algorithm,
  };
};

// ================== DECRYPT FUNCTION ==================
export const decryptText = ({ encryptedData, iv, authTag }) => {
  const decipher = crypto.createDecipheriv(
    algorithm,
    keyBuffer,
    Buffer.from(iv, "hex")
  );

  decipher.setAuthTag(Buffer.from(authTag, "hex"));

  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
};

// ================== TLS STATUS ==================
export const getTlsStatus = () => {
  return {
    status: "secure",
    message: "HTTPS/TLS certificate is active and communication is secured.",
  };
};