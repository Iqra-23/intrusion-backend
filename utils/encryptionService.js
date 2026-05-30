import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";

const getEncryptionKey = () => {
  const key = process.env.ENCRYPTION_KEY;

  if (!key || key.length !== 64) {
    throw new Error("Invalid ENCRYPTION_KEY. It must be exactly 64 hex characters.");
  }

  return Buffer.from(key, "hex");
};

export const encryptText = (text) => {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(String(text), "utf8"),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return {
    encryptedData: encrypted.toString("hex"),
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
  };
};

export const decryptText = ({ encryptedData, iv, authTag }) => {
  const key = getEncryptionKey();

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, "hex")
  );

  decipher.setAuthTag(Buffer.from(authTag, "hex"));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedData, "hex")),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
};