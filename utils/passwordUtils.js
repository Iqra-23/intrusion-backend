import bcrypt from "bcrypt";

/**
 * Check password strength
 * @param {string} password
 * @returns {Object} { valid, score, message }
 */
export const checkPasswordStrength = (password) => {
  let score = 0;
  let message = [];

  if (password.length >= 8) score += 1; else message.push("Password too short");
  if (/[A-Z]/.test(password)) score += 1; else message.push("No uppercase letter");
  if (/[0-9]/.test(password)) score += 1; else message.push("No number");
  if (/[^A-Za-z0-9]/.test(password)) score += 1; else message.push("No special character");

  return {
    valid: score >= 3,
    score,
    message: message.length ? message.join(", ") : "Strong password"
  };
};

/**
 * Hash password using bcrypt
 */
export const hashPassword = async (plainText) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(plainText, salt);
};

/**
 * Compare plain text and hashed password
 */
export const comparePassword = async (plainText, hashed) => {
  return bcrypt.compare(plainText, hashed);
};
