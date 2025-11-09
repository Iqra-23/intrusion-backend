import Log from "../models/Log.js";

export const logEvent = async (level, message, keyword = []) => {
  await Log.create({ level, message, keyword });
};
