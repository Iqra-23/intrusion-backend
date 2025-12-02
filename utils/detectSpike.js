let requestStore = {};

export const SPIKE_THRESHOLD = 10;   
export const SPIKE_WINDOW_MS = 8000; 

export default function detectSpike(ip) {
  const now = Date.now();

  if (!requestStore[ip]) {
    requestStore[ip] = [];
  }

  requestStore[ip] = requestStore[ip].filter(
    (t) => now - t < SPIKE_WINDOW_MS
  );

  requestStore[ip].push(now);

  if (requestStore[ip].length >= SPIKE_THRESHOLD) {
    return true;
  }

  return false;
}
