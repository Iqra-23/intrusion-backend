import axios from "axios";

export const lookupGeo = async (ip) => {
  try {
    if (!ip) return null;

    // For localhost, force an example country so UI works
    if (ip === "::1" || ip === "127.0.0.1") {
      return {
        country: "Local",
        city: "Localhost",
        region: "N/A",
        isp: "N/A",
        lat: 0,
        lon: 0,
      };
    }

    const res = await axios.get(`http://ip-api.com/json/${ip}`);

    if (res.data?.status === "success") {
      return {
        country: res.data.country,
        city: res.data.city,
        region: res.data.regionName,
        isp: res.data.isp,
        lat: res.data.lat,
        lon: res.data.lon,
      };
    }

    return null;
  } catch {
    return null;
  }
};
