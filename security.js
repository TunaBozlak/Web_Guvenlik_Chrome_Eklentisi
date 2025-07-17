export const analyzeSecurityStatus = (response, site_url) => {
  const statuses = {};

  statuses["HTTPS "] = site_url.startsWith("https://") ? "safe" : "danger";

  const headers = response.securityHeaders || {};
  const header_keys = Object.keys(headers).map((k) => k.toLowerCase());
  statuses["Strict-Transport-Security"] = header_keys.includes(
    "strict-transport-security"
  )
    ? "safe"
    : "warning";

  statuses["Content-Security-Policy"] = header_keys.includes(
    "content-security-policy"
  )
    ? "safe"
    : "warning";

  statuses["X-Frame-Options"] = header_keys.includes("x-frame-options")
    ? "safe"
    : "danger";

  const virus_total = response.malwareScan || {};
  const scans = virus_total.scans || {};
  const detected_count = Object.values(scans).filter(
    (scan) => scan.detected === true
  );
  statuses["Virustotal "] =
    detected_count.length === 0
      ? "safe"
      : detected_count.length <= 5
      ? "warning"
      : "danger";

  const cookies = response.cookies || [];
  const insecure_cookies = cookies.filter(
    (cookie) => !cookie.secure || !cookie.httpOnly
  );
  statuses["Çerez Güvenliği"] =
    insecure_cookies.length === 0 ? "safe" : "warning";

  const riskyFunctions = response.riskyFunctions || [];
  statuses["JavaScript Riskleri"] =
    riskyFunctions.length === 0 ? "safe" : "danger";

  return statuses;
};

export const calculateSecurityScore = (statues) => {
  const points = {
    "HTTPS ": 15,
    "Strict-Transport-Security": 10,
    "Content-Security-Policy": 10,
    "X-Frame-Options": 10,
    "Çerez Güvenliği": 10,
    "JavaScript Riskleri": 15,
    "Virustotal ": 30,
  };
  let total_score = 0;
  let max_score = 0;

  for (const key in points) {
    const point = points[key];
    max_score += point;

    const status = statues[key] || "danger";

    if (status === "safe") {
      total_score += point;
    } else if (status === "warning") {
      total_score += point / 2;
    }
  }
  return Math.round((total_score / max_score) * 100);
};
