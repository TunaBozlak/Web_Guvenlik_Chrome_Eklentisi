export const analyzeSecurityStatus = (response, site_url) => {
  const statuses = {};

  statuses["HTTPS "] = site_url.startsWith("https://") ? "safe" : "danger";

  const headers = response.securityHeaders || {};
  const header_keys = Object.keys(headers).map((k) => k.toLowerCase());

  statuses["Strict-Transport-Security"] = header_keys.includes(
    "strict-transport-security",
  )
    ? "safe"
    : "warning";
  statuses["Content-Security-Policy"] = header_keys.includes(
    "content-security-policy",
  )
    ? "safe"
    : "warning";
  statuses["X-Frame-Options"] = header_keys.includes("x-frame-options")
    ? "safe"
    : "danger";

  const cookies = response.cookies || [];
  const insecure_cookies = cookies.filter(
    (cookie) => cookie.risks && cookie.risks.length > 0,
  );
  statuses["Çerez Güvenliği"] =
    insecure_cookies.length === 0 ? "safe" : "warning";

  const riskyFunctions = response.riskyFunctions || [];
  statuses["JavaScript Riskleri"] =
    riskyFunctions.length === 0 ? "safe" : "danger";

  const leakedDataCount =
    (response.leakedSecrets?.length || 0) +
    (response.storageVulnerabilities?.length || 0);
  statuses["Hassas Veri Sızıntısı"] = leakedDataCount === 0 ? "safe" : "danger";

  const contentRiskCount =
    (response.formVulnerabilities?.length || 0) +
    (response.mixedContent?.length || 0);
  statuses["İçerik & Form Güvenliği"] =
    contentRiskCount === 0 ? "safe" : "warning";

  statuses["Oltalama (Phishing)"] = response.domainAnalysis?.isSuspicious
    ? "danger"
    : "safe";

  const virus_total = response.malwareScan || {};
  const scans = virus_total.scans || {};
  const detected_count = Object.values(scans).filter(
    (scan) => scan.detected === true,
  );
  statuses["Virustotal "] =
    detected_count.length === 0
      ? "safe"
      : detected_count.length <= 5
        ? "warning"
        : "danger";

  return statuses;
};

export const calculateSecurityScore = (statuses) => {
  const points = {
    "HTTPS ": 10,
    "Strict-Transport-Security": 5,
    "Content-Security-Policy": 10,
    "X-Frame-Options": 10,
    "Çerez Güvenliği": 10,
    "JavaScript Riskleri": 10,
    "Hassas Veri Sızıntısı": 20,
    "İçerik & Form Güvenliği": 10,
    "Oltalama (Phishing)": 10,
    "Virustotal ": 5,
  };

  let total_score = 0;
  let max_score = 0;

  for (const key in points) {
    if (statuses[key]) {
      const point = points[key];
      max_score += point;
      const status = statuses[key];

      if (status === "safe") total_score += point;
      else if (status === "warning") total_score += point / 2;
    }
  }
  return max_score === 0 ? 0 : Math.round((total_score / max_score) * 100);
};
