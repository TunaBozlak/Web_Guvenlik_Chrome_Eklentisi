export const analyzeSecurityStatus = (response, site_url) => {
  const statuses = {};

  statuses["HTTPS Bağlantısı"] = site_url.startsWith("https://")
    ? "safe"
    : "danger";

  const headers = response.securityHeaders || {};
  const header_keys = Object.keys(headers).map((k) => k.toLowerCase());

  let missingHeaders = 0;
  if (!header_keys.includes("strict-transport-security")) missingHeaders++;
  if (!header_keys.includes("content-security-policy")) missingHeaders++;
  if (!header_keys.includes("x-frame-options")) missingHeaders++;

  if (missingHeaders === 0) statuses["Güvenlik Başlıkları"] = "safe";
  else if (missingHeaders < 3) statuses["Güvenlik Başlıkları"] = "warning";
  else statuses["Güvenlik Başlıkları"] = "danger";

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
    (response.storageVulnerabilities?.length || 0) +
    (response.devComments?.length || 0);
  statuses["Hassas Veri Sızıntısı"] = leakedDataCount === 0 ? "safe" : "danger";

  const contentRiskCount =
    (response.formVulnerabilities?.length || 0) +
    (response.mixedContent?.length || 0);
  statuses["İçerik & Form Güvenliği"] =
    contentRiskCount === 0 ? "safe" : "warning";

  const corsCount = response.corsVulnerabilities?.length || 0;
  statuses["CORS ve Sunucu"] = corsCount === 0 ? "safe" : "warning";

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
    "HTTPS Bağlantısı": 10,
    "Güvenlik Başlıkları": 15,
    "Çerez Güvenliği": 10,
    "JavaScript Riskleri": 10,
    "Hassas Veri Sızıntısı": 20,
    "İçerik & Form Güvenliği": 10,
    "CORS ve Sunucu": 10,
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
