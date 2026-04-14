export const createCard = (title, status) => {
  const tooltipDescriptions = {
    "HTTPS ": "HTTPS, iletişimi şifreleyerek verilerin güvenliğini sağlar.",
    "Strict-Transport-Security":
      "Tarayıcıya yalnızca HTTPS ile bağlanmasını söyler.",
    "Content-Security-Policy":
      "XSS gibi saldırılara karşı kaynak kısıtlaması yapar.",
    "X-Frame-Options": "Clickjacking saldırılarını engeller.",
    "Virustotal ": "Site kötü amaçlı içerik açısından analiz edilir.",
    "Çerez Güvenliği": "Secure, HttpOnly ve SameSite ayarları kontrol edilir.",
    "JavaScript Riskleri":
      "eval, document.write gibi riskli fonksiyonlar analiz edilir.",
    "Hassas Veri Sızıntısı":
      "Sayfa kaynağında veya yerel hafızada unutulmuş API anahtarları (AWS, JWT vb.) aranır.",
    "İçerik & Form Güvenliği":
      "Güvensiz form gönderimleri ve HTTP üzerinden yüklenen güvensiz (Karma) kaynaklar kontrol edilir.",
    "Oltalama (Phishing)":
      "Domain adının bilinen markaları (Google, Facebook vb.) taklit edip etmediği kontrol edilir.",
    "Performans ": "Sayfa hız ve deneyim skorları.",
    "Erişilebilirlik ": "Engelli kullanıcı uyumluluğu.",
    "En İyi Uygulamalar": "Modern web standartları kontrol edilir.",
    "SEO ": "Arama motoru uyumluluğu.",
  };

  const card = document.createElement("div");
  card.className = `security-card ${status}`;

  const left = document.createElement("div");
  left.className = "card-left";

  const titleSpan = document.createElement("span");
  titleSpan.className = "card-title";
  titleSpan.textContent = title;

  const dot = document.createElement("span");
  dot.className = `status-dot ${status}`;

  left.appendChild(dot);
  left.appendChild(titleSpan);

  const badge = document.createElement("span");
  badge.className = `status-badge ${status}`;
  badge.textContent =
    status === "safe" ? "Güvenli" : status === "warning" ? "Uyarı" : "Riskli";

  card.appendChild(left);
  card.appendChild(badge);

  const tooltipText = tooltipDescriptions[title];
  if (tooltipText) {
    const tooltip = document.createElement("div");
    tooltip.className = "tooltip-modern";
    tooltip.textContent = tooltipText;
    card.appendChild(tooltip);
  }

  return card;
};
