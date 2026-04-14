export const createCard = (title, status) => {
  const tooltipDescriptions = {
    "HTTPS Bağlantısı":
      "HTTPS, iletişimi şifreleyerek verilerin güvenliğini sağlar.",
    "Güvenlik Başlıkları":
      "HSTS, CSP ve X-Frame-Options gibi kritik HTTP güvenlik başlıklarının yapılandırmasını gösterir.",
    "Çerez Güvenliği": "Secure, HttpOnly ve SameSite ayarları kontrol edilir.",
    "JavaScript Riskleri":
      "eval, document.write gibi DOM tabanlı riskli fonksiyonlar analiz edilir.",
    "Hassas Veri Sızıntısı":
      "Sayfa kaynağında, yerel hafızada veya HTML yorumlarında unutulmuş API anahtarları aranır.",
    "İçerik & Form Güvenliği":
      "Güvensiz form gönderimleri ve HTTP üzerinden yüklenen güvensiz (Karma) kaynaklar kontrol edilir.",
    "CORS ve Sunucu":
      "CORS politikası zafiyetleri ve sunucu başlığı (X-Powered-By) sızıntılarını denetler.",
    "Oltalama (Phishing)":
      "Domain adının bilinen markaları (Google, Facebook vb.) taklit edip etmediği kontrol edilir.",
    "Performans ": "Sayfa hız ve deneyim skorları.",
    "Erişilebilirlik ": "Engelli kullanıcı uyumluluğu.",
    "En İyi Uygulamalar": "Modern web standartları kontrol edilir.",
    "SEO ": "Arama motoru uyumluluğu.",
    "Virustotal ": "Site kötü amaçlı içerik açısından analiz edilir.",
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
