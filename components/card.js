export const createCard = (title, status) => {
  const tooltipDescriptions = {
    "HTTPS ":
      "HTTPS, iletişimi şifreleyerek verilerin güvenliğini sağlar. HTTP yerine kullanılmalıdır.",
    "Strict-Transport-Security":
      "Tarayıcıya bu siteye yalnızca HTTPS ile bağlanması gerektiğini bildirir.",
    "Content-Security-Policy":
      "CSP, hangi kaynaklardan içerik yüklenebileceğini belirleyerek XSS gibi saldırıları engeller.",
    "X-Frame-Options":
      "Sayfanızın başka sitelerde iframe olarak yüklenmesini engelleyerek clickjacking'e karşı koruma sağlar.",
    "Virustotal ":
      "Site, VirusTotal veritabanında kötü amaçlı içerik barındırıp barındırmadığı açısından analiz edilir.",
    "Çerez Güvenliği":
      "Çerezlerin Secure, HttpOnly ve SameSite gibi özelliklerle korunduğunu kontrol eder.",
    "JavaScript Riskleri":
      "Sayfada tehlikeli veya şüpheli JavaScript işlevleri (örneğin eval()) kullanılıp kullanılmadığını analiz eder.",
  };

  const card = document.createElement("div");
  card.classList.add("security-card", "tooltip");

  const icon = document.createElement("span");
  icon.style.fontSize = "18px";

  let color, iconSymbol;
  if (status === "safe") {
    color = "green";
    iconSymbol = "🎉";
  } else if (status === "warning") {
    color = "orange";
    iconSymbol = "⚠️";
  } else {
    color = "red";
    iconSymbol = "💣";
  }

  card.style.borderColor = color;
  card.style.color = color;

  const titleSpan = document.createElement("span");
  titleSpan.textContent = title;

  const tooltipText = tooltipDescriptions[title];
  if (tooltipText) {
    const tooltipSpan = document.createElement("span");
    tooltipSpan.className = "tooltiptext";
    tooltipSpan.textContent = tooltipText;
    card.appendChild(tooltipSpan);
  }

  card.appendChild(titleSpan);
  card.appendChild(icon);
  return card;
};
