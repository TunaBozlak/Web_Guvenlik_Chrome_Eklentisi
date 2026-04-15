import {
  analyzeSecurityStatus,
  calculateSecurityScore,
} from "./components/security.js";
import { createCard } from "./components/card.js";
import { filterComponent } from "./components/filter.js";
import { deleteHistory } from "./components/delete.js";
import { saveAnalysisHistory } from "./components/history.js";
import { changeTheme } from "./components/theme.js";
import { setupDownloadDropdown } from "./components/download.js";

const frameworks = {
  React: "./images/framework/react.png",
  Angular: "./images/framework/angular.png",
  "Vue.js": "./images/framework/vue.png",
  "Next.js": "./images/framework/next.png",
  jQuery: "./images/framework/jquery.png",
  Svelte: "./images/framework/svelte.png",
  "Nuxt.js": "./images/framework/nuxt.png",
  WordPress: "./images/framework/wordpress.png",
  Preact: "./images/framework/preact.png",
  "Alpine.js": "./images/framework/alpine.png",
  "Ember.js": "./images/framework/ember.png",
  Qwik: "./images/framework/qwik.png",
  Astro: "./images/framework/astro.png",
  Inferno: "./images/framework/inferno.png",
};

const ui_frameworks = {
  "Tailwind CSS": "./images/ui_framework/tailwind.png",
  Bootstrap: "./images/ui_framework/bootstrap.png",
  "Material UI (MUI)": "./images/ui_framework/materialui.png",
  Bulma: "./images/ui_framework/bulma.png",
  Foundation: "./images/ui_framework/foundation.png",
  "Ant Design": "./images/ui_framework/antdesing.png",
  "Chakra UI": "./images/ui_framework/chakraui.png",
  PrimeFlex: "./images/ui_framework/primeflex.png",
  "Carbon Design": "./images/ui_framework/carbondesign.png",
};

document.addEventListener("DOMContentLoaded", () => {
  const analysis_button = document.getElementById("analysis_button");
  const download_button = document.getElementById("download_pdf");
  const ai_button = document.getElementById("ai_button");
  const performance_button = document.getElementById("performance_button");
  const loading = document.getElementById("loading");
  const loading_explanation = document.getElementById("loading-explanation");
  const results_content = document.getElementById("results-content");
  const explanation_content = document.getElementById("explanation-content");

  const copy_button = document.createElement("button");
  copy_button.textContent = "Kopyala";
  copy_button.classList.add("copy-button");

  const copyResults = (data) => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    copy_button.textContent = "Kopyalandı!";
    setTimeout(() => (copy_button.textContent = "Kopyala"), 1500);
  };

  const performSecurityAnalysis = async () => {
    const startTime = Date.now();
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    results_content.innerHTML = "";
    explanation_content.innerText = "";

    const dlBtn = document.getElementById("download_pdf");
    if (dlBtn) dlBtn.disabled = true;

    ai_button.disabled = true;
    loading.style.display = "block";

    const site_url = (
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: () => window.location.href,
      })
    )[0].result;

    const response = await chrome.runtime.sendMessage({
      action: "analyze",
      url: site_url,
    });
    const apiResponse = await chrome.runtime.sendMessage({
      action: "analyzeApiEndpoints",
    });
    response.endpoints = apiResponse?.endpoints || [];

    loading.style.display = "none";
    const durationInSeconds = ((Date.now() - startTime) / 1000).toFixed(2);

    const headerContainer = document.createElement("div");
    headerContainer.style.marginBottom = "15px";
    headerContainer.innerHTML = `<div style="font-size: 0.9em; color: #888;">⏳ Analiz Süresi: ${durationInSeconds} saniye</div>`;
    results_content.appendChild(headerContainer);

    if (!response || response.error) {
      results_content.innerHTML = `<p style="color:red;">Analiz başarısız: ${response?.details || "Bilinmeyen Hata"}</p>`;
      return;
    }

    const createAlertBox = (title, items, bgColor, textColor, icon) => {
      if (!items || items.length === 0) return null;

      const box = document.createElement("div");
      box.style.background = bgColor;
      box.style.color = textColor;
      box.style.padding = "12px";
      box.style.borderRadius = "8px";
      box.style.marginBottom = "12px";
      box.style.border = `1px solid ${textColor}50`;

      let listHtml = items
        .map(
          (i) =>
            `<li style="margin-bottom:6px; padding-bottom:4px; border-bottom:1px dashed ${textColor}40;">${i}</li>`,
        )
        .join("");

      box.innerHTML = `
        <strong style="display:flex; align-items:center; gap:8px; margin-bottom: 10px; font-size:1.05em;">
           ${icon} ${title} 
           <span style="background:${textColor}; color:${bgColor}; padding:2px 8px; border-radius:12px; font-size:0.75em;">${items.length}</span>
        </strong>
        <ul style="margin: 0; padding-left: 20px; font-size:0.85em; max-height: 110px; overflow-y: auto; scrollbar-width: thin; scrollbar-color: ${textColor} transparent;">
           ${listHtml}
        </ul>`;
      return box;
    };

    if (response.domainAnalysis && response.domainAnalysis.isSuspicious) {
      const phishingBox = createAlertBox(
        "Kritik Uyarı: Şüpheli Alan Adı!",
        [
          response.domainAnalysis.warning,
          `Tespit: ${response.domainAnalysis.hostname}`,
        ],
        "#ffebee",
        "#d32f2f",
        "🚨",
      );
      if (phishingBox) results_content.appendChild(phishingBox);
    }

    const secretsBox = createAlertBox(
      "Hassas Veri Sızıntısı Tespit Edildi!",
      response.leakedSecrets,
      "#fff3e0",
      "#e65100",
      "🔑",
    );
    if (secretsBox) results_content.appendChild(secretsBox);

    const storageBox = createAlertBox(
      "Yerel Hafıza (Storage) Zafiyetleri",
      response.storageVulnerabilities,
      "#fce4ec",
      "#c2185b",
      "💾",
    );
    if (storageBox) results_content.appendChild(storageBox);

    const formBox = createAlertBox(
      "Güvensiz Form / Parola Yapılandırması",
      response.formVulnerabilities,
      "#fffde7",
      "#f57f17",
      "📝",
    );
    if (formBox) results_content.appendChild(formBox);

    const cspBox = createAlertBox(
      "CSP (İçerik Güvenlik Politikası) Riskleri",
      response.cspVulnerabilities,
      "#e8eaf6",
      "#3f51b5",
      "🚧",
    );
    if (cspBox) results_content.appendChild(cspBox);

    const mixedContentBox = createAlertBox(
      "Güvenlik Açığı: Karma İçerik (Mixed Content)",
      response.mixedContent,
      "#fff8e1",
      "#f57f17",
      "⚠️",
    );
    if (mixedContentBox) results_content.appendChild(mixedContentBox);

    const riskyFuncsBox = createAlertBox(
      "Tehlikeli JS Fonksiyonları Tespit Edildi",
      response.riskyFunctions,
      "#f3e5f5",
      "#7b1fa2",
      "⚡",
    );
    if (riskyFuncsBox) results_content.appendChild(riskyFuncsBox);

    if (response.cookies && response.cookies.length > 0) {
      const riskyCookies = response.cookies.filter(
        (c) => c.risks && c.risks.length > 0,
      );
      if (riskyCookies.length > 0) {
        const cookieBox = createAlertBox(
          "Riskli Çerez Yapılandırmaları",
          riskyCookies.map(
            (c) =>
              `<strong>${c.name || "Bilinmeyen Çerez"}</strong>: ${c.risks.join(", ")}`,
          ),
          "#e8f4fd",
          "#0277bd",
          "🍪",
        );
        if (cookieBox) results_content.appendChild(cookieBox);
      }

      const corsBox = createAlertBox(
        "CORS & Sunucu Başlığı Zafiyetleri",
        response.corsVulnerabilities,
        "#fff8e1",
        "#f57f17",
        "🌐",
      );
      if (corsBox) results_content.appendChild(corsBox);
    }

    const statuses = analyzeSecurityStatus(response, site_url);
    const score = calculateSecurityScore(statuses);

    const score_div = document.createElement("div");
    score_div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
        <div style="font-size: 1.1em;"><strong>Skor:</strong> ${score} / 100</div>
        <div style="background: ${response.detectedWAF !== "Tespit Edilemedi / Korunmasız" ? "#e8f5e9" : "#ffebee"}; color: ${response.detectedWAF !== "Tespit Edilemedi / Korunmasız" ? "#2e7d32" : "#c62828"}; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; border: 1px solid currentColor;">
          🛡️ WAF: <strong>${response.detectedWAF}</strong>
        </div>
      </div>
      <div style="background: #e0e0e0; border-radius: 8px; overflow: hidden; width: 100%; height: 12px; margin-bottom: 15px;">
        <div style="width: ${score}%; height: 100%; background: ${score >= 80 ? "#4caf50" : score >= 50 ? "#ff9800" : "#f44336"}; transition: width 0.5s ease-in-out;"></div>
      </div>
    `;
    headerContainer.appendChild(score_div);

    const cardsContainer = document.createElement("div");
    cardsContainer.className = "status-cards-grid";

    Object.entries(statuses).forEach(([title, status]) => {
      const card = createCard(title, status);
      cardsContainer.appendChild(card);
    });

    results_content.appendChild(cardsContainer);

    const createReconAccordion = (title, items, icon) => {
      if (!items || items.length === 0) return null;

      const container = document.createElement("div");
      container.style.border = "1px solid var(--border-color)";
      container.style.borderRadius = "8px";
      container.style.marginBottom = "10px";
      container.style.background = "var(--card-bg)";
      container.style.overflow = "hidden";

      const header = document.createElement("div");
      header.style.padding = "10px 15px";
      header.style.cursor = "pointer";
      header.style.display = "flex";
      header.style.justifyContent = "space-between";
      header.style.alignItems = "center";
      header.style.background = "rgba(0,0,0,0.02)";
      header.style.fontWeight = "600";
      header.style.fontSize = "13px";

      const titleWrap = document.createElement("div");
      titleWrap.style.display = "flex";
      titleWrap.style.alignItems = "center";
      titleWrap.style.gap = "8px";
      titleWrap.innerHTML = `<span>${icon}</span> <span>${title} <span style="background:var(--primary);color:white;padding:2px 6px;border-radius:10px;font-size:10px;margin-left:4px;">${items.length}</span></span>`;

      const arrow = document.createElement("span");
      arrow.innerHTML = "&#9660;";
      arrow.style.fontSize = "10px";
      arrow.style.transition = "transform 0.2s";

      header.appendChild(titleWrap);
      header.appendChild(arrow);

      const content = document.createElement("div");
      content.style.padding = "10px 15px";
      content.style.display = "none";
      content.style.borderTop = "1px solid var(--border-color)";
      content.style.fontSize = "12px";
      content.style.maxHeight = "150px";
      content.style.overflowY = "auto";
      content.style.fontFamily = "monospace";
      content.style.background = "var(--bg-color)";

      let listHtml = items
        .map(
          (item) =>
            `<div style="margin-bottom:4px; padding-bottom:4px; border-bottom:1px dashed var(--border-color); word-break: break-all;">${item}</div>`,
        )
        .join("");
      content.innerHTML = listHtml;

      header.addEventListener("click", () => {
        const isHidden = content.style.display === "none";
        content.style.display = isHidden ? "block" : "none";
        arrow.style.transform = isHidden ? "rotate(180deg)" : "rotate(0deg)";
      });

      container.appendChild(header);
      container.appendChild(content);

      return container;
    };

    if (
      (response.hiddenInputs && response.hiddenInputs.length > 0) ||
      (response.suspiciousLinks && response.suspiciousLinks.length > 0) ||
      (response.devComments && response.devComments.length > 0) ||
      (response.hiddenFiles && response.hiddenFiles.length > 0)
    ) {
      const reconTitle = document.createElement("h3");
      reconTitle.textContent = "Keşif Bilgileri (Recon)";
      reconTitle.style.marginTop = "20px";
      reconTitle.style.marginBottom = "10px";
      reconTitle.style.fontSize = "13px";
      reconTitle.style.borderBottom = "1px solid var(--border-color)";
      results_content.appendChild(reconTitle);

      const hiddenInputsAccordion = createReconAccordion(
        "Gizli Form Alanları (Hidden Inputs)",
        response.hiddenInputs,
        "🕵️",
      );
      if (hiddenInputsAccordion)
        results_content.appendChild(hiddenInputsAccordion);

      const suspiciousLinksAccordion = createReconAccordion(
        "Kritik Linkler (Admin/Portal)",
        response.suspiciousLinks,
        "🔗",
      );
      if (suspiciousLinksAccordion)
        results_content.appendChild(suspiciousLinksAccordion);

      const commentsAccordion = createReconAccordion(
        "Geliştirici Yorumları (HTML Comments)",
        response.devComments,
        "💬",
      );
      if (commentsAccordion) results_content.appendChild(commentsAccordion);

      const filesAccordion = createReconAccordion(
        "Gizli Dosya Taraması (robots.txt vs)",
        response.hiddenFiles,
        "📂",
      );
      if (filesAccordion) results_content.appendChild(filesAccordion);
    }

    const renderFrameworks = (title, items, logoMap) => {
      if (!items || items.length === 0) return;
      const header = document.createElement("h3");
      header.textContent = title;
      header.style.marginTop = "20px";
      header.style.borderBottom = "1px solid #ccc";
      results_content.appendChild(header);

      const ul = document.createElement("ul");
      ul.style.listStyleType = "none";
      ul.style.paddingLeft = "0";
      ul.style.display = "flex";
      ul.style.flexWrap = "wrap";
      ul.style.gap = "10px";

      items.forEach((item) => {
        const name = typeof item === "string" ? item : item.name;

        const versionHTML =
          typeof item === "object" && item.version
            ? `<span style="margin-left:6px; padding:2px 6px; background:rgba(0,0,0,0.08); border-radius:10px; font-size:0.75em; color:var(--text-secondary); font-weight:bold;">v${item.version}</span>`
            : "";

        const li = document.createElement("li");
        li.style.display = "flex";
        li.style.alignItems = "center";
        li.style.background = "var(--badge-bg, #eee)";
        li.style.padding = "5px 10px";
        li.style.borderRadius = "20px";
        li.style.fontSize = "0.9em";

        const logoPath = logoMap[name];
        const logoImg = logoPath
          ? `<img src="${logoPath}" alt="${name}" style="width:16px; height:16px; margin-right:6px;">`
          : "";

        li.innerHTML = `${logoImg}<span style="font-weight: 500;">${name}</span>${versionHTML}`;
        ul.appendChild(li);
      });
      results_content.appendChild(ul);
    };

    renderFrameworks("Teknolojiler", response.detectedFrameworks, frameworks);
    renderFrameworks(
      "UI & CSS Kütüphaneleri",
      response.detectedUIFrameworks,
      ui_frameworks,
    );

    const endpoints = response?.endpoints || [];
    if (endpoints.length > 0) {
      const apiHeader = document.createElement("h3");
      apiHeader.textContent = "API Endpoint Analizi";
      apiHeader.style.marginTop = "20px";
      apiHeader.style.borderBottom = "1px solid #ccc";
      results_content.appendChild(apiHeader);

      const card = document.createElement("div");
      card.classList.add("api-card-v2");
      results_content.appendChild(card);

      endpoints.forEach((entry) => {
        const div = document.createElement("div");
        div.classList.add("api-card");
        div.style.padding = "8px";
        div.style.background = "var(--card-bg, #f9f9f9)";
        div.style.marginBottom = "5px";
        div.style.borderRadius = "4px";
        div.innerHTML = `
          <div><span style="color: ${entry.method === "GET" ? "#007acc" : "#d32f2f"}; font-weight:bold;">${entry.method}</span> 
               <span style="color: ${entry.status >= 400 ? "red" : "green"};">[${entry.status}]</span></div>
          <div style="word-break: break-all; font-size: 0.85em; font-family: monospace;">${entry.url}</div>
        `;
        card.appendChild(div);
      });
    }

    const item = document.createElement("div");
    item.classList.add("item");
    item.style.marginTop = "20px";

    const title = document.createElement("div");
    title.innerHTML =
      "<strong>Ham Analiz Raporu (JSON)</strong> <span style='font-size:10px;'>&#9660;</span>";
    title.style.cursor = "pointer";

    const headerRow = document.createElement("div");
    headerRow.style.display = "flex";
    headerRow.style.justifyContent = "space-between";
    headerRow.style.alignItems = "center";
    headerRow.style.background = "var(--card-bg, #eee)";
    headerRow.style.padding = "8px";
    headerRow.style.borderRadius = "5px";

    headerRow.appendChild(title);
    headerRow.appendChild(copy_button);
    item.appendChild(headerRow);

    const details = document.createElement("div");
    details.classList.add("details");
    details.style.display = "none";
    details.style.marginTop = "10px";
    details.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word; background:#222; color:#0f0; padding:10px; border-radius:5px; font-size:11px;">${JSON.stringify(response, null, 2)}</pre>`;
    item.appendChild(details);
    results_content.appendChild(item);

    copy_button.addEventListener("click", () => copyResults(response));
    title.addEventListener("click", () => {
      details.style.display =
        details.style.display === "none" ? "block" : "none";
    });

    const domain = new URL(site_url).origin;
    ai_button.disabled = false;

    saveAnalysisHistory({
      site: domain,
      type: "security",
      securityScore: score,
      ...response,
    });

    const mdReport = `
# Güvenlik Analiz Raporu
**Hedef URL:** \`${response.url}\`
**Tarih:** \`${new Date().toLocaleString("tr-TR")}\`
**Genel Güvenlik Skoru:** ${score}/100
**Tespit Edilen WAF:** ${response.detectedWAF}

## 1. Kritik Zafiyetler
${response.leakedSecrets && response.leakedSecrets.length > 0 ? response.leakedSecrets.map((s) => `- [CRITICAL] Hassas Veri: ${s}`).join("\n") : "- Tespit edilmedi."}
${response.domainAnalysis && response.domainAnalysis.isSuspicious ? `- [HIGH] Oltalama Riski: ${response.domainAnalysis.warning}` : "- Oltalama riski yok."}

## 2. Web Yapılandırma ve CSP
${response.cspVulnerabilities && response.cspVulnerabilities.length > 0 ? response.cspVulnerabilities.map((c) => `- [MEDIUM] CSP: ${c}`).join("\n") : "- Zafiyetli CSP kuralı bulunamadı."}
${response.mixedContent && response.mixedContent.length > 0 ? response.mixedContent.map((m) => `- [LOW] Mixed Content: ${m}`).join("\n") : "- Karma içerik yok."}

## 3. Depolama ve Fonksiyon Riskleri
${response.storageVulnerabilities && response.storageVulnerabilities.length > 0 ? response.storageVulnerabilities.map((s) => `- [HIGH] Storage Sızıntısı: ${s}`).join("\n") : "- Yerel hafıza temiz."}
${response.riskyFunctions && response.riskyFunctions.length > 0 ? response.riskyFunctions.map((r) => `- [LOW] Tehlikeli Fonksiyon: \`${r}\``).join("\n") : "- Tespit edilmedi."}

## 4. Keşif Bilgileri (Recon)
- **Gizli Form Alanları (${response.hiddenInputs ? response.hiddenInputs.length : 0}):** ${response.hiddenInputs && response.hiddenInputs.length > 0 ? "\n  - " + response.hiddenInputs.join("\n  - ") : "Bulunmadı"}
- **Kritik Linkler (${response.suspiciousLinks ? response.suspiciousLinks.length : 0}):** ${response.suspiciousLinks && response.suspiciousLinks.length > 0 ? "\n  - " + response.suspiciousLinks.join("\n  - ") : "Bulunmadı"}

## 5. Kullanılan Teknolojiler
- **Frameworkler:** ${response.detectedFrameworks.map((f) => (f.version ? `${f.name} (v${f.version})` : f.name)).join(", ") || "Bulunamadı"}
- **UI Kütüphaneleri:** ${response.detectedUIFrameworks.map((f) => (typeof f === "string" ? f : f.version ? `${f.name} (v${f.version})` : f.name)).join(", ") || "Bulunamadı"}
    `;

    setupDownloadDropdown(response, mdReport, site_url);

    ai_button.onclick = () => {
      explanation_content.innerText = "";
      loading_explanation.style.display = "block";
      chrome.runtime.sendMessage(
        { action: "explain", data: response },
        (explanation) => {
          explanation_content.innerText = explanation;
          loading_explanation.style.display = "none";
        },
      );
    };
  };

  const performPerformanceTest = async () => {
    const startTime = Date.now();
    results_content.innerHTML = "";
    explanation_content.innerText = "";

    const dlBtn = document.getElementById("download_pdf");
    if (dlBtn) dlBtn.disabled = true;

    ai_button.disabled = true;
    loading.style.display = "block";

    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const site_url = (
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: () => window.location.href,
      })
    )[0].result;

    const page_speed_scores = await chrome.runtime.sendMessage({
      action: "performance",
      url: site_url,
    });
    loading.style.display = "none";

    const durationInSeconds = ((Date.now() - startTime) / 1000).toFixed(2);
    const duration_div = document.createElement("div");
    duration_div.innerHTML = `<strong>Analiz Süresi:</strong> ${durationInSeconds} saniye`;
    duration_div.style.marginBottom = "8px";
    results_content.prepend(duration_div);

    if (!page_speed_scores) {
      results_content.innerHTML = "<p>Performans skorları alınamadı.</p>";
      return;
    }

    const performance_statuses = {};
    const map_status = (score) => {
      if (score >= 80) return "safe";
      if (score >= 50) return "warning";
      return "danger";
    };

    performance_statuses["Performans "] = map_status(
      page_speed_scores.performance,
    );
    performance_statuses["Erişilebilirlik "] = map_status(
      page_speed_scores.accessibility,
    );
    performance_statuses["En İyi Uygulamalar"] = map_status(
      page_speed_scores.bestPractices,
    );
    performance_statuses["SEO "] = map_status(page_speed_scores.seo);

    const cardsContainer = document.createElement("div");
    cardsContainer.className = "status-cards-grid";
    Object.entries(performance_statuses).forEach(([title, status]) => {
      const card = createCard(title, status);
      cardsContainer.appendChild(card);
    });
    results_content.appendChild(cardsContainer);

    const score_div = document.createElement("div");
    score_div.innerHTML = `
      <strong>Performans Skorları:</strong><br>
      Performans: ${page_speed_scores.performance}<br>
      Erişilebilirlik: ${page_speed_scores.accessibility}<br>
      En İyi Uygulamalar: ${page_speed_scores.bestPractices}<br>
      SEO: ${page_speed_scores.seo}
    `;
    score_div.style.marginBottom = "10px";
    results_content.prepend(score_div);

    const item = document.createElement("div");
    item.classList.add("item");

    const title = document.createElement("div");
    title.innerHTML = "<strong>Performans Raporu JSON</strong> ";
    const arrow = document.createElement("span");
    arrow.innerHTML = "&#9660;";
    arrow.style.marginLeft = "8px";
    title.appendChild(arrow);

    const headerRow = document.createElement("div");
    headerRow.style.display = "flex";
    headerRow.style.justifyContent = "space-between";
    headerRow.style.alignItems = "center";
    headerRow.style.background = "var(--card-bg, #eee)";
    headerRow.style.padding = "8px";
    headerRow.style.borderRadius = "5px";

    headerRow.appendChild(title);
    headerRow.appendChild(copy_button);

    item.appendChild(headerRow);
    copy_button.addEventListener("click", () => copyResults(page_speed_scores));

    title.addEventListener("click", () => {
      details.style.display =
        details.style.display === "none" ? "block" : "none";
      arrow.innerHTML =
        details.style.display === "none" ? "&#9660;" : "&#9650;";
    });

    const details = document.createElement("div");
    details.classList.add("details");
    details.style.display = "none";
    details.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word; background:#222; color:#0f0; padding:10px; border-radius:5px; font-size:11px;">${JSON.stringify(page_speed_scores, null, 2)}</pre>`;

    item.appendChild(details);
    results_content.appendChild(item);

    const domain = new URL(site_url).origin;
    ai_button.disabled = false;

    saveAnalysisHistory({
      site: domain,
      type: "performance",
      pageSpeed: page_speed_scores,
    });

    const mdPerfReport = `
# Performans Analiz Raporu
**Hedef URL:** \`${site_url}\`
**Tarih:** \`${new Date().toLocaleString("tr-TR")}\`

## Skorlar (100 Üzerinden)
- **🚀 Performans:** ${page_speed_scores.performance}
- **♿ Erişilebilirlik:** ${page_speed_scores.accessibility}
- **💡 En İyi Uygulamalar:** ${page_speed_scores.bestPractices}
- **🔍 SEO:** ${page_speed_scores.seo}

> *Bu rapor otomatik performans asistanı ile oluşturulmuştur.*
    `;

    setupDownloadDropdown(page_speed_scores, mdPerfReport, site_url);

    ai_button.onclick = () => {
      explanation_content.innerText = "";
      loading_explanation.style.display = "block";
      chrome.runtime.sendMessage(
        { action: "explain", data: page_speed_scores },
        (explanation) => {
          explanation_content.innerText = explanation;
          loading_explanation.style.display = "none";
        },
      );
    };
  };

  analysis_button.addEventListener("click", performSecurityAnalysis);
  performance_button.addEventListener("click", performPerformanceTest);

  filterComponent();
  deleteHistory();
  changeTheme();
});
