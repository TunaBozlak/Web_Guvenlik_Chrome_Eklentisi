import {
  analyzeSecurityStatus,
  calculateSecurityScore,
} from "./components/security.js";
import { createCard } from "./components/card.js";
import { filterComponent } from "./components/filter.js";
import { deleteHistory } from "./components/delete.js";
import { saveAnalysisHistory } from "./components/history.js";
import { changeTheme } from "./components/theme.js";
import { downloadPdf } from "./components/download.js";

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
    download_button.disabled = true;
    ai_button.disabled = true;

    loading.style.display = "block";

    const site_url = (
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: () => window.location.href,
      })
    )[0].result;
    console.log("Analizlenen site (popup'dan):", site_url);

    const response = await chrome.runtime.sendMessage({
      action: "analyze",
      url: site_url,
    });

    const apiResponse = await chrome.runtime.sendMessage({
      action: "analyzeApiEndpoints",
    });
    response.endpoints = apiResponse?.endpoints || [];

    loading.style.display = "none";

    const endTime = Date.now();
    const durationInSeconds = ((endTime - startTime) / 1000).toFixed(2);

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
      box.style.padding = "10px";
      box.style.borderRadius = "8px";
      box.style.marginBottom = "10px";
      box.style.border = `1px solid ${textColor}`;

      let listHtml = items.map((i) => `<li>${i}</li>`).join("");
      box.innerHTML = `<strong style="display:flex; align-items:center; gap:5px;">${icon} ${title}</strong>
                       <ul style="margin: 5px 0 0 0; padding-left: 20px; font-size:0.9em;">${listHtml}</ul>`;
      return box;
    };

    if (response.domainAnalysis && response.domainAnalysis.isSuspicious) {
      const phishingBox = createAlertBox(
        "Kritik Uyarı: Şüpheli Alan Adı!",
        [
          response.domainAnalysis.warning,
          `Tespit edilen: ${response.domainAnalysis.hostname}`,
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
        const cookieWarnings = riskyCookies.map(
          (c) => `<strong>${c.name}</strong>: ${c.risks.join(", ")}`,
        );
        const cookieBox = createAlertBox(
          "Riskli Çerez Yapılandırmaları",
          cookieWarnings,
          "#e8f4fd",
          "#0277bd",
          "🍪",
        );
        if (cookieBox) results_content.appendChild(cookieBox);
      }
    }

    const statuses = analyzeSecurityStatus(response, site_url);
    const score = calculateSecurityScore(statuses);

    const score_div = document.createElement("div");
    score_div.innerHTML = `
      <div style="font-size: 1.1em; margin-bottom: 5px;"><strong>Genel Güvenlik Skoru:</strong> ${score} / 100</div>
      <div style="background: #e0e0e0; border-radius: 8px; overflow: hidden; width: 100%; height: 12px; margin-bottom: 15px;">
        <div style="
          width: ${score}%;
          height: 100%;
          background: ${score >= 80 ? "#4caf50" : score >= 50 ? "#ff9800" : "#f44336"};
          transition: width 0.5s ease-in-out;
        "></div>
      </div>
    `;
    headerContainer.appendChild(score_div);

    Object.entries(statuses).forEach(([title, status]) => {
      const card = createCard(title, status);
      results_content.appendChild(card);
    });

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
        li.innerHTML = `${logoImg}<span style="font-weight: 500;">${name}</span>`;
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
    download_button.disabled = false;
    ai_button.disabled = false;

    saveAnalysisHistory({
      site: domain,
      type: "security",
      securityScore: score,
      ...response,
    });

    download_button.addEventListener("click", () =>
      downloadPdf(response, site_url),
    );

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
    download_button.disabled = true;
    ai_button.disabled = true;

    loading.style.display = "block";

    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const site_url = (
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: () => window.location.href,
      })
    )[0].result;
    console.log("Performans testi yapılan site (popup'dan):", site_url);

    const page_speed_scores = await chrome.runtime.sendMessage({
      action: "performance",
      url: site_url,
    });

    loading.style.display = "none";

    const endTime = Date.now();
    const durationInSeconds = ((endTime - startTime) / 1000).toFixed(2);
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

    Object.entries(performance_statuses).forEach(([title, status]) => {
      const card = createCard(title, status);
      results_content.appendChild(card);
    });

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
    title.innerHTML = "<strong>Performans Raporu</strong> ";

    const arrow = document.createElement("span");
    arrow.innerHTML = "&#9660;";
    arrow.style.marginLeft = "8px";
    title.appendChild(arrow);

    const headerRow = document.createElement("div");
    headerRow.style.display = "flex";
    headerRow.style.justifyContent = "space-between";
    headerRow.style.alignItems = "center";
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
    details.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${JSON.stringify(
      page_speed_scores,
      null,
      2,
    )}</pre>`;

    item.appendChild(details);
    results_content.appendChild(item);

    const domain = new URL(site_url).origin;
    download_button.disabled = false;
    ai_button.disabled = false;

    saveAnalysisHistory({
      site: domain,
      type: "performance",
      pageSpeed: page_speed_scores,
    });

    download_button.addEventListener("click", () => {
      downloadPdf(page_speed_scores, site_url);
    });

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
