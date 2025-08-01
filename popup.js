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
    const duration_div = document.createElement("div");
    duration_div.innerHTML = `<strong>Analiz Süresi:</strong> ${durationInSeconds} saniye`;
    duration_div.style.marginBottom = "8px";
    results_content.prepend(duration_div);

    if (!response) {
      results_content.innerHTML =
        "<p>Güvenlik analizi sonuçları alınamadı.</p>";
      return;
    }

    const statuses = analyzeSecurityStatus(response, site_url);

    Object.entries(statuses).forEach(([title, status]) => {
      const card = createCard(title, status);
      results_content.appendChild(card);
    });

    const apiHeader = document.createElement("h3");
    apiHeader.textContent = "API Endpoint Analizi";
    apiHeader.style.marginTop = "20px";
    results_content.appendChild(apiHeader);

    const card = document.createElement("div");
    card.classList.add("api-card-v2");
    results_content.appendChild(card);

    const endpoints = response?.endpoints || [];

    if (endpoints.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "Gerçek API isteği bulunamadı.";
      empty.style.color = "#555";
      card.appendChild(empty);
    } else {
      endpoints.forEach((entry) => {
        const div = document.createElement("div");
        div.classList.add("api-card");
        div.innerHTML = `
      <div><strong>Method:</strong> <span style="color: #007acc;">${entry.method}</span></div>
      <div><strong>Status:</strong> ${entry.status}</div>
      <div><strong>Time:</strong> ${entry.time}</div>
      <div style="word-break: break-all;"><strong>URL:</strong> ${entry.url}</div>
    `;
        card.appendChild(div);
      });
    }

    const frameworkHeader = document.createElement("h3");
    frameworkHeader.textContent = "Tespit Edilen Teknolojiler";
    frameworkHeader.style.marginTop = "20px";
    results_content.appendChild(frameworkHeader);

    if (response.detectedFrameworks && response.detectedFrameworks.length > 0) {
      const ul = document.createElement("ul");
      ul.style.listStyleType = "none";
      ul.style.paddingLeft = "0";
      response.detectedFrameworks.forEach((framework) => {
        const li = document.createElement("li");
        li.style.marginBottom = "5px";
        li.style.fontSize = "1.1em";
        const logoPath = frameworks[framework.name];
        const logoImg = logoPath
          ? `<img src="${logoPath}" alt="${framework.name}" style="width:20px;vertical-align:middle;margin-right:6px;">`
          : "";
        li.innerHTML = `${logoImg}<span style="font-weight: bold; color: #4CAF50;">${
          framework.name
        } ${
          framework.version ? framework.version : "(Versiyon Bilinmiyor)"
        }</span>`;
        ul.appendChild(li);
      });
      results_content.appendChild(ul);
    } else {
      const noFrameworkText = document.createElement("p");
      noFrameworkText.textContent =
        "Bu sitede belirgin bir JavaScript çerçevesi tespit edilemedi.";
      noFrameworkText.style.color = "#555";
      noFrameworkText.style.marginTop = "10px";
      results_content.appendChild(noFrameworkText);
    }

    const uiHeader = document.createElement("h3");
    uiHeader.textContent = "Tespit Edilen UI Kit ve CSS Framework'leri";
    uiHeader.style.marginTop = "20px";
    results_content.appendChild(uiHeader);
    if (
      response.detectedUIFrameworks &&
      response.detectedUIFrameworks.length > 0
    ) {
      const ul = document.createElement("ul");
      ul.style.listStyleType = "none";
      ul.style.paddingLeft = "0";
      response.detectedUIFrameworks.forEach((kit) => {
        const li = document.createElement("li");
        li.style.marginBottom = "5px";
        li.style.fontSize = "1.1em";
        const logoPath = ui_frameworks[kit];
        const logoImg = logoPath
          ? `<img src="${logoPath}" alt="${kit}" style="width:20px;vertical-align:middle;margin-right:6px;">`
          : "";
        li.innerHTML = `${logoImg}<span style="font-weight: bold; color: #007bff;">${kit}</span>`;
        ul.appendChild(li);
      });
      results_content.appendChild(ul);
    } else {
      const noUiText = document.createElement("p");
      noUiText.textContent =
        "Bu sitede yaygın bir UI kütüphanesi tespit edilemedi.";
      noUiText.style.color = "#555";
      noUiText.style.marginTop = "10px";
      results_content.appendChild(noUiText);
    }

    const score = calculateSecurityScore(statuses);
    const score_div = document.createElement("div");
    score_div.innerHTML = `
  <strong>Genel Güvenlik Skoru:</strong> ${score} / 100
  <div style="background: #eee; border-radius: 8px; overflow: hidden; width: 100%; height: 20px; margin-top: 4px;">
    <div style="
      width: ${score}%;
      height: 100%;
      background: ${score >= 80 ? "green" : score >= 50 ? "orange" : "red"};
      transition: width 0.3s ease;
    "></div>
  </div>
`;
    score_div.style.marginBottom = "10px";
    results_content.prepend(score_div);

    const item = document.createElement("div");
    item.classList.add("item");

    const title = document.createElement("div");
    title.innerHTML = "<strong>Analiz Raporu</strong> ";

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
    copy_button.addEventListener("click", () => copyResults(response));

    title.addEventListener("click", () => {
      details.style.display =
        details.style.display === "none" ? "block" : "none";
      arrow.innerHTML =
        details.style.display === "none" ? "&#9660;" : "&#9650;";
    });

    const details = document.createElement("div");
    details.classList.add("details");
    details.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${JSON.stringify(
      response,
      null,
      2
    )}</pre>`;
    item.appendChild(details);
    results_content.appendChild(item);

    const domain = new URL(site_url).origin;
    download_button.disabled = false;
    ai_button.disabled = false;
    saveAnalysisHistory({
      site: domain,
      type: "security",
      securityScore: score,
      ...response,
    });
    download_button.addEventListener("click", () => {
      downloadPdf(response, site_url);
    });

    ai_button.onclick = () => {
      explanation_content.innerText = "";
      loading_explanation.style.display = "block";
      chrome.runtime.sendMessage(
        { action: "explain", data: response },
        (explanation) => {
          explanation_content.innerText = explanation;
          loading_explanation.style.display = "none";
        }
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
      page_speed_scores.performance
    );
    performance_statuses["Erişilebilirlik "] = map_status(
      page_speed_scores.accessibility
    );
    performance_statuses["En İyi Uygulamalar"] = map_status(
      page_speed_scores.bestPractices
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
    details.style.display = "none";
    details.style.marginTop = "8px";
    details.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${JSON.stringify(
      page_speed_scores,
      null,
      2
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
        }
      );
    };
  };

  analysis_button.addEventListener("click", performSecurityAnalysis);
  performance_button.addEventListener("click", performPerformanceTest);

  filterComponent();
  deleteHistory();
  changeTheme();
});
