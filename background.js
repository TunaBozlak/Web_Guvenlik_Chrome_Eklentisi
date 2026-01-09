import { getAIExplanation } from "./geminiAPI.js";
import { pageSpeedScores } from "./components/performance.js";
//import { API_KEY_VIRUS } from "./config.js";

let latestHeaders = {};
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = {};
    for (const header of details.responseHeaders) {
      headers[header.name.toLowerCase()] = header.value;
    }

    latestHeaders[details.url] = headers;
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

/*const api_key_virus = API_KEY_VIRUS;
const scanUrlWithVirusTotal = async (url) => {
  const scanUrl = `https://www.virustotal.com/vtapi/v2/url/scan`;
  const reportUrl = `https://www.virustotal.com/vtapi/v2/url/report`;
  const scanResponse = await fetch(scanUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `apikey=${api_key_virus}&url=${encodeURIComponent(url)}`,
  });
  const scanData = await scanResponse.json();
  if (scanData.response_code !== 1) {
    throw new Error("Virustotal scan başarısız");
  }
  const reportResponse = await fetch(
    `${reportUrl}?apikey=${api_key_virus}&resource=${encodeURIComponent(url)}`
  );
  const reportData = await reportResponse.json();
  if (reportData.response_code !== 1) {
    throw new Error("Virustotal raporu alınamadı");
  }
  return reportData;
};*/

let detectedApiCalls = [];
chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (
      ["xmlhttprequest", "fetch"].includes(details.type) &&
      ["GET", "POST", "PUT", "DELETE"].includes(details.method.toUpperCase()) &&
      /\/(api|rest|v\d+|endpoint|json|php)/i.test(details.url)
    ) {
      detectedApiCalls.push({
        url: details.url,
        method: details.method,
        status: details.statusCode,
        time: new Date().toLocaleTimeString(),
      });
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyze") {
    console.log("Analizlenen site:", message.url);
    (async () => {
      try {
        const headers = latestHeaders[message.url] || {};
        const securityHeaders = {
          "Content-Security-Policy": headers["content-security-policy"],
          "X-Frame-Options": headers["x-frame-options"],
          "Strict-Transport-Security": headers["strict-transport-security"],
        };
        //const malwareResult = await scanUrlWithVirusTotal(message.url);

        const site_url = message.url;
        let tabId = sender.tab ? sender.tab.id : null;

        if (!tabId) {
          const [tab] = await chrome.tabs.query({
            active: true,
            currentWindow: true,
          });
          tabId = tab?.id;
        }

        if (!tabId) {
          throw new Error("Aktif sekme bulunamadı.");
        }

        let rawCookies = [];
        try {
          rawCookies = (await chrome.cookies.getAll({ url: site_url })) || [];
        } catch (e) {
          console.warn("Çerezler alınırken hata:", e);
        }

        const pageAnalysisResult = await chrome.scripting.executeScript({
          target: { tabId: tabId },
          func: () => {
            const htmlContent = document.documentElement.outerHTML;
            const scripts = Array.from(document.scripts);
            const scriptSrcs = scripts.map((s) => s.src).filter(Boolean);
            const inlineScripts = scripts
              .filter((s) => !s.src)
              .map((s) => s.textContent || "");

            const allElements = document.querySelectorAll("*");
            const classList = [];
            for (const el of allElements) {
              if (el.classList && el.classList.length > 0) {
                classList.push(...el.classList);
              }
            }

            const linkHrefs = Array.from(
              document.querySelectorAll("link[href]")
            ).map((l) => l.href);

            const riskyFunctionsList = [
              "eval",
              "document.write",
              "Function",
              "setTimeout",
              "setInterval",
              "innerHTML",
              "outerHTML",
              "execScript",
              "unescape",
              "with",
            ];
            const detectedRiskyFunctions = [];

            inlineScripts.forEach((code) => {
              riskyFunctionsList.forEach((func) => {
                if (
                  code.includes(func) &&
                  !detectedRiskyFunctions.includes(func)
                ) {
                  detectedRiskyFunctions.push(func);
                }
              });
            });

            const detectedFrameworks = [];
            const detectedUIFrameworks = [];

            const frameworkPatterns = [
              {
                name: "React",
                regex:
                  /react-dom|react-root|_REACT_|data-reactroot|react\.development|react\.production/i,
              },
              { name: "Next.js", regex: /_next\/static|__NEXT_DATA__/i },
              {
                name: "Vue.js",
                regex: /vue\.js|vue\.min\.js|vue-router|data-v-|data-vue-/i,
              },
              { name: "Nuxt.js", regex: /_nuxt|__NUXT__/i },
              {
                name: "Angular",
                regex: /angular\.js|ng-version|ng-app|_ngcontent/i,
              },
              { name: "Svelte", regex: /svelte-/i },
              { name: "jQuery", regex: /jquery|wufoo|jQ/i },
              {
                name: "WordPress",
                regex: /wp-content|wp-includes|wp-json|wp-admin/i,
              },
              { name: "Alpine.js", regex: /x-data|alpine\.js/i },
              { name: "Preact", regex: /preact/i },
              { name: "Astro", regex: /astro/i },
            ];

            frameworkPatterns.forEach((fw) => {
              const inSrc = scriptSrcs.some((s) => fw.regex.test(s));
              const inHtml = fw.regex.test(htmlContent);
              if (inSrc || inHtml) detectedFrameworks.push({ name: fw.name });
            });

            const twCount = classList.filter((c) =>
              /^(tw-|text-|bg-|p-|m-|flex-|grid-|justify-)/.test(c)
            ).length;
            if (twCount > 5 || linkHrefs.some((h) => /tailwind/i.test(h))) {
              detectedUIFrameworks.push("Tailwind CSS");
            }

            if (
              classList.some((c) =>
                /^(container|row|col-|btn-|navbar-)/.test(c)
              ) ||
              linkHrefs.some((h) => /bootstrap/i.test(h))
            ) {
              detectedUIFrameworks.push("Bootstrap");
            }

            if (classList.some((c) => /^Mui/.test(c)))
              detectedUIFrameworks.push("Material UI");

            if (classList.some((c) => /^ant-/.test(c)))
              detectedUIFrameworks.push("Ant Design");

            if (
              classList.some((c) =>
                /^(is-|has-|column|notification)/.test(c)
              ) &&
              linkHrefs.some((h) => /bulma/i.test(h))
            ) {
              detectedUIFrameworks.push("Bulma");
            }

            return {
              jsFiles: scriptSrcs,
              detectedRiskyFunctions,
              detectedFrameworks,
              detectedUIFrameworks,
              scriptStats: {
                inline: inlineScripts.length,
                external: scriptSrcs.length,
              },
            };
          },
        });

        if (
          !pageAnalysisResult ||
          !pageAnalysisResult[0] ||
          !pageAnalysisResult[0].result
        ) {
          throw new Error("Sayfa analizi başarısız oldu.");
        }

        const resultData = pageAnalysisResult[0].result;

        const cookiesArray = rawCookies.map((c) => ({
          name: c.name,
          domain: c.domain,
          secure: c.secure,
          httpOnly: c.httpOnly,
          sameSite: c.sameSite,
          path: c.path,
          expirationDate: c.expirationDate,
          hostOnly: c.hostOnly,
          session: c.session,
        }));

        const analysisResult = {
          url: site_url,
          securityHeaders,
          riskyFunctions: resultData.detectedRiskyFunctions,
          detectedFrameworks: resultData.detectedFrameworks,
          detectedUIFrameworks: resultData.detectedUIFrameworks,
          jsFiles: resultData.jsFiles,
          scriptStats: resultData.scriptStats,
          cookies: cookiesArray,
          malwareScan: { state: "geçici" },
        };

        sendResponse(analysisResult);
      } catch (error) {
        console.error("Analiz hatası:", error);
        sendResponse({
          error: "Analiz sırasında hata oluştu",
          details: error.message,
        });
      }
    })();
    return true;
  }

  if (message.action === "explain") {
    console.log("AI açıklaması istendi");
    (async () => {
      try {
        const explanation = await getAIExplanation(message.data);
        sendResponse(explanation);
      } catch (error) {
        console.error("AI açıklama hatası:", error);
        sendResponse("AI açıklaması alınamadı.");
      }
    })();
    return true;
  }

  if (message.action === "performance") {
    const site_url = message.url;
    console.log("Performans testi istendi:", site_url);

    (async () => {
      try {
        const page_speed_scores = await pageSpeedScores(site_url);
        sendResponse(page_speed_scores);
      } catch (error) {
        console.error("Performans testi hatası:", error);
        sendResponse(null);
      }
    })();
    return true;
  }

  if (message.action === "analyzeApiEndpoints") {
    sendResponse({ endpoints: detectedApiCalls });
    detectedApiCalls = [];
    return true;
  }
});
