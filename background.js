import { getAIExplanation } from "./geminiAPI.js";
import { pageSpeedScores } from "./components/performance.js";
// import { API_KEY_VIRUS } from "./config.js";

const saveHeaders = async (url, headers) => {
  const data = await chrome.storage.session.get("latestHeaders");
  const latestHeaders = data.latestHeaders || {};
  latestHeaders[url] = headers;
  await chrome.storage.session.set({ latestHeaders });
};

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = {};
    for (const header of details.responseHeaders) {
      headers[header.name.toLowerCase()] = header.value;
    }
    saveHeaders(details.url, headers);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"],
);

/*
const api_key_virus = API_KEY_VIRUS;
const scanUrlWithVirusTotal = async (url) => {
  const scanUrl = `https://www.virustotal.com/vtapi/v2/url/scan`;
  const reportUrl = `https://www.virustotal.com/vtapi/v2/url/report`;
  
  await fetch(scanUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `apikey=${api_key_virus}&url=${encodeURIComponent(url)}`,
  });
  
  const reportResponse = await fetch(`${reportUrl}?apikey=${api_key_virus}&resource=${encodeURIComponent(url)}`);
  const reportData = await reportResponse.json();
  return reportData;
};
*/

chrome.webRequest.onCompleted.addListener(
  async (details) => {
    if (
      ["xmlhttprequest", "fetch"].includes(details.type) &&
      ["GET", "POST", "PUT", "DELETE"].includes(details.method.toUpperCase()) &&
      /\/(api|rest|v\d+|endpoint|json|php)/i.test(details.url)
    ) {
      const data = await chrome.storage.session.get("detectedApiCalls");
      const calls = data.detectedApiCalls || [];
      calls.push({
        url: details.url,
        method: details.method,
        status: details.statusCode,
        time: new Date().toLocaleTimeString(),
      });
      await chrome.storage.session.set({ detectedApiCalls: calls });
    }
  },
  { urls: ["<all_urls>"] },
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyze") {
    (async () => {
      try {
        const site_url = message.url;
        let tabId = sender.tab ? sender.tab.id : null;

        if (!tabId) {
          const [tab] = await chrome.tabs.query({
            active: true,
            currentWindow: true,
          });
          tabId = tab?.id;
        }
        if (!tabId) throw new Error("Aktif sekme bulunamadı.");

        const storageData = await chrome.storage.session.get("latestHeaders");
        const headers =
          (storageData.latestHeaders && storageData.latestHeaders[site_url]) ||
          {};
        const securityHeaders = {
          "Content-Security-Policy":
            headers["content-security-policy"] || "Eksik",
          "X-Frame-Options": headers["x-frame-options"] || "Eksik",
          "Strict-Transport-Security":
            headers["strict-transport-security"] || "Eksik",
        };

        const results = await Promise.allSettled([
          //scanUrlWithVirusTotal(site_url),
          chrome.cookies.getAll({ url: site_url }), // İndeks 0
          chrome.scripting.executeScript({
            // İndeks 1
            target: { tabId: tabId },
            world: "MAIN",
            func: () => {
              const htmlContent = document.documentElement.outerHTML;
              const scripts = Array.from(document.scripts);
              const scriptSrcs = scripts.map((s) => s.src).filter(Boolean);
              const inlineScripts = scripts
                .filter((s) => !s.src)
                .map((s) => s.textContent || "");

              const riskyFunctionsList = [
                "eval",
                "document.write",
                "setTimeout",
                "setInterval",
                "innerHTML",
              ];
              const detectedRiskyFunctions = [];
              inlineScripts.forEach((code) => {
                riskyFunctionsList.forEach((func) => {
                  const regex = new RegExp("\\b" + func + "\\b");
                  if (
                    regex.test(code) &&
                    !detectedRiskyFunctions.includes(func)
                  ) {
                    detectedRiskyFunctions.push(func);
                  }
                });
              });

              const detectedSecrets = [];
              const secretPatterns = [
                {
                  name: "Muhtemel API Key / Token",
                  regex:
                    /(?:api_key|apikey|auth_token|access_token|secret)[\s:=]+["']([a-zA-Z0-9\-_]{16,})["']/i,
                },
                {
                  name: "AWS Access Key",
                  regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/,
                },
                {
                  name: "Google Cloud API Key",
                  regex: /AIza[0-9A-Za-z\-_]{35}/,
                },
                {
                  name: "Stripe Standard Key",
                  regex: /sk_live_[0-9a-zA-Z]{24}/,
                },
                {
                  name: "JSON Web Token (JWT)",
                  regex:
                    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
                },
              ];

              const searchArea =
                inlineScripts.join("\n") +
                (
                  htmlContent.match(/<script[\s\S]*?>[\s\S]*?<\/script>/g) || []
                ).join("\n");

              secretPatterns.forEach((pattern) => {
                const match = searchArea.match(pattern.regex);
                if (match) detectedSecrets.push(pattern.name);
              });

              const mixedContentIssues = [];
              if (window.location.protocol === "https:") {
                const allUrls = [
                  ...Array.from(document.images).map((img) => img.src),
                  ...scriptSrcs,
                  ...Array.from(
                    document.querySelectorAll("link[rel='stylesheet']"),
                  ).map((link) => link.href),
                ];

                const insecureUrls = allUrls.filter(
                  (url) => url && url.startsWith("http://"),
                );
                if (insecureUrls.length > 0) {
                  mixedContentIssues.push(
                    `${insecureUrls.length} adet güvensiz (HTTP) kaynak tespit edildi.`,
                  );
                }
              }

              const currentHostname = window.location.hostname;
              let isSuspiciousDomain = false;
              let domainWarning = null;

              const suspiciousPatterns = [
                /g[0oO]{2}gle/,
                /faceb[0oO]{2}k/,
                /inst[a@]gr[a@]m/,
                /b[a@]nk/,
              ];
              if (
                suspiciousPatterns.some((regex) =>
                  regex.test(currentHostname),
                ) &&
                !currentHostname.includes("google.com") &&
                !currentHostname.includes("facebook.com")
              ) {
                isSuspiciousDomain = true;
                domainWarning =
                  "Şüpheli Domain! Bilinen bir markayı taklit ediyor olabilir.";
              }

              const detectedFrameworks = [];
              const detectedUIFrameworks = [];

              const frameworkPatterns = [
                { name: "React", regex: /react-dom|_REACT_/i },
                { name: "Next.js", regex: /_next\/static|__NEXT_DATA__/i },
                { name: "Vue.js", regex: /data-v-|data-vue-/i },
                { name: "Angular", regex: /ng-version|ng-app|_ngcontent/i },
                { name: "WordPress", regex: /wp-content|wp-includes/i },
              ];

              frameworkPatterns.forEach((fw) => {
                if (
                  scriptSrcs.some((s) => fw.regex.test(s)) ||
                  fw.regex.test(htmlContent)
                ) {
                  detectedFrameworks.push({ name: fw.name });
                }
              });

              const winProps = Object.keys(window);

              if (
                window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
                winProps.some((p) => p.startsWith("_reactRootContainer"))
              ) {
                if (!detectedFrameworks.some((f) => f.name === "React"))
                  detectedFrameworks.push({ name: "React" });
              }
              if (window.__VUE__ || window.Vue) {
                if (!detectedFrameworks.some((f) => f.name === "Vue.js"))
                  detectedFrameworks.push({ name: "Vue.js" });
              }
              if (window.getAllAngularRootElements || window.ng) {
                if (!detectedFrameworks.some((f) => f.name === "Angular"))
                  detectedFrameworks.push({ name: "Angular" });
              }
              if (window.Ember || window.EmberENV) {
                if (!detectedFrameworks.some((f) => f.name === "Ember.js"))
                  detectedFrameworks.push({ name: "Ember.js" });
              }
              if (window.jQuery || window.$) {
                if (!detectedFrameworks.some((f) => f.name === "jQuery"))
                  detectedFrameworks.push({ name: "jQuery" });
              }

              const allElements = document.querySelectorAll("*");
              const classList = [];
              for (const el of allElements) {
                if (el.classList && el.classList.length > 0) {
                  classList.push(...el.classList);
                }
              }

              const linkHrefs = Array.from(
                document.querySelectorAll("link[href]"),
              ).map((l) => l.href);
              const twCount = classList.filter((c) =>
                /^(tw-|text-|bg-|p-|m-|flex-|grid-|justify-)/.test(c),
              ).length;
              if (twCount > 5 || linkHrefs.some((h) => /tailwind/i.test(h)))
                detectedUIFrameworks.push("Tailwind CSS");

              if (
                classList.some((c) =>
                  /^(container|row|col-|btn-|navbar-)/.test(c),
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
                  /^(is-|has-|column|notification)/.test(c),
                ) &&
                linkHrefs.some((h) => /bulma/i.test(h))
              ) {
                detectedUIFrameworks.push("Bulma");
              }

              return {
                jsFiles: scriptSrcs,
                detectedRiskyFunctions,
                detectedSecrets,
                mixedContentIssues,
                domainAnalysis: {
                  hostname: currentHostname,
                  isSuspicious: isSuspiciousDomain,
                  warning: domainWarning,
                },
                detectedFrameworks,
                detectedUIFrameworks,
                scriptStats: {
                  inline: inlineScripts.length,
                  external: scriptSrcs.length,
                },
              };
            },
          }),
        ]);

        //const malwareResult = results[0] || { status: "rejected" };
        const rawCookies = results[0] || { status: "rejected", value: [] };
        const pageAnalysisResult = results[1] || { status: "rejected" };

        const safeCookieList =
          rawCookies.status === "fulfilled" && Array.isArray(rawCookies.value)
            ? rawCookies.value
            : [];

        const cookiesArray = safeCookieList.map((c) => {
          let risks = [];
          if (!c.httpOnly && c.value) risks.push("XSS Riski (HttpOnly Yok)");
          if (!c.secure) risks.push("MitM Riski (Secure Yok)");
          if (c.sameSite === "no_restriction" && !c.secure)
            risks.push("CSRF Riski (SameSite=None ve Secure değil)");

          return {
            name: c.name,
            domain: c.domain,
            secure: c.secure,
            httpOnly: c.httpOnly,
            sameSite: c.sameSite,
            risks: risks,
          };
        });

        const resultData =
          pageAnalysisResult.status === "fulfilled" &&
          pageAnalysisResult.value &&
          pageAnalysisResult.value[0]
            ? pageAnalysisResult.value[0].result
            : {};

        sendResponse({
          url: site_url,
          securityHeaders,
          riskyFunctions: resultData.detectedRiskyFunctions || [],
          leakedSecrets: resultData.detectedSecrets || [],
          mixedContent: resultData.mixedContentIssues || [],
          domainAnalysis: resultData.domainAnalysis || {},
          detectedFrameworks: resultData.detectedFrameworks || [],
          detectedUIFrameworks: resultData.detectedUIFrameworks || [], // Tailwind ve Bootstrap burada yakalanacak
          jsFiles: resultData.jsFiles || [],
          scriptStats: resultData.scriptStats || {},
          cookies: cookiesArray,
          /*malwareScan:
            malwareResult.status === "fulfilled"
              ? malwareResult.value
              : { error: "Tarama yapılamadı" },*/
          malwareScan: { state: "geçici" },
        });
      } catch (error) {
        console.error("Analiz hatası:", error);
        sendResponse({ error: "Analiz başarısız", details: error.message });
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
    (async () => {
      const data = await chrome.storage.session.get("detectedApiCalls");
      sendResponse({ endpoints: data.detectedApiCalls || [] });
      await chrome.storage.session.set({ detectedApiCalls: [] });
    })();
    return true;
  }
});
