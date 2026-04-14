import { getAIExplanation } from "./geminiAPI.js";
import { pageSpeedScores } from "./components/performance.js";
// import { API_KEY_VIRUS } from "./config.js";

const saveHeaders = async (url, headers) => {
  const data = await chrome.storage.session.get("latestHeaders");
  const latestHeaders = data.latestHeaders || {};
  const origin = new URL(url).origin;
  latestHeaders[url] = headers;
  latestHeaders[origin] = headers;
  await chrome.storage.session.set({ latestHeaders });
};

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === "main_frame") {
      const headers = {};
      for (const header of details.responseHeaders) {
        headers[header.name.toLowerCase()] = header.value;
      }
      saveHeaders(details.url, headers);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"],
);

/*const api_key_virus = API_KEY_VIRUS;
const scanUrlWithVirusTotal = async (url) => {
  const scanUrl = `https://www.virustotal.com/vtapi/v2/url/scan`;

  const reportUrl = `https://www.virustotal.com/vtapi/v2/url/report`;

  await fetch(scanUrl, {
    method: "POST",

    headers: { "Content-Type": "application/x-www-form-urlencoded" },

    body: `apikey=${api_key_virus}&url=${encodeURIComponent(url)}`,
  });

  const reportResponse = await fetch(
    `${reportUrl}?apikey=${api_key_virus}&resource=${encodeURIComponent(url)}`,
  );

  const reportData = await reportResponse.json();

  return reportData;
};*/

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
        const origin = new URL(site_url).origin;

        let headers =
          (storageData.latestHeaders &&
            (storageData.latestHeaders[site_url] ||
              storageData.latestHeaders[origin])) ||
          {};

        if (Object.keys(headers).length === 0) {
          try {
            const fetchRes = await fetch(site_url, {
              method: "HEAD",
              cache: "no-cache",
            });
            fetchRes.headers.forEach((value, key) => {
              headers[key.toLowerCase()] = value;
            });
            console.log("Headerlar anlık FETCH ile kurtarıldı!");
          } catch (e) {
            console.warn("Canlı Header çekilemedi, sadece DOM incelenecek.");
          }
        }

        const securityHeaders = {
          "Content-Security-Policy":
            headers["content-security-policy"] || "Eksik",
          "X-Frame-Options": headers["x-frame-options"] || "Eksik",
          "Strict-Transport-Security":
            headers["strict-transport-security"] || "Eksik",
          "X-Content-Type-Options":
            headers["x-content-type-options"] || "Eksik",
          "CORS-Allow-Origin":
            headers["access-control-allow-origin"] || "Kısıtlı (Güvenli)",
          "Server-Bilgisi": headers["server"] || "Gizlenmiş",
          "X-Powered-By": headers["x-powered-by"] || "Gizlenmiş",
        };

        const results = await Promise.allSettled([
          //scanUrlWithVirusTotal(site_url),
          chrome.cookies.getAll({ url: site_url }),
          chrome.scripting.executeScript({
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
                )
                  detectedFrameworks.push({ name: fw.name });
              });

              const winProps = Object.keys(window);
              const getVersion = (obj) =>
                obj && obj.version ? obj.version : null;
              const extractVerFromUrl = (url) => {
                const match = url.match(
                  /(?:@|v\/|-|\/)([0-9]+\.[0-9]+(?:\.[0-9]+)?)/,
                );
                return match ? match[1] : null;
              };

              if (
                window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
                winProps.some((p) => p.startsWith("_reactRootContainer"))
              ) {
                let v = getVersion(window.__REACT_DEVTOOLS_GLOBAL_HOOK__);
                if (!v && window.__REACT_DEVTOOLS_GLOBAL_HOOK__?.renderers) {
                  try {
                    v = Object.values(
                      window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers,
                    )[0]?.version;
                  } catch (e) {}
                }
                if (!detectedFrameworks.some((f) => f.name === "React"))
                  detectedFrameworks.push({ name: "React", version: v });
              }
              if (window.__VUE__ || window.Vue) {
                let v = getVersion(window.Vue);
                if (!detectedFrameworks.some((f) => f.name === "Vue.js"))
                  detectedFrameworks.push({ name: "Vue.js", version: v });
              }
              if (window.getAllAngularRootElements || window.ng) {
                let v =
                  window.ng?.coreTokens?.VERSION?.full ||
                  window.ng?.VERSION?.full;
                if (!detectedFrameworks.some((f) => f.name === "Angular"))
                  detectedFrameworks.push({ name: "Angular", version: v });
              }
              if (window.Ember || window.EmberENV) {
                let v = window.Ember?.VERSION;
                if (!detectedFrameworks.some((f) => f.name === "Ember.js"))
                  detectedFrameworks.push({ name: "Ember.js", version: v });
              }
              if (window.jQuery || window.$) {
                let v = window.jQuery
                  ? window.jQuery.fn.jquery
                  : window.$
                    ? window.$.fn.jquery
                    : null;
                if (!detectedFrameworks.some((f) => f.name === "jQuery"))
                  detectedFrameworks.push({ name: "jQuery", version: v });
              }

              const detectedUIFrameworks = [];
              const allElements = document.querySelectorAll("*");
              const classList = [];
              for (const el of allElements) {
                if (el.classList && el.classList.length > 0)
                  classList.push(...el.classList);
              }

              const linkHrefs = Array.from(
                document.querySelectorAll("link[href]"),
              ).map((l) => l.href);
              const twLink = linkHrefs.find((h) => /tailwind/i.test(h));
              const twCount = classList.filter((c) =>
                /^(tw-|text-|bg-|p-|m-|flex-|grid-|justify-)/.test(c),
              ).length;
              if (twCount > 5 || twLink) {
                detectedUIFrameworks.push({
                  name: "Tailwind CSS",
                  version: twLink ? extractVerFromUrl(twLink) : null,
                });
              }
              const bsLink = linkHrefs.find((h) => /bootstrap/i.test(h));
              if (
                classList.some((c) =>
                  /^(container|row|col-|btn-|navbar-)/.test(c),
                ) ||
                bsLink
              ) {
                detectedUIFrameworks.push({
                  name: "Bootstrap",
                  version: bsLink ? extractVerFromUrl(bsLink) : null,
                });
              }
              if (classList.some((c) => /^Mui/.test(c)))
                detectedUIFrameworks.push({ name: "Material UI" });
              if (classList.some((c) => /^ant-/.test(c)))
                detectedUIFrameworks.push({ name: "Ant Design" });
              const bulmaLink = linkHrefs.find((h) => /bulma/i.test(h));
              if (
                classList.some((c) =>
                  /^(is-|has-|column|notification)/.test(c),
                ) &&
                bulmaLink
              ) {
                detectedUIFrameworks.push({
                  name: "Bulma",
                  version: bulmaLink ? extractVerFromUrl(bulmaLink) : null,
                });
              }

              const storageVulnerabilities = [];
              try {
                const checkStorage = (storageObj, storageName) => {
                  for (let i = 0; i < storageObj.length; i++) {
                    const key = storageObj.key(i);
                    const value = storageObj.getItem(key);
                    if (/(token|auth|jwt|secret|password|api_key)/i.test(key)) {
                      storageVulnerabilities.push(
                        `${storageName} içinde hassas anahtar: '${key}'`,
                      );
                    }
                    if (
                      value &&
                      /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/.test(
                        value,
                      )
                    ) {
                      if (
                        !storageVulnerabilities.some((v) => v.includes(key))
                      ) {
                        storageVulnerabilities.push(
                          `${storageName} ('${key}') içinde şifresiz JWT!`,
                        );
                      }
                    }
                  }
                };
                checkStorage(window.localStorage, "LocalStorage");
                checkStorage(window.sessionStorage, "SessionStorage");
              } catch (e) {}

              const formVulnerabilities = [];
              const forms = document.querySelectorAll("form");
              forms.forEach((f, index) => {
                const action = f.getAttribute("action");
                if (
                  action &&
                  action.trim().toLowerCase().startsWith("http://")
                ) {
                  formVulnerabilities.push(
                    `Form #${index + 1} güvensiz (HTTP) gönderim yapıyor!`,
                  );
                }
              });

              const hiddenInputs = [];
              document
                .querySelectorAll("input[type='hidden']")
                .forEach((inp) => {
                  if (inp.name || inp.id) {
                    let val = inp.value;
                    if (val.length > 25) val = val.substring(0, 25) + "...";
                    hiddenInputs.push(`${inp.name || inp.id}: ${val || "Boş"}`);
                  }
                });

              const suspiciousLinks = [];
              document.querySelectorAll("a").forEach((a) => {
                const href = a.getAttribute("href");
                if (
                  href &&
                  /(admin|login|dashboard|portal|cpanel|wp-admin|config|setup)/i.test(
                    href,
                  )
                ) {
                  if (!suspiciousLinks.includes(href))
                    suspiciousLinks.push(href);
                }
              });

              const devComments = [];
              try {
                const iterator = document.createNodeIterator(
                  document.documentElement,
                  NodeFilter.SHOW_COMMENT,
                  null,
                );
                let currentNode;
                while ((currentNode = iterator.nextNode())) {
                  const commentText = currentNode.nodeValue;
                  if (
                    /(todo|fixme|admin|pass|key|http|api)/i.test(commentText)
                  ) {
                    let cleanText = commentText.trim();
                    if (cleanText.length > 60)
                      cleanText = cleanText.substring(0, 60) + "...";
                    if (cleanText) devComments.push(cleanText);
                  }
                }
              } catch (e) {}

              return {
                jsFiles: scriptSrcs,
                detectedRiskyFunctions,
                detectedSecrets,
                storageVulnerabilities,
                formVulnerabilities,
                hiddenInputs,
                suspiciousLinks,
                devComments,
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

        const cspVulnerabilities = [];
        const cspHeader = securityHeaders["Content-Security-Policy"] || "";
        if (cspHeader !== "Eksik") {
          if (cspHeader.includes("unsafe-inline"))
            cspVulnerabilities.push(
              "CSP 'unsafe-inline' içeriyor (XSS riski).",
            );
          if (cspHeader.includes("unsafe-eval"))
            cspVulnerabilities.push(
              "CSP 'unsafe-eval' içeriyor (DOM tabanlı XSS riski).",
            );
          if (
            !cspHeader.includes("default-src") &&
            !cspHeader.includes("script-src")
          ) {
            cspVulnerabilities.push(
              "Temel kaynak kısıtlamaları (default-src/script-src) eksik.",
            );
          }
        }

        const corsVulnerabilities = [];
        if (headers["access-control-allow-origin"] === "*") {
          corsVulnerabilities.push(
            "CORS politikası çok gevşek (*). API verileri çalınabilir!",
          );
        }
        if (headers["x-powered-by"]) {
          corsVulnerabilities.push(
            `Sunucu teknolojisini sızdırıyor: ${headers["x-powered-by"]}`,
          );
        }

        let hiddenFiles = [];
        try {
          const robotsRes = await fetch(`${origin}/robots.txt`, {
            method: "HEAD",
            cache: "no-cache",
          });
          if (robotsRes.ok)
            hiddenFiles.push(`${origin}/robots.txt (Gizli dizinler olabilir)`);

          const secRes = await fetch(`${origin}/.well-known/security.txt`, {
            method: "HEAD",
            cache: "no-cache",
          });
          if (secRes.ok)
            hiddenFiles.push(
              `${origin}/.well-known/security.txt (Bug Bounty programı var!)`,
            );
        } catch (e) {}

        let detectedWAF = "Tespit Edilemedi / Korunmasız";
        const headerStr = JSON.stringify(headers).toLowerCase();
        if (headerStr.includes("cf-ray") || headerStr.includes("cloudflare"))
          detectedWAF = "Cloudflare";
        else if (headerStr.includes("x-sucuri")) detectedWAF = "Sucuri WAF";
        else if (
          headerStr.includes("x-amz-cf-id") ||
          headerStr.includes("awselb")
        )
          detectedWAF = "AWS WAF";
        else if (headerStr.includes("x-akamai")) detectedWAF = "Akamai";
        else if (headerStr.includes("bigip") || headerStr.includes("f5"))
          detectedWAF = "F5 BIG-IP";
        else if (
          headerStr.includes("imperva") ||
          headerStr.includes("incapsula")
        )
          detectedWAF = "Imperva Incapsula";

        sendResponse({
          url: site_url,
          securityHeaders,
          detectedWAF,
          riskyFunctions: resultData.detectedRiskyFunctions || [],
          leakedSecrets: resultData.detectedSecrets || [],
          storageVulnerabilities: resultData.storageVulnerabilities || [],
          formVulnerabilities: resultData.formVulnerabilities || [],
          hiddenInputs: resultData.hiddenInputs || [],
          suspiciousLinks: resultData.suspiciousLinks || [],
          devComments: resultData.devComments || [],
          corsVulnerabilities: corsVulnerabilities || [],
          hiddenFiles: hiddenFiles || [],
          mixedContent: resultData.mixedContentIssues || [],
          domainAnalysis: resultData.domainAnalysis || {},
          detectedFrameworks: resultData.detectedFrameworks || [],
          detectedUIFrameworks: resultData.detectedUIFrameworks || [],
          jsFiles: resultData.jsFiles || [],
          scriptStats: resultData.scriptStats || {},
          cspVulnerabilities: cspVulnerabilities,
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
    (async () => {
      try {
        const explanation = await getAIExplanation(message.data);
        sendResponse(explanation);
      } catch (error) {
        sendResponse("AI açıklaması alınamadı.");
      }
    })();
    return true;
  }
  if (message.action === "performance") {
    (async () => {
      try {
        const page_speed_scores = await pageSpeedScores(message.url);
        sendResponse(page_speed_scores);
      } catch (error) {
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
