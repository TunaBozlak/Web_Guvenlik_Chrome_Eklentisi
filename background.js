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
      const headers = latestHeaders[message.url] || {};
      const securityHeaders = {
        "Content-Security-Policy": headers["content-security-policy"],
        "X-Frame-Options": headers["x-frame-options"],
        "Strict-Transport-Security": headers["strict-transport-security"],
      };
      //const malwareResult = await scanUrlWithVirusTotal(message.url);

      const site_url = message.url;
      let tabId = sender.tab ? sender.tab.id : null; // Mesajı gönderen sekmenin ID'sini al

      if (!tabId) {
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });
        tabId = tab.id;
      }

      const cookies = await chrome.cookies.getAll({ url: site_url });
      const jsAnalysis = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: () => {
          const scripts = Array.from(document.scripts);

          const inlineScriptsArray = scripts
            .filter((script) => !script.src)
            .map((script) => script.textContent || "");

          const riskyFunctions = [
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

          inlineScriptsArray.forEach((code) => {
            riskyFunctions.forEach((func) => {
              if (code.includes(func)) {
                if (!detectedRiskyFunctions.includes(func)) {
                  detectedRiskyFunctions.push(func);
                }
              }
            });
          });

          const externalScripts = scripts
            .map((script) => script.src)
            .filter((src) => src);

          return {
            externalScripts,
            detectedRiskyFunctions,
          };
        },
      });
      const frameworkAnalysis = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: () => {
          const detectedFrameworks = [];

          const scriptSrcs = Array.from(document.scripts)
            .map((s) => s.src || "")
            .filter(Boolean);

          const classList = Array.from(
            document.querySelectorAll("[class]")
          ).flatMap((el) => Array.from(el.classList));

          const devtoolHooks = {
            React: !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__,
            "Vue.js": !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__,
            Angular: !!window.__ANGULAR_DEVTOOLS_GLOBAL_HOOK__,
          };

          const scanCommentNodes = () => {
            const iterator = document.createNodeIterator(
              document,
              NodeFilter.SHOW_COMMENT,
              null,
              false
            );

            let currentNode;
            const found = {};
            while ((currentNode = iterator.nextNode())) {
              const text = currentNode.textContent;
              if (
                /react-empty|react-text|data-react-checksum|react-container/i.test(
                  text
                )
              )
                found["React"] = true;
              if (/vue-component|v-if|v-for|v-bind|v-on/i.test(text))
                found["Vue.js"] = true;
              if (/ng-/.test(text)) found["Angular"] = true;
            }
            return found;
          };

          const commentBased = scanCommentNodes();

          const knownFrameworks = [
            {
              name: "React",
              test: () =>
                (window.React &&
                  (typeof window.React.createElement === "function" ||
                    typeof window.ReactDOM === "object")) ||
                !!document.querySelector(
                  "[data-reactroot], #root, #app, [data-reactid], [data-react-checksum]"
                ) ||
                devtoolHooks["React"] ||
                commentBased["React"] ||
                classList.some(
                  (c) =>
                    c.startsWith("jsx-") ||
                    c.startsWith("react-") ||
                    c.includes("react-container")
                ) ||
                scriptSrcs.some(
                  (src) =>
                    /react|react-dom|next/i.test(src) &&
                    !/web-components/.test(src)
                ),
              version: () => window.React?.version || null,
            },
            {
              name: "Next.js",
              test: () =>
                !!window.__NEXT_DATA__ ||
                scriptSrcs.some((src) =>
                  /_next\/(static|webpack|client-script)/i.test(src)
                ) ||
                allFetchedUrls.some(
                  (url) =>
                    url.includes("_next/data") ||
                    url.includes("_next/webpack-hmr")
                ) ||
                moduleScriptContents.some(
                  (content) =>
                    content.includes("next.config") ||
                    content.includes("webpackHotUpdate")
                ),
              version: () => window.__NEXT_DATA__?.buildId || null,
            },
            {
              name: "Angular",
              test: () =>
                (window.angular && window.angular.version) ||
                !!document.querySelector(
                  "[ng-app], [data-ng-app], .ng-scope, [ng-version], [_ngcontent-], [_nghost-] "
                ) ||
                devtoolHooks["Angular"] ||
                commentBased["Angular"] ||
                scriptSrcs.some(
                  (src) =>
                    /angular|zone\.js|polyfills|main\.js/i.test(src) &&
                    !/angularjs\.org/.test(src)
                ),
              version: () =>
                window.angular?.version?.full ||
                document
                  .querySelector("[ng-version]")
                  ?.getAttribute("ng-version") ||
                null,
            },
            {
              name: "Vue.js",
              test: () =>
                (window.Vue &&
                  (typeof window.Vue.version === "string" ||
                    typeof window.Vue.createApp === "function")) ||
                !!document.querySelector(
                  "[data-v-app], #app, [data-vue-router-initialized]"
                ) ||
                devtoolHooks["Vue.js"] ||
                commentBased["Vue.js"] ||
                classList.some(
                  (c) => c.startsWith("v-") || c.startsWith("vue-")
                ) ||
                scriptSrcs.some((src) => /vue|vue-router|vuex/i.test(src)),
              version: () => window.Vue?.version || null,
            },
            {
              name: "Nuxt.js",
              test: () =>
                scriptSrcs.some((src) =>
                  /_nuxt\/(build|manifest)/i.test(src)
                ) ||
                !!window.__NUXT__ ||
                allFetchedUrls.some((url) => url.includes("_nuxt")),
              version: () => window.__NUXT__?.version || null,
            },
            {
              name: "jQuery",
              test: () =>
                window.jQuery ||
                (typeof $ === "function" &&
                  typeof $.fn === "object" &&
                  typeof $.fn.jquery === "string") ||
                scriptSrcs.some(
                  (src) =>
                    /jquery(\.min)?\.js/i.test(src) ||
                    src.includes("/ajax/libs/jquery/")
                ),
              version: () => window.jQuery?.fn?.jquery || null,
            },
            {
              name: "Svelte",
              test: () =>
                !!document.querySelector(
                  "[data-svelte-h], [data-sveltekit-prefetch], [data-sveltekit-route]"
                ) ||
                classList.some((c) => c.startsWith("svelte-")) ||
                scriptSrcs.some((src) => /svelte(\.min)?\.js/i.test(src)),
              version: () => {
                const svelteScript = scriptSrcs.find((src) =>
                  /svelte/i.test(src)
                );
                if (svelteScript) {
                  return null;
                }
                return null;
              },
            },
            {
              name: "Alpine.js",
              test: () =>
                !!document.querySelector(
                  "[x-data], [x-bind], [x-on], [x-for], [x-model], [x-init]"
                ) || scriptSrcs.some((src) => /alpine(\.min)?\.js/i.test(src)),
              version: () => window.Alpine?.version || null,
            },
            {
              name: "Ember.js",
              test: () =>
                window.Ember ||
                scriptSrcs.some((src) => /ember(\.min)?\.js/i.test(src)) ||
                !!document.querySelector('[id^="ember"]'),
              version: () => window.Ember?.VERSION || null,
            },
            {
              name: "WordPress",
              test: () => {
                const meta = document.querySelector('meta[name="generator"]');
                const hasMeta =
                  meta && meta.content.toLowerCase().includes("wordpress");
                const hasPaths = [...scriptSrcs].some((src) =>
                  /wp-(content|includes|admin)|themes\//i.test(src)
                );
                const hasClass =
                  document.body.className.includes("wp-") ||
                  classList.some((c) => c.startsWith("wp-"));
                const hasRestApi = allFetchedUrls.some(
                  (url) =>
                    url.includes("/wp-json/") || url.includes("?rest_route=")
                );
                const hasWpObject = !!window.wp;
                return (
                  hasMeta || hasPaths || hasClass || hasRestApi || hasWpObject
                );
              },
              version: () => {
                const meta = document.querySelector('meta[name="generator"]');
                if (meta && meta.content.includes("WordPress")) {
                  const match = meta.content.match(
                    /WordPress (\d+\.\d+(\.\d+)?)/
                  );
                  return match ? match[1] : null;
                }
                return null;
              },
            },
            {
              name: "Preact",
              test: () =>
                !!window.preact ||
                scriptSrcs.some((src) => /preact(\.min)?\.js/i.test(src)),
              version: () => window.preact?.version || null,
            },
            {
              name: "Qwik",
              test: () =>
                !!window.qwikSymbols ||
                scriptSrcs.some((src) => /qwik(\.min)?\.js/i.test(src)) ||
                allFetchedUrls.some((url) => url.includes("/qwik/")),
              version: () => null,
            },
            {
              name: "Astro",
              test: () =>
                classList.some((c) => c.includes("astro")) ||
                scriptSrcs.some(
                  (src) => /astro\.(m)?js/i.test(src) || src.includes("_astro/")
                ) ||
                !!document.querySelector("script[data-astro-cid]"),
              version: () => null,
            },
            {
              name: "Inferno",
              test: () =>
                window.Inferno !== undefined ||
                scriptSrcs.some((src) => /inferno(\.min)?\.js/i.test(src)),
              version: () => window.Inferno?.version || null,
            },
          ];
          knownFrameworks.forEach(({ name, test, version }) => {
            try {
              if (test() && !detectedFrameworks.includes(name)) {
                detectedFrameworks.push({
                  name,
                  version: version ? version() : null,
                });
              }
            } catch (err) {
              console.warn(`Framework tespit hatası: ${name}`, err);
            }
          });
          return { detectedFrameworks };
        },
      });

      const uiResult = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: () => {
          const classList = Array.from(
            document.querySelectorAll("[class]")
          ).flatMap((el) => Array.from(el.classList));

          const linkHrefs = Array.from(
            document.querySelectorAll("link[href]")
          ).map((l) => l.href);

          const detectedUIFrameworks = [];

          const uiFrameworks = [
            {
              name: "Tailwind CSS",
              test: () =>
                classList.filter((c) =>
                  /^(tw-|text|bg|p[trblxy]?|m[trblxy]?|rounded|shadow|flex|grid|items|justify|w-|h-)/.test(
                    c
                  )
                ).length >= 5,
            },

            {
              name: "Bootstrap",
              test: () =>
                classList.some((c) =>
                  /^(container|row|col|btn|navbar|alert|card)/.test(c)
                ),
            },
            {
              name: "Material UI (MUI)",
              test: () => classList.some((c) => /^Mui[A-Z]/.test(c)),
            },
            {
              name: "Bulma",
              test: () =>
                classList.some((c) =>
                  /^(columns|column|notification|is-)/.test(c)
                ),
            },
            {
              name: "Foundation",
              test: () =>
                classList.some((c) => /^(grid-|button-group|callout)/.test(c)),
            },
            {
              name: "Ant Design",
              test: () => classList.some((c) => /^ant-/.test(c)),
            },
            {
              name: "Chakra UI",
              test: () =>
                classList.some((c) => /^css-[a-z0-9]{4,}$/.test(c)) &&
                !!document.querySelector("[data-theme]"),
            },
            {
              name: "PrimeFlex",
              test: () =>
                classList.some((c) =>
                  /^(p-|pi-|p-d|p-m|p-p|p-grid|p-col)/.test(c)
                ),
            },
            {
              name: "UIkit",
              test: () => classList.some((c) => /^uk-/.test(c)),
            },
            {
              name: "Shoelace",
              test: () =>
                !!document.querySelector("sl-button, sl-input, sl-dialog"),
            },
            {
              name: "Carbon Design",
              test: () => classList.some((c) => /^bx--/.test(c)),
            },
          ];

          uiFrameworks.forEach(({ name, test }) => {
            try {
              if (test() && !detectedUIFrameworks.includes(name)) {
                detectedUIFrameworks.push(name);
              }
            } catch (err) {
              console.warn(`UI framework tespiti hatası: ${name}`, err);
            }
          });

          if (
            linkHrefs.some((href) =>
              /uikit|foundation|bulma|tailwind|bootstrap/i.test(href)
            )
          ) {
            if (
              linkHrefs.some((href) => /uikit/i.test(href)) &&
              !detectedUIFrameworks.includes("UIkit")
            ) {
              detectedUIFrameworks.push("UIkit");
            }
            if (
              linkHrefs.some((href) => /foundation/i.test(href)) &&
              !detectedUIFrameworks.includes("Foundation")
            ) {
              detectedUIFrameworks.push("Foundation");
            }
            if (
              linkHrefs.some((href) => /bulma/i.test(href)) &&
              !detectedUIFrameworks.includes("Bulma")
            ) {
              detectedUIFrameworks.push("Bulma");
            }
            if (
              linkHrefs.some((href) => /tailwind/i.test(href)) &&
              !detectedUIFrameworks.includes("Tailwind CSS")
            ) {
              detectedUIFrameworks.push("Tailwind CSS");
            }
            if (
              linkHrefs.some((href) => /bootstrap/i.test(href)) &&
              !detectedUIFrameworks.includes("Bootstrap")
            ) {
              detectedUIFrameworks.push("Bootstrap");
            }
          }
          return { detectedUIFrameworks };
        },
      });

      const analysisResult = {
        url: site_url,
        securityHeaders,
        riskyFunctions: jsAnalysis[0].result.detectedRiskyFunctions,
        detectedFrameworks: frameworkAnalysis[0].result.detectedFrameworks,
        detectedUIFrameworks: uiResult[0].result.detectedUIFrameworks,
        jsFiles: jsAnalysis[0].result.externalScripts,
        cookies,
        malwareScan: { state: "geçici" }, //malwareResult,
      };
      sendResponse(analysisResult);
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
