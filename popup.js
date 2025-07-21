import { pageSpeedScores } from "./performance.js";
import { analyzeSecurityStatus, calculateSecurityScore } from "./security.js";
import { createCard } from "./card.js";
import { filterComponent } from "./filter.js";
import { deleteHistory } from "./delete.js";
import { saveAnalysisHistory } from "./history.js";
import { changeTheme } from "./theme.js";
import { downloadPdf } from "./download.js";

document.addEventListener("DOMContentLoaded", () => {
  const analysis_button = document.getElementById("analysis_button");
  const download_button = document.getElementById("download_pdf");
  const ai_button = document.getElementById("ai_button");
  const performance_button = document.getElementById("performance_button");
  const loading = document.getElementById("loading");
  const loading_explanation = document.getElementById("loading-explanation");
  const results_content = document.getElementById("results-content");
  const explanation_content = document.getElementById("explanation-content");

  const performSecurityAnalysis = async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    results_content.innerHTML = "";
    explanation_content.innerText = "";
    download_button.disabled = true;
    ai_button.disabled = true;

    loading.style.display = "block";

    chrome.scripting.executeScript(
      {
        target: { tabId: tab.id },
        function: () => window.location.href,
      },
      async (results) => {
        const site_url = results[0].result;
        console.log("Analizlenen site:", site_url);

        const response = await chrome.runtime.sendMessage({
          action: "analyze",
          url: site_url,
        });

        const cookies = await chrome.cookies.getAll({ url: site_url });
        response.cookies = cookies;

        const jsAnalysis = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            const scripts = Array.from(document.scripts);

            const inlineScripts = scripts
              .filter((script) => !script.src)
              .map((script) => script.textContent || "");

            const riskyFunctions = [
              "eval",
              "document.write",
              "Function",
              "setTimeout",
              "setInterval",
            ];
            const detectedRiskyFunctions = [];

            inlineScripts.forEach((code) => {
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

            const apiUrls = [];
            document.querySelectorAll("a[href]").forEach((el) => {
              const href = el.href;
              if (href.includes("/api/")) apiUrls.push(href);
            });

            const allScriptContent = inlineScripts.join("\n");
            const fetchMatches = allScriptContent.match(
              /["'`](https?:\/\/[^"'`]*\/api\/[^"'`]*)["'`]/gi
            );
            if (fetchMatches) {
              fetchMatches.forEach((url) => {
                const cleanUrl = url.replace(/^['"`]|['"`]$/g, "");
                if (!apiUrls.includes(cleanUrl)) apiUrls.push(cleanUrl);
              });
            }

            return {
              externalScripts,
              detectedRiskyFunctions,
              apiUrls,
            };
          },
        });
        response.jsFiles = jsAnalysis[0].result.externalScripts;
        response.riskyFunctions = jsAnalysis[0].result.detectedRiskyFunctions;

        const frameworkAnalysis = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            const detectedFrameworks = [];

            const scriptSrcs = Array.from(document.scripts)
              .map((s) => s.src || "")
              .filter(Boolean);

            const linkHrefs = Array.from(
              document.querySelectorAll("link[href]")
            ).map((l) => l.href);

            const fetchUrls = [];
            const classList = Array.from(
              document.querySelectorAll("[class]")
            ).flatMap((el) => Array.from(el.classList));

            const originalFetch = window.fetch;
            if (originalFetch) {
              window.fetch = function (...args) {
                try {
                  fetchUrls.push(args[0]);
                } catch {}

                return originalFetch.apply(this, args);
              };
            }

            const devtoolHooks = {
              React: !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__,
              "Vue.js": !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__,
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
                if (/react/i.test(text)) found["React"] = true;
                if (/vue|v-if|v-for/.test(text)) found["Vue.js"] = true;
              }
              return found;
            };

            const commentBased = scanCommentNodes();

            const knownFrameworks = [
              {
                name: "React",
                test: () =>
                  window.React ||
                  !!document.querySelector("[data-reactroot], #root, #app") ||
                  devtoolHooks["React"] ||
                  commentBased["React"] ||
                  classList.some((c) => c.startsWith("jsx-")) ||
                  scriptSrcs.some((src) => /react/i.test(src)),
              },
              {
                name: "Next.js",
                test: () =>
                  !!window.__NEXT_DATA__ ||
                  scriptSrcs.some((src) => src.includes("_next")) ||
                  fetchUrls.some((url) => url.includes("_next/data")),
              },
              {
                name: "Angular",
                test: () =>
                  window.angular ||
                  !!document.querySelector(
                    "[ng-app], [data-ng-app], .ng-scope"
                  ) ||
                  scriptSrcs.some((src) => /angular/i.test(src)),
              },
              {
                name: "Vue.js",
                test: () =>
                  window.Vue ||
                  !!document.querySelector("[data-v-app], #app") ||
                  devtoolHooks["Vue.js"] ||
                  commentBased["Vue.js"] ||
                  classList.some((c) => c.startsWith("v-")) ||
                  scriptSrcs.some((src) => /vue/i.test(src)),
              },
              {
                name: "Nuxt.js",
                test: () =>
                  scriptSrcs.some((src) => src.includes("_nuxt")) ||
                  !!window.__NUXT__ ||
                  fetchUrls.some((url) => url.includes("_nuxt")),
              },
              {
                name: "jQuery",
                test: () =>
                  window.jQuery ||
                  typeof $ === "function" ||
                  scriptSrcs.some((src) => /jquery/i.test(src)),
              },
              {
                name: "Svelte",
                test: () =>
                  !!document.querySelector("[data-svelte-h]") ||
                  classList.some((c) => c.startsWith("svelte-")) ||
                  scriptSrcs.some((src) => /svelte/i.test(src)),
              },
              {
                name: "Alpine.js",
                test: () =>
                  !!document.querySelector("[x-data]") ||
                  scriptSrcs.some((src) => /alpine/i.test(src)),
              },
              {
                name: "Ember.js",
                test: () =>
                  window.Ember ||
                  scriptSrcs.some((src) => /ember/i.test(src)) ||
                  !!document.querySelector('[id^="ember"]'),
              },
              {
                name: "WordPress",
                test: () => {
                  const meta = document.querySelector('meta[name="generator"]');
                  const hasMeta =
                    meta && meta.content.toLowerCase().includes("wordpress");
                  const hasPaths = [...scriptSrcs, ...linkHrefs].some((src) =>
                    /wp-(content|includes)/i.test(src)
                  );

                  const hasClass =
                    document.body.className.includes("wp-") ||
                    classList.some((c) => c.startsWith("wp-"));
                  const hasRestApi = fetchUrls.some((url) =>
                    url.includes("/wp-json/")
                  );
                  return hasMeta || hasPaths || hasClass || hasRestApi;
                },
              },
            ];
            knownFrameworks.forEach(({ name, test }) => {
              try {
                if (test() && !detectedFrameworks.includes(name)) {
                  detectedFrameworks.push(name);
                }
              } catch (err) {
                console.warn(`Framework tespit hatası: ${name}`, err);
              }
            });
            return { detectedFrameworks };
          },
        });

        const uiResult = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
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
                  classList.some((c) =>
                    /^(grid-|button-group|callout)/.test(c)
                  ),
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

        response.detectedFrameworks =
          frameworkAnalysis[0].result.detectedFrameworks;
        console.log("Tespit edilen Çerçeveler", response.detectedFrameworks);

        response.detectedUIFrameworks = uiResult[0].result.detectedUIFrameworks;
        console.log(
          "Tespit edilen CSS Çerçeveleri",
          response.detectedUIFrameworks
        );

        const apiUrls = jsAnalysis[0].result.apiUrls;
        console.log("Bulunan API endpoint'leri:", apiUrls);

        if (apiUrls.length > 0) {
          const apiAnalysis = await chrome.runtime.sendMessage({
            action: "analyzeApiEndpoints",
            endpoints: apiUrls,
          });

          response.apiSecurityAnalysis = apiAnalysis.apiSecurity;
        }

        const statuses = analyzeSecurityStatus(response, site_url);

        loading.style.display = "none";

        Object.entries(statuses).forEach(([title, status]) => {
          const card = createCard(title, status);
          results_content.appendChild(card);
        });

        const apiHeader = document.createElement("h3");
        apiHeader.textContent = "API Endpoint Güvenlik Analizi";
        apiHeader.style.marginTop = "20px";
        results_content.appendChild(apiHeader);
        if (
          response.apiSecurityAnalysis &&
          Object.keys(response.apiSecurityAnalysis).length > 0
        ) {
          Object.entries(response.apiSecurityAnalysis).forEach(
            ([endpoint, analysis]) => {
              const card = document.createElement("div");
              card.classList.add("api-card");
              card.style.fontFamily =
                "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
              const title = document.createElement("div");
              title.innerHTML = `<strong style="font-size: 1.1em; color: #333;">Endpoint:</strong> 
              <span style="color: #007acc;">${endpoint}</span>`;
              title.style.marginBottom = "12px";
              card.appendChild(title);
              const analysisList = document.createElement("ul");
              analysisList.classList.add("api-ul");
              Object.entries(analysis).forEach(([key, value]) => {
                const li = document.createElement("li");
                li.style.marginBottom = "6px";
                if (typeof value === "object" && value !== null) {
                  li.innerHTML =
                    `<strong style="color: #222;">${key}:</strong>
                    <ul style="margin-top: 6px; margin-left: 18px; padding-left: 0; list-style-type: disc;">` +
                    Object.entries(value)
                      .map(
                        ([subKey, subVal]) =>
                          `<li style="list-style-type: circle; margin-bottom: 4px; color: #555;">${subKey}: 
                        <span style="font-weight: 600;">${
                          subVal ?? "Yok"
                        }</span></li>`
                      )
                      .join("") +
                    `</ul>`;
                } else {
                  li.innerHTML = `<strong style="color: #222;">${key}:</strong> 
                  <span style="font-weight: 600;">${value}</span>`;
                }
                analysisList.appendChild(li);
              });
              card.appendChild(analysisList);
              results_content.appendChild(card);
            }
          );
        } else {
          const noApiText = document.createElement("p");
          noApiText.textContent =
            "Bu sitede analiz edilebilecek API endpointi bulunamadı.";
          noApiText.style.color = "#555";
          noApiText.style.marginTop = "10px";
          results_content.appendChild(noApiText);
        }

        const frameworkHeader = document.createElement("h3");
        frameworkHeader.textContent = "Tespit Edilen Teknolojiler";
        frameworkHeader.style.marginTop = "20px";
        results_content.appendChild(frameworkHeader);

        if (
          response.detectedFrameworks &&
          response.detectedFrameworks.length > 0
        ) {
          const ul = document.createElement("ul");
          ul.style.listStyleType = "none";
          ul.style.paddingLeft = "0";
          response.detectedFrameworks.forEach((framework) => {
            const li = document.createElement("li");
            li.style.marginBottom = "5px";
            li.style.fontSize = "1.1em";
            li.innerHTML = `✨ <span style="font-weight: bold; color: #4CAF50;">${framework}</span>`;
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
            li.innerHTML = `🎨 <span style="font-weight: bold; color: #007bff;">${kit}</span>`;
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
        title.innerHTML =
          "<strong>Analiz Raporu</strong> <span style='float:right;'>&#9660;</span>";
        item.appendChild(title);

        const arrow = title.querySelector("span");
        item.addEventListener("click", () => {
          details.style.display =
            details.style.display === "none" ? "block" : "none";
          arrow.innerHTML =
            details.style.display === "none" ? "&#9660;" : "&#9650;";
        });

        const details = document.createElement("div");
        details.style.display = "none";
        details.style.marginTop = "8px";
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
        saveAnalysisHistory({ site: domain, type: "security", ...response });

        downloadPdf(response, site_url);

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
      }
    );
  };

  const performPerformanceTest = async () => {
    results_content.innerHTML = "";
    explanation_content.innerText = "";
    download_button.disabled = true;
    ai_button.disabled = true;

    loading.style.display = "block";

    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.scripting.executeScript(
      {
        target: { tabId: tab.id },
        function: () => window.location.href,
      },
      async (results) => {
        const site_url = results[0].result;
        console.log("Performans testi yapılan site:", site_url);

        const page_speed_scores = await pageSpeedScores(site_url);

        loading.style.display = "none";

        if (!page_speed_scores) {
          results_content.innerHTML = "<p>Performans skorları alınamadı.</p>";
          return;
        }

        const performance_statuses = {};
        const map_status = (score) => {
          if (score >= 90) return "safe";
          if (score >= 50) return "warning";
          return "danger";
        };

        performance_statuses["Performans"] = map_status(
          page_speed_scores.performance
        );
        performance_statuses["Erişilebilirlik"] = map_status(
          page_speed_scores.accessibility
        );
        performance_statuses["En İyi Uygulamalar"] = map_status(
          page_speed_scores.bestPractices
        );
        performance_statuses["SEO"] = map_status(page_speed_scores.seo);

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
        title.innerHTML =
          "<strong>Performans Raporu</strong> <span style='float:right;'>&#9660;</span>";
        item.appendChild(title);

        const arrow = title.querySelector("span");
        item.addEventListener("click", () => {
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

        downloadPdf(page_speed_scores, site_url);

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
      }
    );
  };

  analysis_button.addEventListener("click", performSecurityAnalysis);
  performance_button.addEventListener("click", performPerformanceTest);

  filterComponent();
  deleteHistory();
  changeTheme();
});
