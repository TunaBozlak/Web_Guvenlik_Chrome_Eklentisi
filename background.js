import { getAIExplanation } from "./geminiAPI.js";
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

      const analysisResult = {
        url: message.url,
        securityHeaders,
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

  if (message.action === "analyzeApiEndpoints") {
    sendResponse({ endpoints: detectedApiCalls });
    detectedApiCalls = [];
    return true;
  }
});
