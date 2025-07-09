importScripts("geminiAPI.js");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyze") {
    console.log("Analizlenen site:", message.url);

    const analysisResult = {
      url: message.url,
      securityHeaders: {
        "Content-Security-Policy": "Missing",
        "X-Frame-Options": "SAMEORIGIN",
        "Strict-Transport-Security": "Missing",
      },
      malwareScan: {
        status: "Unknown",
        score: 0,
      },
      cookies: {
        secure: false,
        httpOnly: false,
      },
      jsAnalysis: {
        riskyFunctions: ["eval", "document.write"],
      },
    };
    sendResponse(analysisResult);
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
});
