import { API_KEY_GEMINI } from "./config.js";

const api_key = API_KEY_GEMINI;
export const getAIExplanation = async (analysisData) => {
  const api_url =
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" +
    api_key;
  const prompt = `
  Şu analiz verilerini incele ve Türkçe olarak basit, anlaşılır bir açıklama yaz:
  ${JSON.stringify(analysisData, null, 2)}
  Ayrıca öneriler ver.
  `;
  const body = {
    contents: [{ parts: [{ text: prompt }] }],
  };
  try {
    const response = await fetch(api_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      console.error("Yanıt başarısız:", response.status, response.statusText);
      return "API isteği başarısız: " + response.status;
    }
    const result = await response.json();
    if (
      result &&
      result.candidates &&
      result.candidates.length > 0 &&
      result.candidates[0].content &&
      result.candidates[0].content.parts &&
      result.candidates[0].content.parts.length > 0
    ) {
      const explanation = result.candidates[0].content.parts[0].text;
      return explanation;
    } else {
      console.warn("Beklenmeyen API yanıtı yapısı:", result);
      return "AI açıklaması alınamadı.";
    }
  } catch (error) {
    console.error("fetch hatası:", error);
    return "fetch hatası: " + error.message;
  }
};
