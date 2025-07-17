import { API_KEY_PAGE_SPEED } from "./config.js";

export const pageSpeedScores = async (site_url) => {
  const api_key = API_KEY_PAGE_SPEED;
  const api_url = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(
    site_url
  )}&key=${api_key}&category=performance&category=accessibility&category=best-practices&category=seo`;

  try {
    const response = await fetch(api_url);
    const data = await response.json();

    if (!data.lighthouseResult || !data.lighthouseResult.categories) {
      console.error("PageSpeed API'dan beklenen veri gelmedi:", data);
      return null;
    }

    const categories = data.lighthouseResult.categories;
    return {
      performance: Math.round(categories.performance.score * 100),
      accessibility: Math.round(categories.accessibility.score * 100),
      bestPractices: Math.round(categories["best-practices"].score * 100),
      seo: Math.round(categories.seo.score * 100),
    };
  } catch (error) {
    console.error("PageSpeed API hatası:", error);
    return null;
  }
};
