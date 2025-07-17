import { analyzeSecurityStatus, calculateSecurityScore } from "./security.js";

export const drawChart = (trendData) => {
  const ctx = document.getElementById("chart").getContext("2d");
  if (window.trendChartInstance) {
    window.trendChartInstance.destroy();
  }
  const labels = [];
  const performanceData = [];
  const securityData = [];
  trendData.forEach((entry) => {
    const dateString = entry.date;
    labels.push(dateString);
    if (entry.result.type === "performance") {
      const s = entry.result.pageSpeed;
      const score = Math.round(
        (s.performance + s.accessibility + s.bestPractices + s.seo) / 4
      );
      performanceData.push(score);
      securityData.push(null);
    } else {
      const score = calculateSecurityScore(
        analyzeSecurityStatus(entry.result, entry.result.site)
      );
      securityData.push(score);
      performanceData.push(null);
    }
  });
  window.trendChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Performans Skoru",
          data: performanceData,
          borderColor: "blue",
          backgroundColor: "rgba(0,0,255,0.1)",
          borderWidth: 2,
          stack: "Stack 0",
        },
        {
          label: "     Güvenlik Skoru",
          data: securityData,
          borderColor: "green",
          backgroundColor: "rgba(0,128,0,0.1)",
          borderWidth: 2,
          stack: "Stack 0",
        },
      ],
    },
    options: {
      responsive: true,
      interaction: {
        mode: "point",
        intersect: true,
      },
      plugins: {
        legend: {
          labels: {
            color: "#222",
            font: { size: 13, weight: "bold" },
          },
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              const index = context.dataIndex;
              const score = context.raw;
              const entry = trendData[index];
              const site = entry?.result?.site || "Bilinmeyen Site";
              const type =
                entry.result?.type === "performance"
                  ? "Performans"
                  : "Güvenlik";
              return [`${type} Skoru: ${score}`, `${site}`];
            },
          },
        },
      },
      scales: {
        x: {
          display: false,
        },
        y: {
          beginAtZero: true,
          max: 100,
        },
      },
    },
  });
};
