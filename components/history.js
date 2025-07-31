import { drawChart } from "./chart.js";
import { deleteAnalysis } from "./delete.js";
import { downloadPdf } from "./download.js";

const history_div = document.getElementById("history");

export const saveAnalysisHistory = (result) => {
  chrome.storage.local.get("history", (data) => {
    const history = data.history || [];
    history.unshift({
      date: new Date().toLocaleString(),
      result,
    });

    chrome.storage.local.set({ history });
    displayHistory();
  });
};

export const displayHistory = (start_date = null, end_date = null) => {
  chrome.storage.local.get("history", (data) => {
    history_div.innerHTML = "";
    const history = data.history || [];

    const filtered_history = history.filter((entry) => {
      if (!start_date || !end_date) {
        return true;
      }

      const dateString = entry.date;
      const [datePart, timePart] = dateString.split(" ");
      const [day, month, year] = datePart.split(".").map(Number);
      const [hour, minute, second] = timePart.split(":").map(Number);
      const entry_date = new Date(year, month - 1, day, hour, minute, second);

      if (isNaN(entry_date.getTime())) {
        console.warn(
          "Geçersiz tarih formatı algılandı (manuel parse sonrası):",
          entry.date
        );
        return false;
      }
      return entry_date >= start_date && entry_date <= end_date;
    });

    if (filtered_history.length === 0) {
      history_div.innerHTML = "Geçmiş Boş";
      drawChart([]);
      return;
    }

    drawChart(filtered_history);

    filtered_history.forEach((entry, index) => {
      const item = document.createElement("div");
      item.classList.add("item");

      const header = document.createElement("div");
      header.style.display = "flex";
      header.style.justifyContent = "space-between";
      header.style.alignItems = "center";

      const leftPart = document.createElement("div");
      const domain = entry.result?.site || "Bilinmeyen Site";
      const type =
        entry.result?.type === "performance" ? " (Performans)" : " (Güvenlik)";
      leftPart.innerHTML = `
          <div style="font-weight: bold;">${domain}${type}</div>
          <div style="font-size: 12px; color: gray;">${entry.date}</div>
        `;

      const rightPart = document.createElement("div");
      rightPart.style.display = "flex";
      rightPart.style.alignItems = "center";
      rightPart.style.gap = "8px";

      const arrow = document.createElement("span");
      arrow.innerHTML = "&#9660;";

      const analysis_delete_button = document.createElement("button");
      analysis_delete_button.textContent = "Sil";
      analysis_delete_button.classList.add("analysis-delete-button");
      analysis_delete_button.onclick = (e) => {
        e.stopPropagation();
        deleteAnalysis(index);
      };

      const download_button = document.createElement("button");
      download_button.textContent = "PDF";
      download_button.classList.add("history-pdf-button");
      download_button.addEventListener("click", () => {
        downloadPdf(entry.result, entry.result.site);
      });
      rightPart.appendChild(download_button);

      rightPart.appendChild(analysis_delete_button);
      rightPart.appendChild(arrow);
      header.appendChild(leftPart);
      header.appendChild(rightPart);
      item.appendChild(header);

      const details = document.createElement("div");
      details.style.display = "none";
      details.style.marginTop = "8px";
      details.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word;">${JSON.stringify(
        entry.result,
        null,
        2
      )}</pre>`;
      item.appendChild(details);

      item.addEventListener("click", () => {
        details.style.display =
          details.style.display === "none" ? "block" : "none";
        arrow.innerHTML =
          details.style.display === "none" ? "&#9660;" : "&#9650;";
      });

      history_div.appendChild(item);
    });
  });
};
displayHistory();
