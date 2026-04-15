import { drawChart } from "./chart.js";
import { deleteAnalysis } from "./delete.js";
import { downloadPdf } from "./download.js";

const history_div = document.getElementById("history");

export const saveAnalysisHistory = (result) => {
  chrome.storage.local.get("history", (data) => {
    const history = data.history || [];
    history.unshift({
      date: new Date().toLocaleString("tr-TR"),
      timestamp: Date.now(),
      result,
    });

    chrome.storage.local.set({ history });
    displayHistory();
  });
};

export const displayHistory = (
  start_date = null,
  end_date = null,
  selected_type = null,
) => {
  chrome.storage.local.get("history", (data) => {
    history_div.innerHTML = "";
    const history = data.history || [];

    const filtered_history = history.filter((entry) => {
      let dateMatch = true;
      let typeMatch = true;

      if (start_date && end_date) {
        const entryTime = entry.timestamp || new Date(entry.date).getTime();

        if (!isNaN(entryTime)) {
          dateMatch =
            entryTime >= start_date.getTime() &&
            entryTime <= end_date.getTime();
        } else {
          dateMatch = false;
        }
      }
      if (selected_type) {
        typeMatch = entry.result?.type === selected_type;
      }
      return dateMatch && typeMatch;
    });

    if (filtered_history.length === 0) {
      history_div.innerHTML = `<div style="text-align:center; color:var(--text-secondary); padding:20px;">Geçmiş kaydı bulunamadı.</div>`;
      drawChart([]);
      return;
    }

    drawChart(filtered_history);

    filtered_history.forEach((entry, index) => {
      const item = document.createElement("div");
      item.classList.add("history-item");

      const header = document.createElement("div");
      header.classList.add("history-header");

      const infoDiv = document.createElement("div");
      infoDiv.classList.add("history-info");

      const domain = entry.result?.site || "Bilinmeyen Site";
      const isPerformance = entry.result?.type === "performance";

      let scoreHtml = "";
      let scoreVal = 0;

      if (!isPerformance && entry.result?.securityScore !== undefined) {
        scoreVal = entry.result.securityScore;
      } else if (isPerformance && entry.result?.pageSpeed) {
        const ps = entry.result.pageSpeed;
        const scores = [
          ps.performance,
          ps.accessibility,
          ps.bestPractices,
          ps.seo,
        ].filter((v) => typeof v === "number");
        scoreVal = scores.length
          ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
          : 0;
      }

      const scoreColor =
        scoreVal >= 80 ? "#10b981" : scoreVal >= 50 ? "#f59e0b" : "#ef4444";

      infoDiv.innerHTML = `
        <div class="history-domain">
          ${domain} 
          <span style="font-weight:normal; font-size:11px; margin-left:4px; opacity:0.8;">
            (${isPerformance ? "Performans" : "Güvenlik"})
          </span>
        </div>
        <div class="history-meta">
          <span>📅 ${entry.date}</span>
          <span style="color:${scoreColor}; font-weight:700; border:1px solid ${scoreColor}33; padding:1px 6px; border-radius:4px; font-size:10px;">
            ${scoreVal} Puan
          </span>
        </div>
      `;

      const actionsDiv = document.createElement("div");
      actionsDiv.classList.add("history-actions");

      const pdfBtn = document.createElement("button");
      pdfBtn.className = "btn-icon-small";
      pdfBtn.innerHTML = "⬇";
      pdfBtn.title = "Raporu İndir";
      pdfBtn.onclick = (e) => {
        e.stopPropagation();
        downloadPdf(entry.result, entry.result.site);
      };

      const delBtn = document.createElement("button");
      delBtn.className = "btn-icon-small delete";
      delBtn.innerHTML = "🗑";
      delBtn.title = "Kaydı Sil";
      delBtn.onclick = (e) => {
        e.stopPropagation();
        deleteAnalysis(index);
      };

      const arrow = document.createElement("span");
      arrow.innerHTML = "&#9660;";
      arrow.style.fontSize = "10px";
      arrow.style.color = "var(--text-secondary)";
      arrow.style.marginLeft = "4px";

      actionsDiv.appendChild(pdfBtn);
      actionsDiv.appendChild(delBtn);
      actionsDiv.appendChild(arrow);

      header.appendChild(infoDiv);
      header.appendChild(actionsDiv);
      item.appendChild(header);

      const details = document.createElement("div");
      details.classList.add("history-details");
      details.style.display = "none";
      details.innerHTML = `<pre style="white-space: pre-wrap; word-wrap: break-word; font-family:monospace;">${JSON.stringify(
        entry.result,
        null,
        2,
      )}</pre>`;

      item.appendChild(details);

      header.addEventListener("click", () => {
        const isHidden = details.style.display === "none";
        details.style.display = isHidden ? "block" : "none";
        arrow.innerHTML = isHidden ? "&#9650;" : "&#9660;";
      });

      history_div.appendChild(item);
    });
  });
};
displayHistory();
