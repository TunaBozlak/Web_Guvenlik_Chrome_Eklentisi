document.addEventListener("DOMContentLoaded", () => {
  const theme_button = document.getElementById("change_theme");
  const analysis_button = document.getElementById("analysis_button");
  const results_div = document.getElementById("results");
  const download_button = document.getElementById("download_pdf");
  const ai_button = document.getElementById("ai_button");
  const history_div = document.getElementById("history");
  const clear_history_button = document.getElementById("delete_history");
  const explanation_div = document.getElementById("explanation");

  download_button.disabled = true;
  ai_button.disabled = true;

  theme_button.addEventListener("click", async () => {
    document.body.classList.toggle("dark");
    const is_dark = document.body.classList.contains("dark");
    await chrome.storage.local.set({ theme: is_dark ? "dark" : "light" });
  });

  chrome.storage.local.get("theme", (data) => {
    if (data.theme === "dark") {
      document.body.classList.add("dark");
    }
  });

  analysis_button.addEventListener("click", async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

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

        const item = document.createElement("div");
        item.style.border = "1px solid #ccc";
        item.style.padding = "8px";
        item.style.marginTop = "8px";
        item.style.cursor = "pointer";

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

        results_div.appendChild(item);

        download_button.disabled = false;
        ai_button.disabled = false;
        saveAnalysisHistory(response);

        download_button.onclick = () => {
          const { jsPDF } = window.jspdf;
          const doc = new jsPDF();

          doc.setFont("helvetica", "bold");
          doc.setFontSize(22);
          doc.text("Web Güvenlik Analiz Raporu", 105, 20, null, null, "center");

          doc.setFont("helvetica", "normal");
          doc.setFontSize(12);
          doc.setTextColor(100);
          doc.text(`Analiz edilen: ${site_url}`, 105, 30, null, null, "center");
          doc.line(10, 38, 200, 38);

          doc.setTextColor(0);
          doc.setFontSize(16);
          doc.setFont("helvetica", "bold");
          doc.text("Analiz Sonuçlari:", 10, 50);

          doc.setFontSize(10);
          doc.setFont("courier", "normal");

          const analysisText = JSON.stringify(response, null, 2);
          const splitText = doc.splitTextToSize(analysisText, 190);

          let y = 60;
          const lineHeight = 5;
          const pageHeight = doc.internal.pageSize.height;
          const margin = 10;

          splitText.forEach((line) => {
            if (y + lineHeight > pageHeight - margin) {
              doc.addPage();
              y = 10;
              y = margin;
              doc.setFontSize(10);
              doc.setFont("courier", "normal");
            }
            doc.text(line, 10, y);
            y += lineHeight;
          });

          const pageCount = doc.internal.getNumberOfPages();
          for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(10);
            doc.setTextColor(150);
            doc.text(
              `${i}.Sayfa`,
              doc.internal.pageSize.width - 30,
              doc.internal.pageSize.height - 10,
              null,
              null,
              "right"
            );
            doc.text(
              `Olusturulma tarihi: ${new Date().toLocaleDateString()}`,
              10,
              doc.internal.pageSize.height - 10
            );
          }

          doc.save("web_guvenlik.pdf");
        };

        ai_button.onclick = () => {
          chrome.runtime.sendMessage(
            { action: "explain", data: response },
            (explanation) => {
              explanation_div.innerText = explanation;
            }
          );
        };
      }
    );
  });

  const saveAnalysisHistory = (result) => {
    chrome.storage.local.get("history", (data) => {
      const history = data.history || [];
      history.unshift({
        date: new Date().toLocaleString(),
        result,
      });

      if (history.length > 20) {
        history.pop();
      }

      chrome.storage.local.set({ history });
      displayHistory();
    });
  };

  const displayHistory = () => {
    chrome.storage.local.get("history", (data) => {
      history_div.innerHTML = "";
      const history = data.history || [];

      if (history.length === 0) {
        history_div.innerHTML = "Geçmiş Boş";
        return;
      }

      history.forEach((entry, index) => {
        const item = document.createElement("div");

        item.style.border = "1px solid #ccc";
        item.style.padding = "8px";
        item.style.marginBottom = "8px";
        item.style.cursor = "pointer";

        const date = document.createElement("div");
        date.innerHTML = `<strong>${entry.date}</strong> <span style='float:right;'>&#9660;</span>`;
        item.appendChild(date);

        const analysis_delete_button = document.createElement("button");
        analysis_delete_button.textContent = "Sil";
        analysis_delete_button.classList.add("analysis-delete-button");
        analysis_delete_button.onclick = (e) => {
          e.stopPropagation();
          deleteAnalysis(index);
        };
        date.appendChild(analysis_delete_button);

        const arrow = date.querySelector("span");
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
          entry.result,
          null,
          2
        )}</pre>`;

        item.appendChild(details);

        history_div.appendChild(item);
      });
    });
  };
  displayHistory();

  clear_history_button.addEventListener("click", () => {
    chrome.storage.local.remove("history", () => {
      displayHistory();
      alert("Geçmiş Başarıyla Temizlendi!");
    });
  });

  const deleteAnalysis = (index) => {
    chrome.storage.local.get("history", (data) => {
      const history = data.history || [];
      history.splice(index, 1);
      chrome.storage.local.set({ history }, () => {
        displayHistory(alert("Seçilen kayıt silindi"));
      });
    });
  };
});
