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
        results_div.innerText = JSON.stringify(response, null, 2);
        download_button.disabled = false;
        ai_button.disabled = false;
        saveAnalysisHistory(response);

        download_button.onclick = () => {
          const { jsPDF } = window.jspdf;
          const doc = new jsPDF();
          doc.setFontSize(12);
          doc.text("Web Güvenlik Analiz", 10, 10);
          doc.text(`Site: ${site_url}`, 10, 20);
          doc.text("Analiz Sonuçları:", 10, 30);

          const analysisText = JSON.stringify(response, null, 2);
          const splitText = doc.splitTextToSize(analysisText, 180);
          doc.text(splitText, 10, 40);

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

      if (history.length > 10) {
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
      history.forEach((entry) => {
        const item = document.createElement("div");
        item.style.border = "1px solid #ccc";
        item.style.padding = "8px";
        item.style.marginBottom = "8px";
        item.style.backgroundColor = "white";
        item.innerHTML = `
          <strong>${entry.date}</strong><br>
          <pre>${JSON.stringify(entry.result, null, 2)}</pre>
        `;
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
});
