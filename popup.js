document.addEventListener("DOMContentLoaded", () => {
  const theme_button = document.getElementById("change_theme");
  const analysis_button = document.getElementById("analysis_button");
  const results_div = document.getElementById("results");
  const download_button = document.getElementById("download_pdf");
  const ai_button = document.getElementById("ai_button");
  const history_div = document.getElementById("history");
  const clear_history_button = document.getElementById("delete_history");
  const explanation_div = document.getElementById("explanation");
  const filter_button = document.getElementById("filter_button");
  const reset_filter_button = document.getElementById("reset_filter_button");
  const start_date_input = document.getElementById("start_date");
  const end_date_input = document.getElementById("end_date");

  const analyzeSecurityStatus = (response, site_url) => {
    const statuses = {};

    statuses["HTTPS"] = site_url.startsWith("https://") ? "safe" : "danger";

    const headers = response.securityHeaders || {};
    const header_keys = Object.keys(headers).map((k) => k.toLowerCase());
    statuses["Strict-Transport-Security"] = header_keys.includes(
      "strict-transport-security"
    )
      ? "safe"
      : "warning";

    statuses["Content-Security-Policy"] = header_keys.includes(
      "content-security-policy"
    )
      ? "safe"
      : "warning";

    statuses["X-Frame-Options"] = header_keys.includes("x-frame-options")
      ? "safe"
      : "danger";

    const virus_total = response.malwareScan || {};
    const scans = virus_total.scans || {};
    const detected_count = Object.values(scans).filter(
      (scan) => scan.detected === true
    );
    if (detected_count.length === 0) {
      statuses["Virustotal"] = "safe";
    } else if (detected_count.length <= 5) {
      statuses["Virustotal"] = "warning";
    } else {
      statuses["Virustotal"] = "danger";
    }

    const cookies = response.cookies || [];
    const insecure_cookies = cookies.filter(
      (cookie) => !cookie.secure || !cookie.httpOnly
    );
    statuses["Çerez Güvenliği"] =
      insecure_cookies.length === 0 ? "safe" : "warning";

    const riskyFunctions = response.riskyFunctions || [];
    statuses["JavaScript Riskleri"] =
      riskyFunctions.length === 0 ? "safe" : "danger";

    return statuses;
  };

  const createSecurityCard = (title, status) => {
    const card = document.createElement("div");
    card.classList.add("security-card");

    const icon = document.createElement("span");
    icon.style.fontSize = "18px";

    let color, iconSymbol;
    if (status === "safe") {
      color = "green";
      iconSymbol = "🎉";
    } else if (status === "warning") {
      color = "orange";
      iconSymbol = "⚠️";
    } else {
      color = "red";
      iconSymbol = "💣";
    }

    card.style.borderColor = color;
    card.style.color = color;

    card.innerHTML = `<span>${title}</span>`;
    icon.textContent = iconSymbol;

    card.appendChild(icon);
    return card;
  };

  filter_button.addEventListener("click", () => {
    const start_date = new Date(start_date_input.value);
    const end_date = new Date(end_date_input.value);
    if (!start_date_input.value || !end_date_input.value) {
      alert("Lütfen tarih aralığı seçiniz");
      return;
    }
    displayHistory(start_date, end_date);
  });

  reset_filter_button.addEventListener("click", () => {
    start_date_input.value = "";
    end_date_input.value = "";
    displayHistory();
  });

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

            return {
              externalScripts,
              detectedRiskyFunctions,
            };
          },
        });
        response.jsFiles = jsAnalysis[0].result.externalScripts;
        response.riskyFunctions = jsAnalysis[0].result.detectedRiskyFunctions;

        //yeni
        const statuses = analyzeSecurityStatus(response, site_url);
        Object.entries(statuses).forEach(([title, status]) => {
          const card = createSecurityCard(title, status);
          results_div.appendChild(card);
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

        const domain = new URL(site_url).origin;
        download_button.disabled = false;
        ai_button.disabled = false;
        saveAnalysisHistory({ site: domain, ...response });

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

  const displayHistory = (start_date = null, end_date = null) => {
    chrome.storage.local.get("history", (data) => {
      history_div.innerHTML = "";
      const history = data.history || [];

      const filtered_history = history.filter((entry) => {
        if (!start_date || !end_date) return true;
        const entry_date = new Date(entry.date);
        return entry_date >= start_date && entry_date <= end_date;
      });

      if (filtered_history.length === 0) {
        history_div.innerHTML = "Geçmiş Boş";
        return;
      }

      filtered_history.forEach((entry, index) => {
        const item = document.createElement("div");
        item.style.border = "1px solid #ccc";
        item.style.padding = "8px";
        item.style.marginBottom = "8px";
        item.style.cursor = "pointer";

        const header = document.createElement("div");
        header.style.display = "flex";
        header.style.justifyContent = "space-between";
        header.style.alignItems = "center";

        const leftPart = document.createElement("div");
        const domain = entry.result?.site || "Bilinmeyen Site";
        leftPart.innerHTML = `
    <div style="font-weight: bold;">${domain}</div>
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
        alert("Seçilen kayıt silindi");
        displayHistory();
      });
    });
  };
});
