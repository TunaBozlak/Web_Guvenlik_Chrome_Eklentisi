export const downloadPdf = (data, site_url) => {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.text("Web Analiz Raporu", 105, 20, null, null, "center");

  doc.setFont("helvetica", "normal");
  doc.setFontSize(12);
  doc.setTextColor(100);
  doc.text(`Analiz edilen: ${site_url}`, 105, 30, null, null, "center");
  doc.line(10, 38, 200, 38);

  doc.setTextColor(0);
  doc.setFontSize(16);
  doc.setFont("helvetica", "bold");
  doc.text("Sonuçlar:", 10, 50);

  doc.setFontSize(10);
  doc.setFont("courier", "normal");

  const text = JSON.stringify(data, null, 2);
  const splitText = doc.splitTextToSize(text, 190);

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
      "right",
    );
    doc.text(
      `Olusturulma tarihi: ${new Date().toLocaleDateString()}`,
      10,
      doc.internal.pageSize.height - 10,
    );
  }

  doc.save("web.pdf");
};

const downloadMarkdown = (mdReportString, site_url) => {
  const blob = new Blob([mdReportString.trim()], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safeName = new URL(site_url).hostname
    .replace(/[^a-z0-9]/gi, "_")
    .toLowerCase();
  a.download = `guvenlik_raporu_${safeName}_${new Date().getTime()}.md`;
  a.click();
  URL.revokeObjectURL(url);
};

export const setupDownloadDropdown = (data, mdReportString, site_url) => {
  let originalBtn = document.getElementById("download_pdf");
  if (!originalBtn) return;

  let wrapper = document.getElementById("download-wrapper");
  if (!wrapper) {
    wrapper = document.createElement("div");
    wrapper.id = "download-wrapper";
    wrapper.style.position = "relative";
    wrapper.style.width = "100%";
    originalBtn.parentNode.insertBefore(wrapper, originalBtn);
    wrapper.appendChild(originalBtn);
  }

  const newBtn = originalBtn.cloneNode(true);
  newBtn.id = "download_pdf";
  newBtn.innerHTML = "📥 Raporu İndir ▼";
  newBtn.disabled = false;
  wrapper.replaceChild(newBtn, originalBtn);

  let oldDropdown = document.getElementById("download-dropdown");
  if (oldDropdown) oldDropdown.remove();

  const dropdown = document.createElement("div");
  dropdown.id = "download-dropdown";
  dropdown.style.cssText =
    "display: none; position: absolute; bottom: 100%; left: 0; width: 100%; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; box-shadow: var(--shadow-md); z-index: 100; flex-direction: column; overflow: hidden; margin-bottom: 8px;";

  const createOption = (text, onClick) => {
    const opt = document.createElement("div");
    opt.innerHTML = text;
    opt.style.cssText =
      "padding: 10px 15px; cursor: pointer; border-bottom: 1px solid var(--border-color); font-size: 13px; transition: background 0.2s; color: var(--text-main); font-weight: 500;";
    opt.onmouseover = () => (opt.style.background = "var(--bg-color)");
    opt.onmouseout = () => (opt.style.background = "transparent");
    opt.onclick = () => {
      onClick();
      dropdown.style.display = "none";
    };
    return opt;
  };

  const pdfOption = createOption("📄 PDF Olarak İndir", () =>
    downloadPdf(data, site_url),
  );
  const mdOption = createOption("📝 Markdown Olarak İndir", () =>
    downloadMarkdown(mdReportString, site_url),
  );
  mdOption.style.borderBottom = "none";

  dropdown.appendChild(mdOption);
  dropdown.appendChild(pdfOption);
  wrapper.appendChild(dropdown);

  newBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    dropdown.style.display =
      dropdown.style.display === "none" ? "flex" : "none";
  });

  document.addEventListener("click", () => {
    if (dropdown.style.display === "flex") {
      dropdown.style.display = "none";
    }
  });
};
