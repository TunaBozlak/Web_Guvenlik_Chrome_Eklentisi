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
      "right"
    );
    doc.text(
      `Olusturulma tarihi: ${new Date().toLocaleDateString()}`,
      10,
      doc.internal.pageSize.height - 10
    );
  }

  doc.save("web.pdf");
};
