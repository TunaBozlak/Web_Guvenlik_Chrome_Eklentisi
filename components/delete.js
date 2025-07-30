import { displayHistory } from "./history.js";

const clear_history_button = document.getElementById("delete_history");

export const deleteHistory = () => {
  clear_history_button.addEventListener("click", () => {
    chrome.storage.local.remove("history", () => {
      displayHistory();
      alert("Geçmiş Başarıyla Temizlendi!");
    });
  });
};

export const deleteAnalysis = (index) => {
  chrome.storage.local.get("history", (data) => {
    const history = data.history || [];
    history.splice(index, 1);
    chrome.storage.local.set({ history }, () => {
      alert("Seçilen kayıt silindi");
      displayHistory();
    });
  });
};
