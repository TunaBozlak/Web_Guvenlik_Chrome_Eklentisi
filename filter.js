import { displayHistory } from "./history.js";

const filter_button = document.getElementById("filter_button");
const reset_filter_button = document.getElementById("reset_filter_button");
const start_date_input = document.getElementById("start_date");
const end_date_input = document.getElementById("end_date");

export const filterComponent = () => {
  filter_button.addEventListener("click", () => {
    const start_date = new Date(start_date_input.value);
    const end_date = new Date(end_date_input.value);
    end_date.setHours(23, 59, 59, 999);
    if (!start_date_input.value || !end_date_input.value) {
      alert("Lütfen tarih aralığı seçiniz");
      return;
    }
    if (end_date < start_date) {
      alert("Bitiş tarihi, başlangıç tarihinden küçük olamaz ");
      return;
    }
    displayHistory(start_date, end_date);
  });

  reset_filter_button.addEventListener("click", () => {
    start_date_input.value = "";
    end_date_input.value = "";
    displayHistory();
  });
};
