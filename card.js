export const createCard = (title, status) => {
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
