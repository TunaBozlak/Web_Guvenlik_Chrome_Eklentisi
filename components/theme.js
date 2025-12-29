export const changeTheme = () => {
  const theme_button = document.getElementById("change_theme");

  if (!theme_button) {
    console.warn("Theme button bulunamadı");
    return;
  }
  const updateThemeIcon = (isDark) => {
    theme_button.textContent = isDark ? "☾" : "☀";
  };

  chrome.storage.local.get("theme", (data) => {
    const isDark = data.theme === "dark";
    document.body.classList.toggle("dark", isDark);
    updateThemeIcon(isDark);
  });

  theme_button.addEventListener("click", async () => {
    const isDark = !document.body.classList.contains("dark");
    document.body.classList.toggle("dark", isDark);

    updateThemeIcon(isDark);

    await chrome.storage.local.set({
      theme: isDark ? "dark" : "light",
    });
  });
};
