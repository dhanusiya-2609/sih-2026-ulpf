/* Applied as early as possible (loaded in <head>, before body paint) to
   avoid a flash of the wrong theme. Light is the default. */
(function () {
  const stored = localStorage.getItem("ulpf_theme");
  const theme = stored === "dark" ? "dark" : "light";
  document.documentElement.setAttribute("data-bs-theme", theme);
})();

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-bs-theme") || "light";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-bs-theme", next);
  localStorage.setItem("ulpf_theme", next);
  const icon = document.getElementById("theme-toggle-icon");
  if (icon) icon.className = next === "dark" ? "bi bi-sun" : "bi bi-moon-stars";
  // Lets pages with canvas charts re-render using the new theme's colours.
  window.dispatchEvent(new Event("themechange"));
}

function initThemeToggleIcon() {
  const icon = document.getElementById("theme-toggle-icon");
  if (!icon) return;
  const current = document.documentElement.getAttribute("data-bs-theme") || "light";
  icon.className = current === "dark" ? "bi bi-sun" : "bi bi-moon-stars";
}
