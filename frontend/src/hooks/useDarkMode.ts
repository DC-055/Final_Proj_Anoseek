import { useEffect, useState } from "react";

const KEY = "anoseek.darkMode";

export function useDarkMode() {
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem(KEY);
    if (saved !== null) return saved === "true";
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", dark);
    localStorage.setItem(KEY, String(dark));
  }, [dark]);

  return { dark, toggle: () => setDark((d) => !d) };
}
