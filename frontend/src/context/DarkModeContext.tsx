import { createContext, useContext, useEffect, useState } from "react";

const KEY = "anoseek.darkMode";

interface DarkModeCtx {
  dark: boolean;
  toggle: () => void;
}

const DarkModeContext = createContext<DarkModeCtx>({ dark: false, toggle: () => {} });

export function DarkModeProvider({ children }: { children: React.ReactNode }) {
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem(KEY);
    if (saved !== null) return saved === "true";
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem(KEY, String(dark));
  }, [dark]);

  return (
    <DarkModeContext.Provider value={{ dark, toggle: () => setDark((d) => !d) }}>
      {children}
    </DarkModeContext.Provider>
  );
}

export function useDarkModeContext() {
  return useContext(DarkModeContext);
}
