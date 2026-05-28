import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Layers,
  Bell,
  Activity,
  Radio,
  MessageCircle,
  BarChart3,
  Settings as SettingsIcon,
} from "lucide-react";

const links = [
  { to: "/overview",  label: "Overview",       icon: LayoutDashboard },
  { to: "/modes",     label: "Modes",          icon: Layers },
  { to: "/alerts",    label: "Alerts",         icon: Bell },
  { to: "/agent",     label: "Agent state",    icon: Activity },
  { to: "/live",      label: "Live stream",    icon: Radio },
  { to: "/chat",      label: "Chat",           icon: MessageCircle },
  { to: "/insights",  label: "Model insights", icon: BarChart3 },
  { to: "/settings",  label: "Settings",       icon: SettingsIcon },
];

export default function Sidebar() {
  return (
    <aside className="hidden w-56 shrink-0 border-r border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-800 md:block">
      {/* Brand */}
      <div className="flex h-14 items-center gap-2 border-b border-slate-200 px-4 dark:border-slate-700">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-slate-900 text-sm font-semibold text-white transition-transform duration-200 hover:scale-110 dark:bg-slate-600">
          A
        </div>
        <span className="text-sm font-semibold tracking-tight">Anoseek</span>
      </div>

      <nav className="flex flex-col gap-0.5 p-2">
        {links.map(({ to, label, icon: Icon }, i) => (
          <NavLink
            key={to}
            to={to}
            style={{ animationDelay: `${i * 40}ms` }}
            className="animate-slide-in-left"
          >
            {({ isActive }: { isActive: boolean }) => (
              <span
                className={[
                  "group relative flex items-center gap-2.5 overflow-hidden rounded-xl px-3 py-2.5 text-sm",
                  "transition-all duration-200 ease-out",
                  isActive
                    ? "bg-blue-50 font-semibold text-blue-700 shadow-sm dark:bg-blue-500/10 dark:text-blue-400"
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-700/60 dark:hover:text-white",
                ].join(" ")}
              >
                {/* Active left bar */}
                <span
                  className={[
                    "absolute left-0 top-1/2 w-[3px] rounded-full bg-blue-500",
                    "transition-all duration-300 ease-out",
                    isActive
                      ? "h-3/5 -translate-y-1/2 opacity-100"
                      : "h-0 -translate-y-1/2 opacity-0",
                  ].join(" ")}
                />

                {/* Icon */}
                <Icon
                  className={[
                    "h-4 w-4 shrink-0 transition-all duration-200",
                    isActive
                      ? "text-blue-600 dark:text-blue-400"
                      : "group-hover:scale-110 group-hover:-rotate-6",
                  ].join(" ")}
                />

                {/* Label */}
                <span className="transition-transform duration-200 group-hover:translate-x-0.5">
                  {label}
                </span>

                {/* Hover shimmer */}
                <span className="absolute inset-0 -translate-x-full skew-x-[-20deg] bg-white/20 transition-transform duration-500 group-hover:translate-x-[200%] dark:bg-white/5" />
              </span>
            )}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
