import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  TableProperties,
  Bell,
  Activity,
  Radio,
  BarChart3,
  Settings as SettingsIcon,
} from "lucide-react";

const links = [
  { to: "/overview",  label: "Overview",       icon: LayoutDashboard },
  { to: "/flows",     label: "Flows",          icon: TableProperties },
  { to: "/alerts",    label: "Alerts",         icon: Bell },
  { to: "/agent",     label: "Agent state",    icon: Activity },
  { to: "/live",      label: "Live stream",    icon: Radio },
  { to: "/insights",  label: "Model insights", icon: BarChart3 },
  { to: "/settings",  label: "Settings",       icon: SettingsIcon },
];

export default function Sidebar() {
  return (
    <aside className="hidden w-56 shrink-0 border-r border-slate-200 bg-white md:block">
      <div className="flex h-14 items-center gap-2 border-b border-slate-200 px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-slate-900 text-sm font-semibold text-white">
          A
        </div>
        <span className="text-sm font-semibold tracking-tight">Anoseek</span>
      </div>

      <nav className="flex flex-col gap-0.5 p-2">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              [
                "flex items-center gap-2 rounded-lg px-3 py-2 text-sm",
                isActive
                  ? "bg-slate-100 font-medium text-slate-900"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900",
              ].join(" ")
            }
          >
            <Icon className="h-4 w-4" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}