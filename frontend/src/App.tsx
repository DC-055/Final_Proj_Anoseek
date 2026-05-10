/**
 * Top-level layout shell.
 * Sidebar on the left, topbar on top, page content fills the rest.
 */
import { Routes, Route, Navigate } from "react-router-dom";

import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";

import Overview from "./pages/Overview";
import Flows from "./pages/Flows";
import Alerts from "./pages/Alerts";
import AgentState from "./pages/AgentState";
import LiveStream from "./pages/LiveStream";
import ModelInsights from "./pages/ModelInsights";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <Topbar />
        <main className="flex-1 overflow-x-hidden p-6">
          <Routes>
            <Route path="/" element={<Navigate to="/overview" replace />} />
            <Route path="/overview" element={<Overview />} />
            <Route path="/flows" element={<Flows />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/agent" element={<AgentState />} />
            <Route path="/live" element={<LiveStream />} />
            <Route path="/insights" element={<ModelInsights />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}