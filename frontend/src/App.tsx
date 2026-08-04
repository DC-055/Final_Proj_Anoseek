/**
 * Top-level layout shell.
 * Sidebar on the left, topbar on top, page content fills the rest.
 */
import { Routes, Route, Navigate } from "react-router-dom";

import { ChatProvider } from "./context/ChatContext";
import { DarkModeProvider } from "./context/DarkModeContext";
import { SettingsProvider } from "./context/SettingsContext";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";

import Overview from "./pages/Overview";
import Modes from "./pages/Modes";
import Alerts from "./pages/Alerts";
import AgentState from "./pages/AgentState";
import LiveStream from "./pages/LiveStream";
import Chat from "./pages/Chat";
import ModelInsights from "./pages/ModelInsights";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <DarkModeProvider>
      <SettingsProvider>
      <ChatProvider>
        <div className="flex h-screen overflow-hidden bg-slate-50 text-slate-900 dark:bg-slate-900 dark:text-slate-100">
          <Sidebar />
          <div className="flex flex-1 flex-col overflow-hidden">
            <Topbar />
            <main className="flex-1 overflow-y-auto overflow-x-hidden p-6">
              <Routes>
                <Route path="/" element={<Navigate to="/overview" replace />} />
                <Route path="/overview" element={<Overview />} />
                <Route path="/modes" element={<Modes />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/agent" element={<AgentState />} />
                <Route path="/live" element={<LiveStream />} />
                <Route path="/chat" element={<Chat />} />
                <Route path="/insights" element={<ModelInsights />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </main>
          </div>
        </div>
      </ChatProvider>
      </SettingsProvider>
    </DarkModeProvider>
  );
}
