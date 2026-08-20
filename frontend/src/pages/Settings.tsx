import { useEffect, useState } from "react";
import {
  DEFAULT_STREAM_GAP_SECONDS, MAX_STREAM_GAP_SECONDS, MIN_STREAM_GAP_SECONDS,
  DEFAULT_HISTORY_LIMIT,      MAX_HISTORY_LIMIT,      MIN_HISTORY_LIMIT,
  DEFAULT_STREAM_BUCKET_MS,   DEFAULT_STREAM_POLL_SECONDS,
  MIN_STREAM_POLL_SECONDS,    MAX_STREAM_POLL_SECONDS,
  BUCKET_OPTIONS,
} from "../lib/settings";
import { useSettings } from "../context/SettingsContext";
import { getPolicy, login, updatePolicy, type Policy } from "../api/client";

const STATE_LABEL: Record<string, string> = {
  ALERTED: "Alerted Mode",
  UNDER_ATTACK: "Under Attack Mode",
};

const ACTION_LABEL: Record<string, string> = {
  rate_limit: "Rate Limit",
  block: "Block",
};

const ADMIN_TOKEN_KEY = "anoseek_admin_token";
const ADMIN_ROLE_KEY = "anoseek_admin_role";

export default function Settings() {
  const {
    streamGapSeconds, updateStreamGap,
    historyLimit,     updateHistoryLimit,
    streamBucketMs,   updateStreamBucket,
    streamPollSeconds,updateStreamPoll,
  } = useSettings();

  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policySaving, setPolicySaving] = useState(false);
  const [policyMsg, setPolicyMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const [adminToken, setAdminToken] = useState<string | null>(() =>
    sessionStorage.getItem(ADMIN_TOKEN_KEY),
  );
  const [adminRole, setAdminRole] = useState<string | null>(() =>
    sessionStorage.getItem(ADMIN_ROLE_KEY),
  );
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginLoading, setLoginLoading] = useState(false);

  const isAdmin = adminToken !== null && adminRole === "ADMIN";

  function clearAdminSession() {
    sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    sessionStorage.removeItem(ADMIN_ROLE_KEY);
    setAdminToken(null);
    setAdminRole(null);
    setPolicy(null);
  }

  async function handleAdminLogin() {
    setLoginError(null);
    setLoginLoading(true);
    try {
      const result = await login(loginUsername, loginPassword);
      if (result.role !== "ADMIN") {
        setLoginError("This account does not have ADMIN access.");
        return;
      }
      sessionStorage.setItem(ADMIN_TOKEN_KEY, result.token);
      sessionStorage.setItem(ADMIN_ROLE_KEY, result.role);
      setAdminToken(result.token);
      setAdminRole(result.role);
      setLoginPassword("");
    } catch (e: any) {
      setLoginError(e?.message ?? "Login failed.");
    } finally {
      setLoginLoading(false);
    }
  }

  useEffect(() => {
    if (!adminToken) return;
    getPolicy(adminToken)
      .then(setPolicy)
      .catch((e: any) => {
        // Token rejected/expired — drop back to the login form.
        setLoginError(e?.message ?? "Session expired, please log in again.");
        clearAdminSession();
      });
  }, [adminToken]);

  function toggleAllowed(index: number) {
    if (!policy) return;
    const updated: Policy = {
      ...policy,
      Statement: policy.Statement.map((s, i) =>
        i === index ? { ...s, Allowed: !s.Allowed } : s
      ),
    };
    setPolicy(updated);
  }

  async function savePolicy() {
    if (!policy || !adminToken) return;
    setPolicySaving(true);
    setPolicyMsg(null);
    try {
      await updatePolicy(policy, adminToken);
      setPolicyMsg({ ok: true, text: "Policy saved." });
    } catch (e: any) {
      setPolicyMsg({ ok: false, text: e?.message ?? "Save failed." });
    } finally {
      setPolicySaving(false);
    }
  }

  return (
    <div className="mx-auto w-full max-w-none flex-col p-4 md:p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Stream behavior and dashboard preferences. Changes apply immediately.
        </p>
      </header>

      <div className="flex flex-col gap-4 max-w-2xl">

        {/* CSV stream gap */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">CSV stream timing</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                Speed multiplier for CSV replay. Each row waits its actual
                <span className="font-mono"> FLOW_DURATION_MILLISECONDS </span>
                scaled by this factor — like the live ZMQ feed.
                <span className="font-medium"> 1.0</span> = real-time,
                <span className="font-medium"> 0.1</span> = 10× faster,
                <span className="font-medium"> 0</span> = no delay.
              </p>
            </div>
            <label className="block">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Speed multiplier</span>
              <div className="mt-2 flex items-center gap-3">
                <input
                  type="range"
                  min={MIN_STREAM_GAP_SECONDS} max={MAX_STREAM_GAP_SECONDS} step="0.25"
                  value={streamGapSeconds}
                  onChange={(e) => updateStreamGap(Number(e.target.value))}
                  className="w-full accent-blue-500"
                />
                <input
                  type="number"
                  min={MIN_STREAM_GAP_SECONDS} max={MAX_STREAM_GAP_SECONDS} step="0.25"
                  value={streamGapSeconds}
                  onChange={(e) => updateStreamGap(Number(e.target.value))}
                  className="w-24 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                />
                <span className="text-sm text-slate-600 dark:text-slate-400">sec</span>
              </div>
            </label>
            <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
              <span className="text-xs text-slate-500">{streamGapSeconds.toFixed(2)}s</span>
              <button type="button" onClick={() => updateStreamGap(DEFAULT_STREAM_GAP_SECONDS)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">Reset</button>
            </div>
          </div>
        </div>

        {/* Live stream poll interval */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Live stream poll interval</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                How often the Live stream page fetches new events from the agent.
              </p>
            </div>
            <label className="block">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Poll every</span>
              <div className="mt-2 flex items-center gap-3">
                <input
                  type="range"
                  min={MIN_STREAM_POLL_SECONDS} max={MAX_STREAM_POLL_SECONDS} step="1"
                  value={streamPollSeconds}
                  onChange={(e) => updateStreamPoll(Number(e.target.value))}
                  className="w-full accent-blue-500"
                />
                <input
                  type="number"
                  min={MIN_STREAM_POLL_SECONDS} max={MAX_STREAM_POLL_SECONDS} step="1"
                  value={streamPollSeconds}
                  onChange={(e) => updateStreamPoll(Number(e.target.value))}
                  className="w-24 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                />
                <span className="text-sm text-slate-600 dark:text-slate-400">sec</span>
              </div>
            </label>
            <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
              <span className="text-xs text-slate-500">{streamPollSeconds}s</span>
              <button type="button" onClick={() => updateStreamPoll(DEFAULT_STREAM_POLL_SECONDS)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">Reset</button>
            </div>
          </div>
        </div>

        {/* Live stream time frame bucket */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Live stream time frame</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                Bucket size for the flows-per-time-frame chart. "Auto" picks a size based on the event range.
              </p>
            </div>
            <label className="block">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Bucket size </span>
              <select
                value={streamBucketMs}
                onChange={(e) => updateStreamBucket(Number(e.target.value))}
                className="mt-2 w-48 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
              >
                {BUCKET_OPTIONS.map((o) => (
                  <option key={o.ms} value={o.ms}>{o.label}</option>
                ))}
              </select>
            </label>
            <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
              <span className="text-xs text-slate-500">
                Current: {BUCKET_OPTIONS.find((o) => o.ms === streamBucketMs)?.label ?? "Auto"}
              </span>
              <button type="button" onClick={() => updateStreamBucket(DEFAULT_STREAM_BUCKET_MS)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">Reset</button>
            </div>
          </div>
        </div>

        {/* Chat history */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Chat flow history</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                Number of recent flows the chatbot will use as context (1–{MAX_HISTORY_LIMIT}).
              </p>
            </div>
            <label className="block">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Flows to include</span>
              <div className="mt-2 flex items-center gap-3">
                <input
                  type="range"
                  min={MIN_HISTORY_LIMIT} max={MAX_HISTORY_LIMIT} step="1"
                  value={historyLimit}
                  onChange={(e) => updateHistoryLimit(Number(e.target.value))}
                  className="w-full accent-blue-500"
                />
                <input
                  type="number"
                  min={MIN_HISTORY_LIMIT} max={MAX_HISTORY_LIMIT} step="1"
                  value={historyLimit}
                  onChange={(e) => updateHistoryLimit(Number(e.target.value))}
                  className="w-24 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                />
                <span className="text-sm text-slate-600 dark:text-slate-400">flows</span>
              </div>
            </label>
            <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
              <span className="text-xs text-slate-500">{historyLimit} flows</span>
              <button type="button" onClick={() => updateHistoryLimit(DEFAULT_HISTORY_LIMIT)} className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">Reset</button>
            </div>
          </div>
        </div>

        {/* Policy rules */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Agent policy rules</h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                Control which actions the agent is allowed to take autonomously in each state.
                When disabled, SOC confirmation is required.
              </p>
            </div>

            {!isAdmin ? (
              <div className="flex flex-col gap-3">
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  ADMIN login required to view or change automated block / rate-limit policy.
                </p>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <input
                    type="text"
                    placeholder="Username"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    className="flex-1 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                  />
                  <input
                    type="password"
                    placeholder="Password"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleAdminLogin()}
                    className="flex-1 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-200 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100"
                  />
                  <button
                    type="button"
                    onClick={handleAdminLogin}
                    disabled={loginLoading || !loginUsername || !loginPassword}
                    className="rounded-lg bg-blue-500 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-400 disabled:opacity-50"
                  >
                    {loginLoading ? "Signing in…" : "Sign in"}
                  </button>
                </div>
                {loginError && (
                  <span className="text-xs font-medium text-red-600 dark:text-red-400">{loginError}</span>
                )}
              </div>
            ) : !policy ? (
              <div className="text-xs text-slate-400">Loading policy…</div>
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-500 dark:text-slate-400">Signed in as ADMIN</span>
                  <button
                    type="button"
                    onClick={clearAdminSession}
                    className="text-xs font-medium text-slate-500 underline hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
                  >
                    Sign out
                  </button>
                </div>
                <div className="divide-y divide-slate-100 dark:divide-slate-700">
                  {policy.Statement.map((rule, i) => (
                    <div key={i} className="flex items-center justify-between py-3">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-sm font-medium text-slate-800 dark:text-slate-200">
                          {STATE_LABEL[rule.State] ?? rule.State} — {ACTION_LABEL[rule.Action_Required] ?? rule.Action_Required}
                        </span>
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {rule.Allowed ? "Agent acts autonomously" : "Requires SOC confirmation"}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => toggleAllowed(i)}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none ${
                          rule.Allowed ? "bg-blue-500" : "bg-slate-300 dark:bg-slate-600"
                        }`}
                        role="switch"
                        aria-checked={rule.Allowed}
                      >
                        <span
                          className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform duration-200 ${
                            rule.Allowed ? "translate-x-5" : "translate-x-0"
                          }`}
                        />
                      </button>
                    </div>
                  ))}
                </div>

                <div className="flex items-center justify-between border-t border-slate-100 pt-3 dark:border-slate-700">
                  {policyMsg ? (
                    <span className={`text-xs font-medium ${policyMsg.ok ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}>
                      {policyMsg.text}
                    </span>
                  ) : <span />}
                  <button
                    type="button"
                    onClick={savePolicy}
                    disabled={policySaving || !policy}
                    className="rounded-lg bg-blue-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-400 disabled:opacity-50"
                  >
                    {policySaving ? "Saving…" : "Save changes"}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
