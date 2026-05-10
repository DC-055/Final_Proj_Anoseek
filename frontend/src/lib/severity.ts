/**
 * Severity / agent-state color and label helpers.
 * Single source of truth so colors stay consistent across pages.
 */

export function badgeForSeverity(sev?: string): string {
  const s = (sev || "").toLowerCase();
  if (!sev || s === "benign" || s === "none") {
    return "bg-green-100 text-green-800 border-green-200";
  }
  if (s.includes("recon") || s.includes("scan")) {
    return "bg-yellow-100 text-yellow-800 border-yellow-200";
  }
  if (s.includes("brute") || s.includes("fuzz")) {
    return "bg-orange-100 text-orange-800 border-orange-200";
  }
  if (s.includes("dos") || s.includes("ddos")) {
    return "bg-red-100 text-red-800 border-red-200";
  }
  return "bg-purple-100 text-purple-800 border-purple-200";
}

export function badgeForAgentState(state?: string): string {
  switch (state) {
    case "idle":         return "bg-green-100 text-green-800 border-green-200";
    case "alerted":      return "bg-yellow-100 text-yellow-800 border-yellow-200";
    case "under_attack": return "bg-red-100 text-red-800 border-red-200";
    default:             return "bg-slate-100 text-slate-700 border-slate-200";
  }
}

export function labelForAgentState(state?: string): string {
  switch (state) {
    case "idle":         return "IDLE";
    case "alerted":      return "ALERTED";
    case "under_attack": return "UNDER ATTACK";
    default:             return "—";
  }
}

export function badgeForAction(action?: string): string {
  switch (action) {
    case "pass":  return "bg-slate-100 text-slate-700 border-slate-200";
    case "flag":  return "bg-yellow-100 text-yellow-800 border-yellow-200";
    case "alert": return "bg-orange-100 text-orange-800 border-orange-200";
    case "block": return "bg-red-100 text-red-800 border-red-200";
    case "error": return "bg-purple-100 text-purple-800 border-purple-200";
    default:      return "bg-slate-100 text-slate-700 border-slate-200";
  }
}

export function toBool(v: any): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") return ["true", "1", "yes"].includes(v.toLowerCase());
  return false;
}