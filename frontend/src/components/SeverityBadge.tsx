/**
 * Pill-shaped badge showing a severity label with the right color.
 * Wraps `badgeForSeverity` so pages don't have to assemble the className themselves.
 *
 *   <SeverityBadge label="DoS / DDoS attacks" />
 */
import { badgeForSeverity } from "../lib/severity";

export default function SeverityBadge({ label }: { label?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${badgeForSeverity(
        label,
      )}`}
    >
      {label || "—"}
    </span>
  );
}