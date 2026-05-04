from enum import Enum
from datetime import datetime
from collections import defaultdict, deque
from threading import Lock
import logging

logging.basicConfig(filename="policy_agent.log", filemode='a', level=logging.INFO)


class AgentMode(Enum):
    UNDER_ATTACK = "under_attack"
    ALERTED = "alerted"
    IDLE = "idle"


class PolicyAnoseekAgent:
    def __init__(self):
        # Primary stores: event_id -> event dict
        self.event_history: dict[int, dict] = {}
        self.flagged_event_history: dict[int, dict] = {}
        self.blocked_event_history: dict[int, dict] = {}

        # Per-IP indexes — list of event_ids per src_ip, for O(1) counts
        self.events_by_ip: dict[str, list[int]] = defaultdict(list)
        self.flagged_by_ip: dict[str, list[int]] = defaultdict(list)
        self.blocked_by_ip: dict[str, list[int]] = defaultdict(list)

        # Recent state transitions for the UI timeline
        self.transitions: deque = deque(maxlen=50)

        self.status: AgentMode = AgentMode.IDLE
        self.entered_state_at: str = datetime.now().isoformat()
        self.benign_sequence: int = 0
        self.soc_confirm: int = 0

        self.valid_severities = [0, 1, 2, 3, 4]
        self.alerts = {
            0: "Benign traffic.",
            1: "Monitor the source IP for additional suspicious behavior.",
            2: "Check authentication logs and consider temporary rate limiting.",
            3: "Inspect traffic volume and consider DDoS mitigation.",
            4: "Escalate immediately and investigate affected host."
        }

        # Concurrency safety + monotonic id
        self._lock = Lock()
        self._next_event_id = 1

    # === public API
    def analyze_and_act(self, flow_result):
        severity = flow_result["predicted_class"]

        event_id = self._next_event_id
        self._next_event_id += 1

        event = {
            "event_id": event_id,
            "timestamp": datetime.now().isoformat(),
            "flow_id": flow_result.get("flow_id"),
            "src_ip": flow_result.get("src_ip"),
            "dst_ip": flow_result.get("dst_ip"),
            "severity": severity,
            "severity_label": self._label(severity),
            "state_before": self.status.value,
        }
        self.event_history[event_id] = event
        if event["src_ip"]:
            self.events_by_ip[event["src_ip"]].append(event_id)

        if severity not in self.valid_severities:
            return {
                "ok": False,
                "error": f"Unknown severity: {severity}",
                "event_id": event_id,
                "flow_id": event["flow_id"],
                "src_ip": event["src_ip"],
                "agent_state": self.status.value,
            }

        action, note = self.execute_action(event, severity)
        event["action"] = action
        event["note"] = note
        event["state_after"] = self.status.value

        return {
            "ok": True,
            "event_id": event_id,
            "src_ip": event["src_ip"],
            "dst_ip": event["dst_ip"],
            "severity": severity,
            "severity_label": event["severity_label"],
            "action": action,
            "note": note,
            "agent_state": self.status.value,
        }

    # TBD
    def confirm_from_soc(self, event=None) -> dict:
        """
        Called either by the API (no args, when SOC clicks confirm) or
        internally during benign decay. Either way, sets soc_confirm = 1.
        """
        logging.info("Asking confirmation from SOC team..")
        self.soc_confirm = 1
        return {
            "ok": True,
            "soc_confirm": self.soc_confirm,
            "status": self.status.value,
        }

    def reset(self) -> dict:
        """Demo helper — wipe history and return to IDLE."""
        with self._lock:
            self.__init__()
        logging.info("Agent reset.")
        return {"ok": True, "status": self.status.value}

    def snapshot(self) -> dict:
        """For GET /agent/state."""
        with self._lock:
            return {
                "status": self.status.value,
                "entered_state_at": self.entered_state_at,
                "benign_sequence": self.benign_sequence,
                "soc_confirm": self.soc_confirm,
                "totals": {
                    "events": len(self.event_history),
                    "flagged": len(self.flagged_event_history),
                    "blocked": len(self.blocked_event_history),
                    "blocked_ips": len([ip for ip, ids in self.blocked_by_ip.items() if ids]),
                },
                "transitions": list(self.transitions)[-10:],
            }

    def list_events(self, kind: str = "all", limit: int = 200) -> list[dict]:
        """For GET /agent/events?kind=..."""
        with self._lock:
            sources = {
                "all": self.event_history,
                "flagged": self.flagged_event_history,
                "blocked": self.blocked_event_history,
            }
            source = sources.get(kind, self.event_history)
            return list(source.values())[-limit:]

    def by_ip(self, src_ip: str) -> dict:
        """For GET /agent/by-ip/{src_ip}. Drill-down for one source."""
        with self._lock:
            event_ids = self.events_by_ip.get(src_ip, [])
            return {
                "src_ip": src_ip,
                "blocked": bool(self.blocked_by_ip.get(src_ip)),
                "counts": {
                    "events":  len(event_ids),
                    "flagged": len(self.flagged_by_ip.get(src_ip, [])),
                    "blocked": len(self.blocked_by_ip.get(src_ip, [])),
                },
                "events": [self.event_history[i] for i in event_ids],
            }

    # === internals
    def _label(self, severity) -> str:
        labels = ["Benign", "Recon / scanning", "Brute force attacks",
                  "DoS / DDoS attacks", "Exploitation attacks"]
        if isinstance(severity, int) and 0 <= severity < len(labels):
            return labels[severity]
        return "unknown"

    def flag_event(self, event):
        flagged_event_id = len(self.flagged_event_history) + 1
        self.flagged_event_history[flagged_event_id] = event
        if event.get("src_ip"):
            self.flagged_by_ip[event["src_ip"]].append(flagged_event_id)
        logging.info("Event %s flagged", event["event_id"])

    def block_event(self, event):
        blocked_event_id = len(self.blocked_event_history) + 1
        self.blocked_event_history[blocked_event_id] = event
        if event.get("src_ip"):
            self.blocked_by_ip[event["src_ip"]].append(blocked_event_id)
        self.block_ip(event)

    def alert_soc(self, event, severity):
        text = self.alerts[severity]
        logging.info("SOC alert: event=%s severity=%s — %s",
                     event["event_id"], severity, text)
        # Hook for popup/notification system

    def count_events_with_same_ip(self, event):
        return len(self.events_by_ip.get(event.get("src_ip"), []))

    def count_flagged_events_with_same_ip(self, event):
        return len(self.flagged_by_ip.get(event.get("src_ip"), []))

    def count_blocked_events_with_same_ip(self, event):
        return len(self.blocked_by_ip.get(event.get("src_ip"), []))

    def _set_status(self, new: AgentMode, reason: str):
        if new == self.status:
            return
        old = self.status
        self.status = new
        self.entered_state_at = datetime.now().isoformat()
        self.transitions.append({
            "from": old.value, "to": new.value,
            "reason": reason, "at": self.entered_state_at,
        })
        logging.info("State %s -> %s (%s)", old.value, new.value, reason)

    def block_ip(self, event):
        logging.info("Blocking IP %s", event.get("src_ip"))
        # Hook for actual IP blocklist integration

    def block_all_flows(self, event):
        logging.info("Blocking all flows..")
        # Hook for emergency stop

    # === state machine
    def execute_action(self, event, severity) -> tuple[str, str]:
        """Returns (action, note) so analyze_and_act can serialize what happened."""
        match self.status:
            case AgentMode.IDLE:
                if severity == 0:
                    logging.info("Benign flow passed")
                    return "pass", "Benign flow"

                elif severity in [1, 2]:
                    if self.count_events_with_same_ip(event) > 3:
                        self.flag_event(event)
                        logging.info("Event flagged")
                        return "flag", "Repeated low-severity activity from this IP"
                    elif self.count_flagged_events_with_same_ip(event) > 2:
                        self.alert_soc(event, severity)
                        self._set_status(AgentMode.ALERTED, "repeated flags")
                        return "alert", "SOC notified after repeated flags"
                    return "pass", "Single low-severity event, monitoring"

                elif severity in [3, 4]:
                    self.block_event(event)
                    self._set_status(AgentMode.ALERTED, "high-severity event")
                    return "block", "High severity blocked"

            case AgentMode.ALERTED:
                if severity == 0:
                    self.benign_sequence += 1
                    logging.info("Benign flow passed")
                    self.confirm_from_soc(event)  # preserves original behavior
                    if self.benign_sequence > 20 and self.soc_confirm == 1:
                        self.benign_sequence = 0
                        self.soc_confirm = 0
                        self._set_status(AgentMode.IDLE, "sustained benign + SOC confirm")
                        return "pass", "Benign streak; returned to IDLE"
                    return "pass", f"Benign ({self.benign_sequence} in a row)"

                elif severity in [1, 2]:
                    self.benign_sequence = 0
                    if self.count_flagged_events_with_same_ip(event) < 3:
                        self.flag_event(event)
                        self.alert_soc(event, severity)
                        return "flag", "Flagged and SOC notified"
                    else:
                        self.block_event(event)
                        self._set_status(AgentMode.UNDER_ATTACK, "repeated flags while alerted")
                        return "block", "Repeated flags while alerted; blocked"

                elif severity in [3, 4]:
                    self.benign_sequence = 0
                    if self.count_flagged_events_with_same_ip(event) > 0:
                        self.block_event(event)
                        self._set_status(AgentMode.UNDER_ATTACK, "high severity from suspect IP")
                        return "block", "High severity from already-suspect IP"
                    else:
                        self.block_event(event)
                        self.alert_soc(event, severity)
                        return "block", "High severity blocked; SOC notified"

            case AgentMode.UNDER_ATTACK:
                if severity == 0:
                    self.benign_sequence += 1
                    logging.info("Benign flow passed")
                    self.confirm_from_soc(event)  # preserves original behavior
                    if self.benign_sequence > 30 and self.soc_confirm == 1:
                        self.benign_sequence = 0
                        self.soc_confirm = 0
                        self._set_status(AgentMode.ALERTED, "attack subsided + SOC confirm")
                        self.flag_event(event)
                        return "flag", "Decayed to ALERTED; benign event flagged"
                    self.flag_event(event)
                    return "flag", "Benign flagged due to UNDER_ATTACK state"

                elif severity in [1, 2, 3, 4]:
                    self.benign_sequence = 0
                    self.block_event(event)
                    return "block", "Blocked under attack mode"

        return "pass", "no-op"

