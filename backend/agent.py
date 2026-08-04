from enum import Enum
from datetime import datetime
from collections import defaultdict, deque
from threading import Lock
import logging

logging.basicConfig(filename="policy_agent.log", filemode='a', level=logging.INFO)

"""
"class_names": ["Benign", 
                "Recon / scanning", 
                "Brute force attacks", 
                "DoS / DDoS attacks",
                "High severity / exploitation attacks"]
"""


class AgentMode(Enum):
    UNDER_ATTACK = "under_attack"
    ALERTED = "alerted"
    IDLE = "idle"


class PolicyAnoseekAgent:
    def __init__(self, policy: dict, ipsum):
        # Primary stores: event_id -> event dict
        self.event_history: dict[int, dict] = {}
        self.flagged_event_history: dict[int, dict] = {}
        self.blocked_event_history: dict[int, dict] = {}
        self.rate_limited_event_history: dict[int, dict] = {}

        # Per-IP indexes — list of event_ids per src_ip, for O(1) counts
        self.events_by_ip: dict[str, list[int]] = defaultdict(list)
        self.flagged_by_ip: dict[str, list[int]] = defaultdict(list)
        self.blocked_by_ip: dict[str, list[int]] = defaultdict(list)
        self.rate_limited_by_ip: dict[str, list[int]] = defaultdict(list)

        # Manually blocked IPs (set by SOC via /agent/block-ip)
        #self.blocked_by_ip: set[str] = set()
        # Manually rate limits IPs (set by SOC via /agent/block-ip)
        #self.rate_limited_by_ip: set[str] = set()

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

        # Alert queue — populated by alert_soc(); consumed by /agent/alerts
        self._alert_queue: list[dict] = []

        # IP of the most recent non-benign event (exposed in snapshot for UI)
        self.last_event_ip: str | None = None

        # Concurrency safety + monotonic id
        self._lock = Lock()
        self._next_event_id = 1

        self.policy = policy
        self.external_blocked_ips = ipsum

    # === public API
    def analyze_and_act(self, flow_result):
        severity = flow_result["predicted_class"]

        # Pre-check: drop flows from blocked IPs without state-machine processing
        src_ip = flow_result.get("src_ip")

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
            "confidence": flow_result.get("confidence"),
            "agent_state": self.status.value,
            "note":"",
            "action":"",
            }
        self.event_history[event_id] = event
        if event["src_ip"]:
            self.events_by_ip[event["src_ip"]].append(event_id)
            if severity > 0:
                self.last_event_ip = event["src_ip"]

        if severity not in self.valid_severities:
            return {
                "ok": False,
                "error": f"Unknown severity: {severity}",
                "event_id": event_id,
                "flow_id": event["flow_id"],
                "src_ip": event["src_ip"],
                "agent_state": self.status.value,
            }
        
        if src_ip and src_ip in self.external_blocked_ips:
            event["note"] = "Source IP in external blocked IPs list"
            event["action"] = "block"
            return self.block_ip(event)

        if src_ip and src_ip in self.rate_limited_by_ip:
            event["action"] = "rate_limit"
            return self.rate_limit_ip(event)

        if src_ip and src_ip in self.blocked_by_ip:
            event["note"] = "Source IP in model blocked IPs list"
            event["action"] = "block"
            return self.block_ip(event)

        event = self.execute_action(event, severity)

        # Write action/note back to the stored record (execute_action returns a new dict)
        stored = self.event_history.get(event_id)
        if stored is not None:
            stored["action"] = event.get("action", "")
            stored["note"] = event.get("note", "")

        return {
            "ok": True,
            "event_id": event_id,
            "src_ip": event["src_ip"],
            "dst_ip": event["dst_ip"],
            "severity": severity,
            "severity_label": event["severity_label"],
            "confidence": event["confidence"],
            "action": event["action"],
            "note": event["note"],
            "agent_state": self.status.value,
        }

    def confirm_from_soc(self, confirmed: bool = True) -> dict:
        """
        Called by the API when SOC clicks Confirm (confirmed=True) or Deny (confirmed=False).
        soc_confirm=1 unlocks escalation actions and allows state decay.
        soc_confirm=-1 (denied) keeps the agent restricted until the flag is reset.
        """
        self.soc_confirm = 1 if confirmed else -1
        logging.info("SOC %s (soc_confirm=%d)", "confirmed" if confirmed else "denied", self.soc_confirm)
        return {
            "ok": True,
            "confirmed": confirmed,
            "soc_confirm": self.soc_confirm,
            "status": self.status.value,
        }

    def rate_limit_ip_manual(self, src_ip: str) -> dict:
        """Add an IP to the rate limit list. SOC button."""
        with self._lock:
            event_id = self._next_event_id
            self._next_event_id += 1
            synthetic = {
                "event_id": event_id,
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ip,
                "dst_ip": None,
                "severity": None,
                "severity_label": None,
                "confidence": None,
                "agent_state": self.status.value,
                "note": "Manual SOC rate limit",
                "action": "rate_limit",
            }
            rate_limited_id = len(self.rate_limited_event_history) + 1
            self.rate_limited_event_history[rate_limited_id] = synthetic
            self.rate_limited_by_ip[src_ip].append(rate_limited_id)
        logging.info("Manually rate limited IP %s", src_ip)
        return {"ok": True, "src_ip": src_ip, "action": "rate_limit"}

    def rate_unlimit_manual(self, src_ip: str) -> dict:
        """Remove an IP from the rate limit list. SOC undo."""
        with self._lock:
            self.rate_limited_by_ip.pop(src_ip, None)
        logging.info("Manually rate unlimited IP %s", src_ip)
        return {"ok": True, "src_ip": src_ip, "action": "pass"}

    def block_ip_manual(self, src_ip: str) -> dict:
        """Add an IP to the blocklist. SOC button."""
        with self._lock:
            event_id = self._next_event_id
            self._next_event_id += 1
            synthetic = {
                "event_id": event_id,
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ip,
                "dst_ip": None,
                "severity": None,
                "severity_label": None,
                "confidence": None,
                "agent_state": self.status.value,
                "note": "Manual SOC block",
                "action": "block",
            }
            blocked_id = len(self.blocked_event_history) + 1
            self.blocked_event_history[blocked_id] = synthetic
            self.blocked_by_ip[src_ip].append(blocked_id)
        logging.info("Manually blocked IP %s", src_ip)
        return {"ok": True, "src_ip": src_ip, "action": "block"}

    def unblock_ip_manual(self, src_ip: str) -> dict:
        """Remove an IP from the blocklist. SOC undo."""
        with self._lock:
            self.blocked_by_ip.pop(src_ip, None)
        logging.info("Manually unblocked IP %s", src_ip)
        return {"ok": True, "src_ip": src_ip, "action": "pass"}
        

    def reset(self) -> dict:
        """Demo helper — wipe history and return to IDLE."""
        with self._lock:
            self.__init__(self.policy, self.external_blocked_ips)
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
                "last_event_ip": self.last_event_ip,
                "totals": {
                    "events": len(self.event_history),
                    "flagged": len(self.flagged_event_history),
                    "blocked": len(self.blocked_event_history),
                    "blocked_ips": len([ip for ip, ids in self.blocked_by_ip.items() if ids]),
                    "rate_limited_ips": len(self.rate_limited_by_ip),
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
                "blocked": src_ip in self.blocked_by_ip,
                "rate_limited": src_ip in self.rate_limited_by_ip,
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

    def  flag_event(self, event):
        flagged_event_id = len(self.flagged_event_history) + 1
        self.flagged_event_history[flagged_event_id] = event
        if event["src_ip"]:
            self.flagged_by_ip[event["src_ip"]].append(flagged_event_id)

        event["note"] = "Flagged"
        event["action"] = "flag"
        return event


    def _policy_allows(self, state: str, action_required: str) -> bool:
        for rule in self.policy["Statement"]:
            if (rule["State"].lower() == state.lower()
                    and rule["Action_Required"] == action_required):
                allowed = rule.get("Allowed", rule.get("Action_Allowed", False))
                if str(allowed).lower() == "true":
                    return True
        return False

    def rate_limit_event(self, event):
        if self._policy_allows(event["agent_state"], "rate_limit") or self.soc_confirm == 1:
            rate_limit_event_id = len(self.rate_limited_event_history) + 1
            self.rate_limited_event_history[rate_limit_event_id] = event
            if event["src_ip"]:
                self.rate_limited_by_ip[event["src_ip"]].append(rate_limit_event_id)
            event["note"] = "rate_limit, Repeated flags while alerted; rate limited"
            event["action"] = "rate_limit"
            return self.rate_limit_ip(event)

        event["note"] = "rate limit action is restricted by policy and SOC"
        event["action"] = "flag"
        return event

    def block_event(self, event):
        if self._policy_allows(event["agent_state"], "block") or self.soc_confirm == 1:
            blocked_event_id = len(self.blocked_event_history) + 1
            self.blocked_event_history[blocked_event_id] = event
            if event["src_ip"]:
                self.blocked_by_ip[event["src_ip"]].append(blocked_event_id)
            event["note"] = "block, IP blocked by policy"
            event["action"] = "block"
            return self.block_ip(event)

        event["note"] = "block action is restricted by policy and SOC"
        event["action"] = "flag"
        return event
                

    def alert_soc(self, event, severity):
        text = self.alerts[severity]
        logging.info("SOC alert: event=%s severity=%s — %s",
                     event["event_id"], severity, text)
        self._alert_queue.append({
            "alert_id": len(self._alert_queue),
            "event_id": event["event_id"],
            "src_ip": event["src_ip"],
            "dst_ip": event["dst_ip"],
            "severity": severity,
            "severity_label": self._label(severity),
            "text": text,
            "timestamp": event.get("timestamp", datetime.now().isoformat()),
        })

    def get_alerts(self, since: int = 0) -> list[dict]:
        """Return all alerts with alert_id >= since."""
        return [a for a in self._alert_queue if a["alert_id"] >= since]

    def count_events_with_same_ip(self, event):
        return len(self.events_by_ip.get(event["src_ip"], []))

    def count_flagged_events_with_same_ip(self, event):
        return len(self.flagged_by_ip.get(event["src_ip"], []))

    def count_blocked_events_with_same_ip(self, event):
        return len(self.blocked_by_ip.get(event["src_ip"], []))

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

    def rate_limit_ip(self, event):
        logging.info("Rate Limit IP %s", event["src_ip"])
        return {
                "ok": True,
                "event_id": event["event_id"],
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "severity": event["severity"],
                "severity_label": self._label(event["severity"]),
                "action": "rate_limit",
                "note": "Source IP in rate limit list",
                "agent_state": self.status.value,
                "confidence": event["confidence"],
            }
    
    def cancel_rate_limit_ip(self, event):
        logging.info("Cancel Rate Limit IP %s", event["src_ip"])
        return {
                "ok": True,
                "event_id": event["event_id"],
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "severity": event["severity"],
                "severity_label": self._label(event["severity"]),
                "action": "pass",
                "note": "Source IP is no longer in rate limit list",
                "agent_state": self.status.value,
                "confidence": event["confidence"],
            }


    def block_ip(self, event):
        logging.info("Blocking IP %s", event["src_ip"])
        return {
                "ok": True,
                "event_id": event["event_id"],
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "severity": event["severity"],
                "severity_label": self._label(event["severity"]),
                "action": "block",
                "note": event["note"],
                "agent_state": self.status.value,
                "confidence": event["confidence"],
            }
    

    def cancel_block_ip(self, event):
        logging.info("Cancel Block IP %s", event["src_ip"])
        return {
                "ok": True,
                "event_id": event["event_id"],
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "severity": event["severity"],
                "severity_label": self._label(event["severity"]),
                "action": "pass",
                "note": "Source IP is no longer in block list",
                "agent_state": self.status.value,
                "confidence": event["confidence"],
            }
    
    def pass_event(self, event):
        logging.info("Pass IP %s", event["src_ip"])
        return {
                "ok": True,
                "event_id": event["event_id"],
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "severity": event["severity"],
                "severity_label": self._label(event["severity"]),
                "action": "pass",
                "note": event["note"],
                "agent_state": self.status.value,
                "confidence": event["confidence"],
            }
        

    def block_all_flows(self, event):
        logging.info("Blocking all flows..")
        # Hook for emergency stop

    # === state machine
    def execute_action(self, event, severity) -> tuple[str, str]:
        """Returns (action, note) so analyze_and_act can serialize what happened."""
        match self.status:
            case AgentMode.IDLE:
                if severity == 0:
                    event["note"] = "Benign flow passed"
                    logging.info(event["note"])
                    return self.pass_event(event)

                elif severity in [1, 2]:
                    if self.count_events_with_same_ip(event) > 3:
                        event["note"] = "Event flagged, Repeated low-severity activity from this IP"
                        logging.info(event["note"])
                        return self.flag_event(event) 
                    elif self.count_flagged_events_with_same_ip(event) > 2:
                        self.alert_soc(event, severity)
                        self._set_status(AgentMode.ALERTED, "Repeated flags")
                        event["note"] = "Repeated flags alert, SOC notified"
                        logging.info(event["note"])
                        return self.flag_event(event)

                    event["note"] = "Passed single low-severity event, monitoring"
                    logging.info(event["note"])
                    return self.pass_event(event)

                elif severity in [3, 4]:
                    self.benign_sequence = 0
                    if self.count_flagged_events_with_same_ip(event) == 0: 
                        self.alert_soc(event, severity) ########## TBD ###################
                        logging.info("High severity event")
                        return self.rate_limit_event(event)
                    else:
                        self._set_status(AgentMode.ALERTED, "High severity from suspect IP")
                        logging.info("High severity from already-suspect IP")
                        return self.block_event(event)

            case AgentMode.ALERTED:
                if severity == 0:
                    self.benign_sequence += 1
                    logging.info("Benign flow passed")
                    if self.benign_sequence > 20 and self.soc_confirm == 1:
                        self.benign_sequence = 0
                        self.soc_confirm = 0
                        self._set_status(AgentMode.IDLE, "Sustained benign + SOC confirm")
                        event["note"] = "Passed, Benign streak; returned to IDLE"
                        logging.info(event["note"])
                        return self.pass_event(event)

                    event["note"] = f"Passed Benign ({self.benign_sequence} in a row)"
                    logging.info(event["note"])
                    return self.pass_event(event)

                elif severity in [1, 2]:
                    self.benign_sequence = 0
                    self.alert_soc(event, severity)
                    if self.count_flagged_events_with_same_ip(event) < 3:
                        self.alert_soc(event, severity) ########## TBD ###################
                        event["note"] = "Flagged and SOC notified"
                        logging.info(event["note"])
                        return self.flag_event(event)
                    else:
                        self._set_status(AgentMode.UNDER_ATTACK, "Repeated flags in Alerted mode")
                        logging.info("Repeated flags in Alerted mode")
                        return self.rate_limit_event(event)

                elif severity in [3, 4]:
                    self.benign_sequence = 0
                    if self.count_flagged_events_with_same_ip(event) == 0: 
                        self.alert_soc(event, severity) ########## TBD ###################
                        logging.info("High severity event")
                        return self.rate_limit_event(event)
                    else:
                        self._set_status(AgentMode.UNDER_ATTACK, "High severity from suspect IP")
                        logging.info("High severity from already-suspect IP")
                        return self.block_event(event)

            case AgentMode.UNDER_ATTACK:
                if severity == 0:
                    self.benign_sequence += 1
                    logging.info("Benign flow passed")
                    if self.benign_sequence > 30 and self.soc_confirm == 1:
                        self.benign_sequence = 0
                        self.soc_confirm = 0
                        self._set_status(AgentMode.ALERTED, "mode Decayed to ALERTED; benign event flagged")
                        event["note"] = "Benign flagged due to UNDER_ATTACK state"
                        logging.info(event["note"])
                        return self.flag_event(event)

                    event["note"] = f"Passed Benign ({self.benign_sequence} in a row)"
                    logging.info(event["note"])
                    return self.pass_event(event)
                

                elif severity in [1, 2, 3, 4]:
                    self.benign_sequence = 0
                    logging.info("High severity event")
                    return self.block_event(event)

        return self.pass_event(event)

