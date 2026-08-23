from enum import Enum
from datetime import datetime
from collections import defaultdict, deque
import ipaddress
import math
from threading import Lock
import logging

logging.basicConfig(filename="policy_agent.log", filemode='w', level=logging.INFO)

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


LOW_CONFIDENCE_THRESHOLD = 0.73
ALERTED_BENIGNS = 4
UNDER_ATTACK_BENIGNS = 5
INNER_NETWORK = ipaddress.ip_network("10.42.0.0/24")

class PolicyAnoseekAgent:
    def __init__(self, policy: dict, ipsum):
        # Primary stores: event_id -> event dict
        self.event_history: dict[int, dict] = {}
        self.flagged_event_history: dict[int, dict] = {}
        self.blocked_event_history: dict[int, dict] = {}
        self.rate_limited_event_history: dict[int, dict] = {}

        # Per-IP indexes — list of event_ids per src_ip, for O(1) counts
        self.events_by_ip: dict[str, list[int]] = defaultdict(list)
        self.sev_0_events: dict[str, int] = defaultdict(int)
        self.sev_1_2_events: dict[str, int] = defaultdict(int) 
        self.sev_3_4_events: dict[str, int] = defaultdict(int)
        self.sev_flagged_1_2_events: dict[str, int] = defaultdict(int) 
        self.sev_flagged_3_4_events: dict[str, int] = defaultdict(int)
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

        # Every raw flow handed to the pipeline, regardless of whether the
        # per-IP sequence buffer emitted a classification for it yet — unlike
        # event_history, this isn't reduced by SEQ_LENGTH buffering.
        self.flows_seen: int = 0

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
        predicted_severity = flow_result["predicted_class"]
        confidence = flow_result.get("confidence")

        # A prediction the model itself isn't confident about isn't trusted
        # enough to act on — treat it as benign rather than risk a block/alert
        # on a shaky call. The original prediction is still surfaced via the
        # low-confidence alert below, for SOC visibility.
        low_confidence = isinstance(confidence, (int, float)) and confidence < LOW_CONFIDENCE_THRESHOLD
        action_severity = 0 if low_confidence else predicted_severity

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
            "severity": action_severity,
            "severity_label": self._label(action_severity),
            "confidence": confidence,
            "agent_state": self.status.value,
            "note":"",
            "action":"",
            }
        self.event_history[event_id] = event
        if event["src_ip"]:
            self.events_by_ip[event["src_ip"]].append(event_id)
            if action_severity  == 0:
                self.sev_0_events[event["src_ip"]] += 1
            elif action_severity  == 1 or action_severity  == 2:
                self.sev_1_2_events[event["src_ip"]] += 1
            elif action_severity  == 3 or action_severity  == 4:
                self.sev_3_4_events[event["src_ip"]] += 1

            self.last_event_ip = event["src_ip"]


        if low_confidence:
            self.flag_low_confidence(event, predicted_severity)

        if action_severity  not in self.valid_severities:
            return {
                "ok": False,
                "error": f"Unknown severity: {action_severity}",
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

        # TODO:
        #if src_ip and src_ip in self.blocked_by_ip:
        #     event["note"] = "Source IP in model blocked IPs list"
        #     event["action"] = "block"
        #     return self.block_ip(event)

        event = self.execute_action(event, action_severity)

        # Every suspicious (non-benign) flow gets a SOC-visible alert, unless the
        # agent already took an automated block/rate_limit on it — that action's
        # own "Automated ..." alert (see _alert_enforcement_action) is enough,
        # a second generic warning on top of it would just be noise.
        if action_severity > 0 and event.get("action") not in ("block", "rate_limit"):
            self.alert_soc(event, action_severity)

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
            "severity": event["severity"],
            "severity_label": event["severity_label"],
            "confidence": event["confidence"],
            "action": event["action"],
            "note": event["note"],
            "agent_state": self.status.value,
        }

    def record_flow_seen(self) -> None:
        """Called once per raw flow handed to the pipeline, before any buffering
        or classification — keeps flows_seen equal to the actual input volume."""
        with self._lock:
            self.flows_seen += 1

    def confirm_from_soc(self, confirmed: bool = True) -> dict:
        """
        Called by the API when SOC clicks Confirm (confirmed=True) or Deny (confirmed=False).
        soc_confirm=1 unlocks escalation actions and allows state decay.
        soc_confirm=-1 (denied) keeps the agent restricted until the flag is reset.
        """
        self.soc_confirm = 1 if confirmed else -1
        if not confirmed:
            # SOC looked at the streak and rejected it — the traffic that built
            # it up wasn't actually clean, so it shouldn't get credit toward a
            # future decay either. Start the streak over.
            self.benign_sequence = 0
        logging.info("SOC %s (soc_confirm=%d)", "confirmed" if confirmed else "denied", self.soc_confirm)
        return {
            "ok": True,
            "confirmed": confirmed,
            "soc_confirm": self.soc_confirm,
            "status": self.status.value,
        }

    def rate_limit_ip_manual(self, src_ip: str) -> dict:
        """Add an IP to the rate limit list. SOC button. Mutually exclusive with block."""
        with self._lock:
            stale_blocked_ids = self.blocked_by_ip.pop(src_ip, [])
            for blocked_id in stale_blocked_ids:
                self.blocked_event_history.pop(blocked_id, None)

            self.rate_limited_by_ip[src_ip]  # ensure key exists even if no events yet
            for event_id in self.events_by_ip.get(src_ip, []):
                event = self.event_history.get(event_id)
                if event is None:
                    continue
                self.flagged_event_history.pop(event_id, None)      
                event["action"] = "rate_limit"
                event["note"] = "Manual SOC rate limit"
                self.rate_limited_event_history[event_id] = event
                self.rate_limited_by_ip[src_ip].append(event_id)
            self.flagged_by_ip[src_ip] = [                            
                i for i in self.flagged_by_ip.get(src_ip, [])
                if i not in self.events_by_ip.get(src_ip, [])          
            ]
        logging.info("Manually rate limited IP %s", src_ip)
        return {"ok": True, "src_ip": src_ip, "action": "rate_limit"}

    def rate_unlimit_manual(self, src_ip: str) -> dict:
        """Remove an IP from the rate limit list. SOC undo."""
        with self._lock:
            rate_limited_ids = self.rate_limited_by_ip.pop(src_ip, [])
            for event_id in rate_limited_ids:
                self.rate_limited_event_history.pop(event_id, None)
                event = self.event_history.get(event_id)
                if event is not None:
                    event["action"] = "pass"
                    event["note"] = "Manual SOC rate limit lifted"
        logging.info("Manually rate unlimited IP %s", src_ip)
        return {"ok": True, "src_ip": src_ip, "action": "pass"}

    def block_ip_manual(self, src_ip: str) -> dict:
        """Add an IP to the blocklist. SOC button. Mutually exclusive with rate limit."""
        with self._lock:
            stale_rate_limited_ids = self.rate_limited_by_ip.pop(src_ip, [])
            for rate_limited_id in stale_rate_limited_ids:
                self.rate_limited_event_history.pop(rate_limited_id, None)

            self.blocked_by_ip[src_ip]  # ensure key exists even if no events yet
            for event_id in self.events_by_ip.get(src_ip, []):
                event = self.event_history.get(event_id)
                if event is None:
                    continue
                self.flagged_event_history.pop(event_id, None)      
                event["action"] = "block"
                event["note"] = "Manual SOC block"
                self.blocked_event_history[event_id] = event
                self.blocked_by_ip[src_ip].append(event_id)
            self.flagged_by_ip[src_ip] = [                            
                i for i in self.flagged_by_ip.get(src_ip, [])
                if i not in self.events_by_ip.get(src_ip, [])
            ]
        logging.info("Manually blocked IP %s", src_ip)
        return {"ok": True, "src_ip": src_ip, "action": "block"}

    def unblock_ip_manual(self, src_ip: str) -> dict:
        """Remove an IP from the blocklist. SOC undo."""
        with self._lock:
            blocked_ids = self.blocked_by_ip.pop(src_ip, [])
            for event_id in blocked_ids:
                self.blocked_event_history.pop(event_id, None)
                event = self.event_history.get(event_id)
                if event is not None:
                    event["action"] = "pass"
                    event["note"] = "Manual SOC block lifted"
        logging.info("Manually unblocked IP %s", src_ip)
        return {"ok": True, "src_ip": src_ip, "action": "pass"}
    

    def force_block_missing_data(self, flow: dict, missing_columns: list[str]) -> dict:
        """
        Unconditionally blocks the source IP when a flow is missing always-required
        fields. Bypasses policy Allowed rules and SOC confirmation entirely: an
        incomplete capture can hide a real attack from the model, so it isn't
        given the benefit of a "benign" guess while we wait for policy/SOC.
        """
        src_ip = flow.get("IPV4_SRC_ADDR") or flow.get("src_ip")
        dst_ip = flow.get("IPV4_DST_ADDR") or flow.get("dst_ip")
        note = f"Missing critical fields: {', '.join(missing_columns)}"

        with self._lock:
            event_id = self._next_event_id
            self._next_event_id += 1
            event = {
                "event_id": event_id,
                "timestamp": datetime.now().isoformat(),
                "flow_id": flow.get("flow_id"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": None,
                "severity_label": "Data integrity failure",
                "confidence": None,
                "agent_state": self.status.value,
                "note": note,
                "action": "block",
            }
            self.event_history[event_id] = event
            if src_ip:
                self.events_by_ip[src_ip].append(event_id)
                self.last_event_ip = src_ip

            blocked_event_id = len(self.blocked_event_history) + 1
            self.blocked_event_history[blocked_event_id] = event
            if src_ip:
                self.blocked_by_ip[src_ip].append(blocked_event_id)

            self._alert_queue.append({
                "alert_id": len(self._alert_queue),
                "event_id": event_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": None,
                "severity_label": "Data integrity failure",
                "text": f"Flow blocked: {note}. Incomplete captures can mask a real "
                        "attack, so this bypassed policy/SOC confirmation.",
                "timestamp": event["timestamp"],
            })

        logging.info("Force-blocked IP %s — %s", src_ip, note)
        return {
            "ok": True,
            "event_id": event_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "severity": None,
            "severity_label": "Data integrity failure",
            "action": "block",
            "note": note,
            "agent_state": self.status.value,
            "confidence": None,
        }

    def flag_data_quality(self, flow: dict, tier2_issues: list[dict]) -> None:
        """
        Raises a SOC-visible alert for protocol-relevant fields missing from a
        flow. Visibility only — doesn't block or otherwise change how the flow
        is handled; classification still proceeds normally.
        """
        src_ip = flow.get("IPV4_SRC_ADDR") or flow.get("src_ip")
        dst_ip = flow.get("IPV4_DST_ADDR") or flow.get("dst_ip")
        labels = ", ".join(f"{g['label']} ({', '.join(g['columns'])})" for g in tier2_issues)
        text = f"Flow missing protocol-relevant fields: {labels}."

        with self._lock:
            self._alert_queue.append({
                "alert_id": len(self._alert_queue),
                "event_id": None,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": None,
                "severity_label": "Data quality",
                "text": text,
                "timestamp": datetime.now().isoformat(),
            })

        logging.info("Data-quality alert for %s: %s", src_ip, labels)

    def flag_low_confidence(self, event: dict, predicted_severity: int) -> None:
        """
        Raises a SOC-visible alert when a flow's confidence falls below
        LOW_CONFIDENCE_THRESHOLD. The caller has already downgraded the
        event's effective severity to Benign in this case — this alert is
        how SOC still gets visibility into what the model originally predicted.
        """
        conf = event.get("confidence")
        with self._lock:
            self._alert_queue.append({
                "alert_id": len(self._alert_queue),
                "event_id": event.get("event_id"),
                "src_ip": event.get("src_ip"),
                "dst_ip": event.get("dst_ip"),
                "severity": event.get("severity"),
                "severity_label": event.get("severity_label"),
                "text": f"Low-confidence prediction ({conf:.3f}) — model predicted "
                        f"{self._label(predicted_severity)} but confidence was too low; treated as Benign.",
                "timestamp": event.get("timestamp", datetime.now().isoformat()),
            })

        logging.info("Low-confidence override: event=%s predicted=%s confidence=%.3f -> treated as Benign",
                     event.get("event_id"), predicted_severity, conf)

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
                    "flows_seen": self.flows_seen,
                    "events": len(self.event_history),
                    "flagged": len(self.flagged_event_history),
                    "rate_limited": len(self.rate_limited_event_history),
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
                "rate_limited": self.rate_limited_event_history,
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

    def flag_event(self, event, severity):
        if severity == 1 or severity == 2:
            self.sev_flagged_1_2_events[event["src_ip"]] += 1
        elif severity == 3 or severity == 4:
            self.sev_flagged_3_4_events[event["src_ip"]] += 1

        event_id = event["event_id"]
        self.flagged_event_history[event_id] = event
        self.flagged_by_ip[event["src_ip"]].append(event_id)

        if not event.get("note"):
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

    def _alert_enforcement_action(self, event: dict, action: str) -> None:
        """SOC-visible alert for an automated block/rate_limit the agent just took."""
        label = action.replace("_", " ")
        with self._lock:
            self._alert_queue.append({
                "alert_id": len(self._alert_queue),
                "event_id": event.get("event_id"),
                "src_ip": event.get("src_ip"),
                "dst_ip": event.get("dst_ip"),
                "severity": event.get("severity"),
                "severity_label": event.get("severity_label"),
                "text": f"Automated {label}: {event.get('src_ip')} ({event.get('severity_label')}).",
                "timestamp": event.get("timestamp", datetime.now().isoformat()),
            })
        logging.info("Automated %s alert for %s", action, event.get("src_ip"))

    def rate_limit_event(self, event, severity):
        if self._policy_allows(event["agent_state"], "rate_limit") or self.soc_confirm == 1:
            rate_limit_event_id = len(self.rate_limited_event_history) + 1
            self.rate_limited_event_history[rate_limit_event_id] = event
            if event["src_ip"]:
                self.rate_limited_by_ip[event["src_ip"]].append(rate_limit_event_id)
            event["note"] = "rate_limit, Repeated flags while alerted; rate limited"
            event["action"] = "rate_limit"
            self._alert_enforcement_action(event, "rate_limit")
            return self.rate_limit_ip(event)

        event["note"] = "rate limit action is restricted by policy and SOC"
        return self.flag_event(event, severity)

    def block_event(self, event, severity):
        if self._policy_allows(event["agent_state"], "block") or self.soc_confirm == 1:
            src_ip = ipaddress.ip_address(event["src_ip"])
            logging.info("SRC IP %s\n", src_ip)
            if src_ip in INNER_NETWORK:
                blocked_event_id = len(self.blocked_event_history) + 1
                self.blocked_event_history[blocked_event_id] = event
                self.blocked_by_ip[event["src_ip"]].append(blocked_event_id)
                event["note"] = "block, IP blocked by policy"
                event["action"] = "block"
                self._alert_enforcement_action(event, "block")
                return self.block_ip(event)
            # else:
            #     event["note"] = "block requested, but source IP is outside managed hotspot network"
            #     event["action"] = "no_action"
            #     return event

        event["note"] = "block action is restricted by policy and SOC"
        return self.flag_event(event, severity)
                

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

    def _set_status(self, new: AgentMode, reason: str, event: dict | None = None):
        if new == self.status:
            return
        old = self.status
        self.status = new
        self.entered_state_at = datetime.now().isoformat()
        self.transitions.append({
            "from": old.value, "to": new.value,
            "reason": reason, "at": self.entered_state_at,
            "event_id": event.get("event_id") if event else None,
            "src_ip": event.get("src_ip") if event else None,
            "dst_ip": event.get("dst_ip") if event else None,
            "severity_label": event.get("severity_label") if event else None,
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


    def check_statistics_sev(self, severity):
        std = 0
        num_of_events = 0
        if severity == 1 or severity == 2:
            events = self.sev_1_2_events
        elif severity == 3 or severity == 4:
            events = self.sev_3_4_events

        num_of_unique_ips = len(self.events_by_ip)

        for count in events.values():
            num_of_events += count

        if num_of_unique_ips < 2:
            return 2, 0.1
        
        mean = num_of_events / num_of_unique_ips
        for count in events.values():
            std += math.pow(count - mean, 2)
            
        std = math.sqrt(std / (num_of_unique_ips-1))

        return mean, std

    def check_flagged_statistics_sev(self, severity):
            std = 0
            num_of_events = 0
            if severity == 1 or severity == 2:
                events = self.sev_flagged_1_2_events
            elif severity == 3 or severity == 4:
                events = self.sev_flagged_3_4_events

            num_of_unique_ips = len(self.events_by_ip)
    
            for count in events.values():
                num_of_events += count

            if num_of_unique_ips < 2:
                return 1, 0.1

            mean = num_of_events / num_of_unique_ips
            for count in events.values():
                std += math.pow(count - mean, 2)
                
            std = math.sqrt(std / (num_of_unique_ips-1))
    
            return mean, std

    # === state machine
    def execute_action(self, event, severity) -> tuple[str, str]:
        """Returns (action, note) so analyze_and_act can serialize what happened."""
        if severity != 0:
            mean_flagged, std_flagged = self.check_flagged_statistics_sev(severity)
            threshold_flagged = mean_flagged + 2.4 * std_flagged
            mean, std = self.check_statistics_sev(severity)
            threshold = mean + 2.4 * std

        if self.status == AgentMode.IDLE:
            if severity == 0:
                event["note"] = "Benign flow passed"
                logging.info(event["note"])
                return self.pass_event(event)

            elif severity in [1, 2]:
                if self.count_flagged_events_with_same_ip(event) > threshold_flagged:
                    self._set_status(AgentMode.ALERTED, "Repeated flags over threshold", event)
                    event["note"] = "Repeated flags alert, SOC notified"
                    logging.info(event["note"])
                    return self.flag_event(event, severity)
                elif self.count_events_with_same_ip(event) > threshold:
                    event["note"] = "Event flagged, Repeated low-severity activity from this IP"
                    logging.info(event["note"])
                    return self.flag_event(event, severity)

                event["note"] = "Passed single low-severity event, monitoring"
                logging.info(event["note"])
                return self.pass_event(event)

            elif severity in [3, 4]:
                self.benign_sequence = 0
                if self.count_flagged_events_with_same_ip(event) < threshold_flagged:
                    logging.info(f"STAT FROM [3,4]: count_flagged_events_with_same_ip: {self.count_flagged_events_with_same_ip(event)}")
                    logging.info(f"STAT FROM [3,4]: threshold_flagged: {threshold_flagged}")
                    logging.info("High severity event")
                    return self.rate_limit_event(event, severity)
                else:
                    self._set_status(AgentMode.ALERTED, "High severity from suspect IP", event)
                    logging.info("High severity from already-suspect IP")
                    return self.block_event(event, severity)

        elif self.status == AgentMode.ALERTED:
            if severity == 0:
                self.benign_sequence += 1
                logging.info("Benign flow passed")
                if self.benign_sequence > ALERTED_BENIGNS and self.soc_confirm == 1:
                    self.benign_sequence = 0
                    self.soc_confirm = 0
                    self._set_status(AgentMode.IDLE, "Sustained benign + SOC confirm", event)
                    event["note"] = "Passed, Benign streak; returned to IDLE"
                    logging.info(event["note"])
                    return self.pass_event(event)

                event["note"] = f"Passed Benign ({self.benign_sequence} Score)"
                logging.info(event["note"])
                return self.pass_event(event)
            elif severity in [1, 2]:
                if self.benign_sequence >= 1:
                    self.benign_sequence -= 1
                threshold_flagged = mean_flagged + 2.25 * std_flagged
                logging.info(f"ALERTED: STAT FROM [1,2]: threshold_flagged: {threshold_flagged}")
                if self.count_flagged_events_with_same_ip(event) < threshold_flagged:
                    event["note"] = "Flagged and SOC notified"
                    logging.info(event["note"])
                    return self.flag_event(event, severity)
                else:
                    self._set_status(AgentMode.UNDER_ATTACK, "Repeated flags in Alerted mode", event)
                    logging.info("Repeated flags in Alerted mode")
                    return self.rate_limit_event(event, severity)

            elif severity in [3, 4]:
                if self.benign_sequence >= 1:
                    self.benign_sequence -= 1
                threshold_flagged = mean_flagged + 2.2 * std_flagged
                logging.info(f"ALERTED: STAT FROM [3,4]: threshold_flagged: {threshold_flagged}")
                if self.count_flagged_events_with_same_ip(event) < threshold_flagged:
                    logging.info("High severity event")
                    return self.rate_limit_event(event, severity)
                else:
                    self._set_status(AgentMode.UNDER_ATTACK, "High severity from suspect IP", event)
                    logging.info("High severity from already-suspect IP")
                    return self.block_event(event, severity)

        elif self.status == AgentMode.UNDER_ATTACK:
            if severity == 0:
                self.benign_sequence += 1
                logging.info("Benign flow passed")
                if self.benign_sequence > UNDER_ATTACK_BENIGNS and self.soc_confirm == 1:
                    self.benign_sequence = 0
                    self.soc_confirm = 0
                    self._set_status(AgentMode.ALERTED, "mode Decayed to ALERTED", event)
                    event["note"] = "Benign flagged due to UNDER_ATTACK state"
                    logging.info(event["note"])
                    return self.pass_event(event)

                event["note"] = f"Passed Benign ({self.benign_sequence} Score)"
                logging.info(event["note"])
                return self.pass_event(event)

            elif severity in [1, 2]:
                if self.benign_sequence >= 2:
                    self.benign_sequence -= 2
                logging.info("High severity event")
                return self.rate_limit_event(event, severity)
            elif severity in [3, 4]:
                if self.benign_sequence >= 3:
                    self.benign_sequence -= 3
                logging.info("Critical severity event")
                return self.block_event(event, severity)

        return self.pass_event(event)

