from enum import Enum
from datetime import datetime
from collections import defaultdict
import logging
logging.basicConfig(filename="policy_agent.log", filemode='a', level=logging.INFO)


class AgentMode(Enum):
    UNDER_ATTACK = "under_attack"
    ALERTED = "alerted"
    IDLE = "idle"


class PolicyAnoseekAgent:
    def __init__(self):
        self.event_history = {}
        self.flagged_event_history = {}
        self.blocked_event_history = {}
        self.status = AgentMode.IDLE
        self.valid_severities = [0, 1, 2, 3, 4]
        self.benign_sequence = 0
        self.soc_confirm = 0

        self.alerts = {
            0: "Benign traffic.",
            1: "Monitor the source IP for additional suspicious behavior.",
            2: "Check authentication logs and consider temporary rate limiting.",
            3: "Inspect traffic volume and consider DDoS mitigation.",
            4: "Escalate immediately and investigate affected host."
        }

    def analyze_and_act(self, flow_result):
        severity = flow_result["predicted_class"]

        event_id = len(self.event_history) + 1
        event = {
            "event_id": event_id,
            "timestamp": datetime.now().isoformat(),
            "flow_id": flow_result.get("flow_id"),
            "src_ip": flow_result.get("src_ip"),
            "dst_ip": flow_result.get("dst_ip"),
            "severity": severity
        }
        self.event_history[event_id] = event

        if severity in self.valid_severities:
            self.execute_action(event, severity)

        elif severity not in [0, 1, 2, 3, 4]:
            # add to block ip list and notify
            return {
                "error": f"Unknown severity: {event['severity']}",
                "flow_id": event["flow_id"],
                "src_ip": event["src_ip"],
            }

    def flag_event(self, event):
        flagged_event_id = len(self.flagged_event_history) + 1
        self.flagged_event_history[flagged_event_id] = event

    def block_event(self, event):
        blocked_event_id = len(self.blocked_event_history) + 1
        self.blocked_event_history[blocked_event_id] = event
        self.block_ip(event)

    def alert_soc(self, event, severity):
        text = self.alerts[severity]
        # This is where the backend of the popup alert should be !

    def count_events_with_same_ip(self, event):
        count = sum(1 for e in self.event_history.values() if e["src_ip"] == event["src_ip"])
        return count

    def count_flagged_events_with_same_ip(self, event):
        count = sum(1 for e in self.flagged_event_history.values() if e["src_ip"] == event["src_ip"])
        return count

    def count_blocked_events_with_same_ip(self, event):
        count = sum(1 for e in self.blocked_event_history.values() if e["src_ip"] == event["src_ip"])
        return count

    def execute_action(self, event, severity):
        match self.status:
            case AgentMode.IDLE:
                if severity == 0:
                    logging.info("Benign flow passed")
                elif severity in [1, 2]:
                    if self.count_events_with_same_ip(event) > 3:
                        self.flag_event(event)
                        logging.info("Event has been flagged")
                    elif self.count_flagged_events_with_same_ip(event) > 2:
                        self.alert_soc(event, severity)
                        self.status = AgentMode.ALERTED
                        logging.info("SOC team attention was required. System's status updated: ALERTED.")
                elif severity in [3, 4]:
                    self.block_event(event)
                    self.status = AgentMode.ALERTED
                    logging.info("Event has been blocked. System's status updated: ALERTED.")

            case AgentMode.ALERTED:
                if severity == 0:
                    self.benign_sequence += 1
                    logging.info("Benign flow passed")
                    self.confirm_from_soc(event)
                    if (self.benign_sequence > 20) and (self.soc_confirm == 1):
                        self.benign_sequence = 0
                        self.soc_confirm = 0
                        self.status = AgentMode.IDLE
                        logging.info("System's status updated: IDLE.")

                elif severity in [1, 2]:
                    self.benign_sequence = 0
                    if self.count_flagged_events_with_same_ip(event) < 3:
                        self.flag_event(event)
                        self.alert_soc(event, severity)
                        logging.info("Event has been flagged. SOC team attention was required.")
                    elif self.count_flagged_events_with_same_ip(event) >= 3:
                        self.block_event(event)
                        self.status = AgentMode.UNDER_ATTACK
                        logging.info("Event has been blocked. System's status updated: UNDER_ATTACK.")
                elif severity in [3, 4]:
                    self.benign_sequence = 0
                    if self.count_flagged_events_with_same_ip(event) > 0:
                        self.block_event(event)
                        self.status = AgentMode.UNDER_ATTACK
                        logging.info("Event has been blocked. System's status updated: UNDER_ATTACK.")
                    else:
                        self.block_event(event)
                        self.alert_soc(event, severity)
                        logging.info("Event has been blocked. SOC team attention was required.")

            case AgentMode.UNDER_ATTACK:
                if severity == 0:
                    self.benign_sequence += 1
                    logging.info("Benign flow passed")
                    self.confirm_from_soc(event)
                    if (self.benign_sequence > 30) and (self.soc_confirm == 1):
                        self.benign_sequence = 0
                        self.soc_confirm = 0
                        self.status = AgentMode.ALERTED
                        logging.info("System's status updated: ALERTED.")
                    self.flag_event(event)
                    logging.info("Benign event has been flagged due to system's status.")
                elif severity in [1, 2, 3, 4]:
                    self.benign_sequence = 0
                    self.block_event(event)
                    logging.info("Event has been blocked.")

    def block_ip(self, event):
        logging.info("Blocking IP..")
        # This is where the actual blocking should be,
        # or we can use 'blocked_event_history' for each flow
        # before it enters!

    def block_all_flows(self, event):
        logging.info("Blocking all flows..")
        # This is where the actual blocking should be

    def confirm_from_soc(self, event):
        logging.info("Asking confirmation from SOC team..")
        # if SOC team agrees
        self.soc_confirm = 1
        # This is where the asking confirmation from SOC team should be




