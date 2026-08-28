#!/usr/bin/env python3
"""
Anoseek Policy-Agent Multi-Policy Functional Test
==================================================

Flow:
1. Uses the three editable paths near the top of this file.
2. Defines four policy configurations (A-D).
3. Loads the REAL PolicyAnoseekAgent from agent.py.
4. Replays the SAME labeled CSV from the beginning for each policy.
5. Creates a fresh agent for every policy.
6. Calls the REAL agent.analyze_and_act() for every flow.
7. Records actions, states, transitions and policy-sensitive decisions.
8. Measures whether requested enforcement actions obey the selected policy.
9. Produces one detailed CSV per policy + one comparison CSV.

Important:
- The classifier is NOT evaluated here.
  Dataset GT is mapped to Anoseek severity and confidence=1.0 is supplied.
- Bypasses Pi Configuration. 
- SOC confirmation is not simulated in this test (soc_confirm stays 0).
"""

from __future__ import annotations

import importlib.util
import ipaddress
from pathlib import Path

import pandas as pd



AGENT_PATH = Path(r".\backend\agent.py")
CSV_PATH = Path(r".\datasets\NF-CSE-CIC-IDS2018-v2K_sample.csv")
OUTPUT_DIR = Path(r".\tests\policy_test_results")


# ---------------------------------------------------------------------------
# A-D POLICY CONFIGURATIONS
# ---------------------------------------------------------------------------

# These represent the four combinations we want to compare for the configurable
# ALERTED / UNDER_ATTACK enforcement controls.
# IDLE not included since no measurements are taken with this state active. 

POLICIES = {
    "A_all_allowed": {
        "Version": "test-A",
        "Statement": [
            {"State": "ALERTED", "Action_Required": "rate_limit", "Allowed": True},
            {"State": "ALERTED", "Action_Required": "block", "Allowed": True},
            {"State": "UNDER_ATTACK", "Action_Required": "rate_limit", "Allowed": True},
            {"State": "UNDER_ATTACK", "Action_Required": "block", "Allowed": True},
        ],
    },

    "B_all_restricted": {
        "Version": "test-B",
        "Statement": [
            {"State": "ALERTED", "Action_Required": "rate_limit", "Allowed": False},
            {"State": "ALERTED", "Action_Required": "block", "Allowed": False},
            {"State": "UNDER_ATTACK", "Action_Required": "rate_limit", "Allowed": False},
            {"State": "UNDER_ATTACK", "Action_Required": "block", "Allowed": False},
        ],
    },

    "C_rate_limit_only": {
        "Version": "test-C",
        "Statement": [
            {"State": "ALERTED", "Action_Required": "rate_limit", "Allowed": True},
            {"State": "ALERTED", "Action_Required": "block", "Allowed": False},
            {"State": "UNDER_ATTACK", "Action_Required": "rate_limit", "Allowed": True},
            {"State": "UNDER_ATTACK", "Action_Required": "block", "Allowed": False},
        ],
    },

    "D_block_only": {
        "Version": "test-D",
        "Statement": [
            {"State": "ALERTED", "Action_Required": "rate_limit", "Allowed": False},
            {"State": "ALERTED", "Action_Required": "block", "Allowed": True},
            {"State": "UNDER_ATTACK", "Action_Required": "rate_limit", "Allowed": False},
            {"State": "UNDER_ATTACK", "Action_Required": "block", "Allowed": True},
        ],
    },
}


# ---------------------------------------------------------------------------
# LOAD REAL AGENT MODULE
# ---------------------------------------------------------------------------

def load_agent_module(agent_path: Path):
    spec = importlib.util.spec_from_file_location("anoseek_agent_under_test", agent_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load agent module: {agent_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # TEST-ONLY assumption:
    # every IPv4 address in the dataset is considered manageable.
    # Bypasses Pi's internal configuration
    module.INNER_NETWORK = ipaddress.ip_network("0.0.0.0/0")

    return module


# ---------------------------------------------------------------------------
# TEST 
# ---------------------------------------------------------------------------

def make_instrumented_agent_class(agent_module):
    """
    Adds logging around the REAL enforcement functions.

    It does NOT reimplement the policy agent or state machine.
    Each wrapper records that the real state machine requested an enforcement
    action, then immediately calls the production parent implementation.
    """

    class InstrumentedPolicyAgent(agent_module.PolicyAnoseekAgent):

        def __init__(self, policy, ipsum):
            super().__init__(policy, ipsum)
            self.test_last_requested_action = None
            self.test_last_policy_state = None
            self.test_last_policy_allowed = None

        def _reset_test_instrumentation(self):
            self.test_last_requested_action = None
            self.test_last_policy_state = None
            self.test_last_policy_allowed = None

        def rate_limit_event(self, event, severity):
            self.test_last_requested_action = "rate_limit"
            self.test_last_policy_state = event["agent_state"]
            self.test_last_policy_allowed = self._policy_allows(
                event["agent_state"], "rate_limit"
            )
            return super().rate_limit_event(event, severity)

        def block_event(self, event, severity):
            self.test_last_requested_action = "block"
            self.test_last_policy_state = event["agent_state"]
            self.test_last_policy_allowed = self._policy_allows(
                event["agent_state"], "block"
            )
            return super().block_event(event, severity)

    return InstrumentedPolicyAgent


# ---------------------------------------------------------------------------
# DATASET GT -> ANOSEEK SEVERITY
# ---------------------------------------------------------------------------

def gt_to_severity(label, attack_name: str) -> int:
    """
    0 = Benign
    1 = Recon / scanning
    2 = Brute force
    3 = DoS / DDoS
    4 = Other attack / exploitation

    """
    try:
        is_attack = int(label) != 0
    except (TypeError, ValueError):
        is_attack = str(label).strip().lower() not in {
            "0", "benign", "false", ""
        }

    if not is_attack:
        return 0

    attack = str(attack_name).strip().lower()

    if "recon" in attack or "scan" in attack:
        return 1

    if "brute" in attack:
        return 2

    if "ddos" in attack or "dos" in attack:
        return 3

    return 4


# ---------------------------------------------------------------------------
# POLICY-LEVEL EXPECTATION
# ---------------------------------------------------------------------------

def expected_effective_action(
    requested_action: str | None,
    policy_allowed: bool | None,
    actual_action: str,
) -> str | None:
    if requested_action not in {"rate_limit", "block"}:
        return None

    return requested_action if policy_allowed else "flag"


# ---------------------------------------------------------------------------
# ONE POLICY RUN
# ---------------------------------------------------------------------------

def run_policy(
    policy_name: str,
    policy: dict,
    df: pd.DataFrame,
    AgentClass,
    out_dir: Path,
):
    # Reloading agent
    agent = AgentClass(policy=policy, ipsum=set())

    rows = []

    for index, row in df.iterrows():
        row_number = index + 1

        src_ip = str(row["IPV4_SRC_ADDR"])
        dst_ip = str(row["IPV4_DST_ADDR"])
        severity = gt_to_severity(row["Label"], row["Attack"])

        agent._reset_test_instrumentation()

        state_before = agent.status.value
        transitions_before = len(agent.transitions)

        flow_result = {
            "flow_id": row_number,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "predicted_class": severity,

            # Preventing the low-confidence override from changing the GT severity
            # Keep this test for Agent only functionality. 
            "confidence": 1.0,
        }

        result = agent.analyze_and_act(flow_result)

        state_after = agent.status.value
        actual_action = result.get("action", "")

        transition = ""
        transition_reason = ""

        if len(agent.transitions) > transitions_before:
            latest = agent.transitions[-1]
            transition = f"{latest['from']}->{latest['to']}"
            transition_reason = latest["reason"]

        requested_action = agent.test_last_requested_action
        policy_state = agent.test_last_policy_state
        policy_allowed = agent.test_last_policy_allowed

        expected_action = expected_effective_action(
            requested_action=requested_action,
            policy_allowed=policy_allowed,
            actual_action=actual_action,
        )

        policy_sensitive = expected_action is not None

        if policy_sensitive:
            policy_compliant = actual_action == expected_action
        else:
            policy_compliant = None

        rows.append({
            "row": row_number,
            "policy": policy_name,

            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "gt_label": row["Label"],
            "gt_attack": row["Attack"],
            "test_severity": severity,

            "state_before": state_before,
            "state_after": state_after,
            "transition": transition,
            "transition_reason": transition_reason,

            # Enforce action
            "requested_enforcement_action": requested_action,

            # _policy_allows() checkup
            "policy_state_checked": policy_state,
            "policy_allowed": policy_allowed,

            # What should happen by policy
            "expected_effective_action": expected_action,

            # Actual agent output
            "actual_action": actual_action,

            "policy_sensitive": policy_sensitive,
            "policy_compliant": policy_compliant,

            "note": result.get("note", ""),
        })

    details = pd.DataFrame(rows)
    details_path = out_dir / f"{policy_name}_details.csv"
    details.to_csv(details_path, index=False)

    action_counts = details["actual_action"].value_counts()
    state_counts = details["state_after"].value_counts()

    sensitive = details[details["policy_sensitive"] == True]
    sensitive_total = len(sensitive)

    if sensitive_total:
        compliant_count = int((sensitive["policy_compliant"] == True).sum())
        compliance_pct = 100.0 * compliant_count / sensitive_total
    else:
        compliant_count = 0
        compliance_pct = None

    transitions = details[details["transition"] != ""]

    summary = {
        "policy": policy_name,
        "flows": len(details),

        "pass": int(action_counts.get("pass", 0)),
        "flag": int(action_counts.get("flag", 0)),
        "rate_limit": int(action_counts.get("rate_limit", 0)),
        "block": int(action_counts.get("block", 0)),

        "idle_rows": int(state_counts.get("idle", 0)),
        "alerted_rows": int(state_counts.get("alerted", 0)),
        "under_attack_rows": int(state_counts.get("under_attack", 0)),

        "state_transitions": len(transitions),

        "policy_sensitive_decisions": sensitive_total,
        "policy_compliant_decisions": compliant_count,
        "policy_compliance_pct": compliance_pct,
    }

    return summary, details_path


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    # Paths are configured at the top of this file.
    agent_path = AGENT_PATH.expanduser().resolve()
    csv_path = CSV_PATH.expanduser().resolve()
    out_dir = OUTPUT_DIR.expanduser().resolve()

    if not agent_path.exists():
        raise FileNotFoundError(f"agent.py not found: {agent_path}")

    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv_path)

    required = {
        "IPV4_SRC_ADDR",
        "IPV4_DST_ADDR",
        "Label",
        "Attack",
    }

    missing = required - set(df.columns)

    if missing:
        raise ValueError(
            f"CSV is missing required columns: {sorted(missing)}"
        )

    agent_module = load_agent_module(agent_path)
    AgentClass = make_instrumented_agent_class(agent_module)

    summaries = []

    print("\n=== Anoseek Multi-Policy Functional Test ===")
    print(f"Agent:   {agent_path}")
    print(f"Dataset: {csv_path}")
    print(f"Rows:    {len(df)}")
    print("Test assumption: all dataset IPv4 addresses are manageable.")
    print("SOC confirmation: not simulated (soc_confirm = 0).")

    for policy_name, policy in POLICIES.items():
        print("\n" + "=" * 65)
        print(f"POLICY: {policy_name}")
        print("=" * 65)

        summary, details_path = run_policy(
            policy_name=policy_name,
            policy=policy,
            df=df,
            AgentClass=AgentClass,
            out_dir=out_dir,
        )

        summaries.append(summary)

        print(
            "Actions: "
            f"PASS={summary['pass']} | "
            f"FLAG={summary['flag']} | "
            f"RATE_LIMIT={summary['rate_limit']} | "
            f"BLOCK={summary['block']}"
        )

        print(
            f"State transitions: {summary['state_transitions']}"
        )

        if summary["policy_compliance_pct"] is None:
            print("Policy Compliance: N/A (no policy-sensitive decisions)")
        else:
            print(
                "Policy Compliance: "
                f"{summary['policy_compliant_decisions']}/"
                f"{summary['policy_sensitive_decisions']} "
                f"= {summary['policy_compliance_pct']:.2f}%"
            )

        print(f"Detailed results: {details_path}")

    comparison = pd.DataFrame(summaries)

    comparison_path = out_dir / "policy_comparison.csv"
    comparison.to_csv(comparison_path, index=False)

    print("\n" + "=" * 65)
    print("FINAL A-D COMPARISON")
    print("=" * 65)

    display_columns = [
        "policy",
        "pass",
        "flag",
        "rate_limit",
        "block",
        "state_transitions",
        "policy_sensitive_decisions",
        "policy_compliance_pct",
    ]

    print(comparison[display_columns].to_string(index=False))

    print(f"\nComparison written to: {comparison_path}")
    print(f"All results folder:    {out_dir}")


if __name__ == "__main__":
    main()