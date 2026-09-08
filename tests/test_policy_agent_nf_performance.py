#!/usr/bin/env python3
"""
Anoseek Policy Agent - Non-Functional Performance Test
=======================================================

This standalone script measures the performance of the REAL PolicyAnoseekAgent.

Metrics:
- Average decision latency per Flow
- Median decision latency
- Minimum / Maximum latency
- P95 latency
- P99 latency
- Total elapsed time
- Throughput (Flows / second)

It also performs a scalability test using several dataset sizes.

IMPORTANT
---------
1. The classifier is NOT tested here.
   Ground Truth is mapped into Anoseek severity and confidence=1.0 is supplied.

2. The REAL agent.analyze_and_act() function is called for every Flow.

3. For test purposes all IPv4 addresses are assumed manageable. The imported
   agent module's INNER_NETWORK is therefore set to 0.0.0.0/0. The production
   agent.py file itself is NOT modified.

4. Each scalability run starts with a fresh agent so state/history from one
   dataset size does not leak into another.

5. If a requested test size is larger than the CSV, rows are repeated in their
   original order until that size is reached.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import math
import statistics
import time
from pathlib import Path

import pandas as pd


AGENT_PATH = Path(r".\backend\agent.py")
CSV_PATH = Path(r".\datasets\NF-CSE-CIC-IDS2018-v10K_sample.csv")
OUTPUT_DIR = Path(r".\tests\policy_test_results")

# Dataset sizes used for the scalability experiment.
TEST_SIZES = [200, 2000, 10000, 20000]

# Number of initial calls excluded from the latency statistics.
# This reduces one-time import/cache/startup effects.
WARMUP_FLOWS = 20


# Representative policy configuration used for the performance test.
# All enforcement is allowed so the real action paths remain available.
TEST_POLICY = {
    "Version": "nf-performance-test",
    "Statement": [
        {
            "State": "ALERTED",
            "Action_Required": "rate_limit",
            "Allowed": True,
        },
        {
            "State": "ALERTED",
            "Action_Required": "block",
            "Allowed": True,
        },
        {
            "State": "UNDER_ATTACK",
            "Action_Required": "rate_limit",
            "Allowed": True,
        },
        {
            "State": "UNDER_ATTACK",
            "Action_Required": "block",
            "Allowed": True,
        },
    ],
}


# ===========================================================================
# LOAD REAL AGENT MODULE
# ===========================================================================

def load_agent_module(agent_path: Path):
    spec = importlib.util.spec_from_file_location(
        "anoseek_agent_under_nf_test",
        agent_path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load agent module: {agent_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Functional/performance test assumption:
    # every IPv4 source is considered manageable.
    module.INNER_NETWORK = ipaddress.ip_network("0.0.0.0/0")

    return module


# ===========================================================================
# GT -> ANOSEEK SEVERITY
# ===========================================================================

def gt_to_severity(label, attack_name: str) -> int:
    """
    Test adapter only.

    0 = Benign
    1 = Recon / scanning
    2 = Brute force
    3 = DoS / DDoS
    4 = Other attack / exploitation

    The purpose is to isolate the Policy Agent from classifier performance.
    """

    try:
        is_attack = int(label) != 0
    except (TypeError, ValueError):
        is_attack = str(label).strip().lower() not in {
            "0",
            "benign",
            "false",
            "",
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


# ===========================================================================
# HELPERS
# ===========================================================================

def percentile(values: list[float], p: float) -> float:
    """
    Linear-interpolated percentile without requiring NumPy.
    values must be non-empty.
    """
    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    position = (len(ordered) - 1) * p
    lower = math.floor(position)
    upper = math.ceil(position)

    if lower == upper:
        return ordered[lower]

    fraction = position - lower

    return (
        ordered[lower] * (1.0 - fraction)
        + ordered[upper] * fraction
    )


def build_replayed_dataframe(df: pd.DataFrame, size: int) -> pd.DataFrame:
    """
    Produce exactly `size` rows.

    If the original dataset is smaller than size, repeat the same rows in the
    same order. This allows us to test history growth without needing multiple
    physical CSV files.
    """
    if size <= len(df):
        return df.iloc[:size].reset_index(drop=True)

    repeats = math.ceil(size / len(df))
    expanded = pd.concat([df] * repeats, ignore_index=True)

    return expanded.iloc[:size].reset_index(drop=True)


# ===========================================================================
# ONE PERFORMANCE RUN
# ===========================================================================

def run_performance_test(
    df: pd.DataFrame,
    size: int,
    AgentClass,
    output_dir: Path,
):
    test_df = build_replayed_dataframe(df, size)

    # Fresh agent for every test size.
    agent = AgentClass(
        policy=TEST_POLICY,
        ipsum=set(),
    )

    # -----------------------------------------------------------------------
    # Warm-up
    # -----------------------------------------------------------------------
    warmup_count = min(WARMUP_FLOWS, len(test_df))

    for index in range(warmup_count):
        row = test_df.iloc[index]

        severity = gt_to_severity(
            row["Label"],
            row["Attack"],
        )

        flow_result = {
            "flow_id": -(index + 1),
            "src_ip": str(row["IPV4_SRC_ADDR"]),
            "dst_ip": str(row["IPV4_DST_ADDR"]),
            "predicted_class": severity,
            "confidence": 1.0,
        }

        agent.analyze_and_act(flow_result)

    # Reset after warm-up so the measured run begins from a clean state.
    agent = AgentClass(
        policy=TEST_POLICY,
        ipsum=set(),
    )

    # -----------------------------------------------------------------------
    # Measured replay
    # -----------------------------------------------------------------------
    latency_ms: list[float] = []
    detail_rows = []

    action_counts = {
        "pass": 0,
        "flag": 0,
        "rate_limit": 0,
        "block": 0,
    }

    total_start = time.perf_counter()

    for index, row in test_df.iterrows():
        severity = gt_to_severity(
            row["Label"],
            row["Attack"],
        )

        flow_result = {
            "flow_id": index + 1,
            "src_ip": str(row["IPV4_SRC_ADDR"]),
            "dst_ip": str(row["IPV4_DST_ADDR"]),
            "predicted_class": severity,

            # Prevent classifier-confidence handling from contaminating
            # the Policy Agent performance test.
            "confidence": 1.0,
        }

        state_before = agent.status.value

        start = time.perf_counter()
        result = agent.analyze_and_act(flow_result)
        end = time.perf_counter()

        elapsed_ms = (end - start) * 1000.0

        latency_ms.append(elapsed_ms)

        action = result.get("action", "")
        state_after = agent.status.value

        if action in action_counts:
            action_counts[action] += 1

        detail_rows.append({
            "row": index + 1,
            "src_ip": flow_result["src_ip"],
            "gt_attack": row["Attack"],
            "test_severity": severity,
            "state_before": state_before,
            "state_after": state_after,
            "action": action,
            "latency_ms": elapsed_ms,
        })

    total_end = time.perf_counter()

    total_elapsed_sec = total_end - total_start

    throughput_fps = (
        len(test_df) / total_elapsed_sec
        if total_elapsed_sec > 0
        else float("inf")
    )

    avg_ms = statistics.fmean(latency_ms)
    median_ms = statistics.median(latency_ms)
    min_ms = min(latency_ms)
    max_ms = max(latency_ms)
    p95_ms = percentile(latency_ms, 0.95)
    p99_ms = percentile(latency_ms, 0.99)

    details = pd.DataFrame(detail_rows)
    detail_path = output_dir / f"agent_nf_{size}_flows_details.csv"
    details.to_csv(detail_path, index=False)

    return {
        "flows": size,

        "total_elapsed_sec": total_elapsed_sec,

        "avg_latency_ms": avg_ms,
        "median_latency_ms": median_ms,
        "min_latency_ms": min_ms,
        "max_latency_ms": max_ms,
        "p95_latency_ms": p95_ms,
        "p99_latency_ms": p99_ms,

        "throughput_flows_per_sec": throughput_fps,

        "pass_count": action_counts["pass"],
        "flag_count": action_counts["flag"],
        "rate_limit_count": action_counts["rate_limit"],
        "block_count": action_counts["block"],

        "final_state": agent.status.value,

        "details_file": str(detail_path),
    }


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    agent_path = AGENT_PATH.expanduser().resolve()
    csv_path = CSV_PATH.expanduser().resolve()
    output_dir = OUTPUT_DIR.expanduser().resolve()

    if not agent_path.exists():
        raise FileNotFoundError(
            f"agent.py not found:\n{agent_path}"
        )

    if not csv_path.exists():
        raise FileNotFoundError(
            f"CSV not found:\n{csv_path}"
        )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    df = pd.read_csv(csv_path)

    required_columns = {
        "IPV4_SRC_ADDR",
        "IPV4_DST_ADDR",
        "Label",
        "Attack",
    }

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"CSV missing required columns: {sorted(missing)}"
        )

    agent_module = load_agent_module(agent_path)
    AgentClass = agent_module.PolicyAnoseekAgent

    print("\n=== Anoseek Policy Agent - Non-Functional Performance Test ===")
    print(f"Agent:       {agent_path}")
    print(f"Dataset:     {csv_path}")
    print(f"Source rows: {len(df)}")
    print(f"Test sizes:  {TEST_SIZES}")
    print(f"Warm-up:     {WARMUP_FLOWS} flows")
    print("Classifier:  bypassed using GT-derived severity")
    print("IP scope:    all IPv4 addresses assumed manageable")

    summaries = []

    for size in TEST_SIZES:
        print("\n" + "=" * 72)
        print(f"RUNNING PERFORMANCE TEST: {size:,} FLOWS")
        print("=" * 72)

        result = run_performance_test(
            df=df,
            size=size,
            AgentClass=AgentClass,
            output_dir=output_dir,
        )

        summaries.append(result)

        print(
            f"Total elapsed:  "
            f"{result['total_elapsed_sec']:.6f} sec"
        )

        print(
            f"Average latency: "
            f"{result['avg_latency_ms']:.6f} ms"
        )

        print(
            f"Median latency:  "
            f"{result['median_latency_ms']:.6f} ms"
        )

        print(
            f"P95 latency:     "
            f"{result['p95_latency_ms']:.6f} ms"
        )

        print(
            f"P99 latency:     "
            f"{result['p99_latency_ms']:.6f} ms"
        )

        print(
            f"Minimum latency: "
            f"{result['min_latency_ms']:.6f} ms"
        )

        print(
            f"Maximum latency: "
            f"{result['max_latency_ms']:.6f} ms"
        )

        print(
            f"Throughput:      "
            f"{result['throughput_flows_per_sec']:.2f} flows/sec"
        )

        print(
            "Actions: "
            f"PASS={result['pass_count']} | "
            f"FLAG={result['flag_count']} | "
            f"RATE_LIMIT={result['rate_limit_count']} | "
            f"BLOCK={result['block_count']}"
        )

    summary_df = pd.DataFrame(summaries)

    summary_path = output_dir / "agent_nf_scalability_summary.csv"
    summary_df.to_csv(
        summary_path,
        index=False,
    )

    print("\n" + "=" * 72)
    print("FINAL SCALABILITY SUMMARY")
    print("=" * 72)

    display_columns = [
        "flows",
        "total_elapsed_sec",
        "avg_latency_ms",
        "p95_latency_ms",
        "max_latency_ms",
        "throughput_flows_per_sec",
    ]

    print(
        summary_df[display_columns].to_string(
            index=False,
            float_format=lambda x: f"{x:.6f}",
        )
    )

    print(
        f"\nSummary written to:\n{summary_path}"
    )

    print(
        f"\nDetailed per-flow result files written to:\n{output_dir}"
    )


if __name__ == "__main__":
    main()
