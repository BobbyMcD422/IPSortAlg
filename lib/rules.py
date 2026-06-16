from collections import defaultdict, deque
from ipaddress import ip_address
from pathlib import Path
import re

import pandas as pd

ATTACK_LABEL = "attack"
NORMAL_LABEL = "normal"


def load_blacklist(blacklist_file):
    blacklist_file = Path(blacklist_file)

    if not blacklist_file.exists():
        return set()

    return {
        line.strip().lower()
        for line in blacklist_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def extract_host(endpoint):
    endpoint = str(endpoint).strip().lower()

    if endpoint.startswith("[") and "]" in endpoint:
        return endpoint[1:endpoint.index("]")]

    if endpoint.count(":") == 1:
        host, port = endpoint.rsplit(":", 1)
        if port.isdigit():
            return host

    return endpoint


def is_valid_host(host):
    if not host or host in {"nan", "none"}:
        return False

    try:
        ip_address(host)
        return True
    except ValueError:
        pass

    if len(host) > 253:
        return False

    hostname_pattern = re.compile(
        r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
    )
    return bool(hostname_pattern.fullmatch(host))


def save_new_blacklist_entries(blacklist_file, entries):
    if not entries:
        return

    blacklist_file.parent.mkdir(parents=True, exist_ok=True)
    needs_leading_newline = (
        blacklist_file.exists()
        and blacklist_file.stat().st_size > 0
        and not blacklist_file.read_bytes().endswith(b"\n")
    )

    with blacklist_file.open("a", encoding="utf-8") as file:
        if needs_leading_newline:
            file.write("\n")
        for entry in sorted(entries):
            file.write(f"{entry}\n")


def apply_rules(
    data_file,
    blacklist_file="data/blacklist.txt",
    output_file="data/predictions.csv",
    target_column="Source",
):
    data_file = Path(data_file)
    blacklist_file = Path(blacklist_file)
    output_file = Path(output_file)

    df = pd.read_csv(data_file)
    required_columns = {"time", "IP"}
    missing_columns = required_columns.difference(df.columns)

    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Missing required columns in {data_file}: {missing}")

    source_was_provided = target_column in df.columns
    expected_labels = None
    if source_was_provided:
        expected_labels = (
            df[target_column]
            .fillna(NORMAL_LABEL)
            .astype(str)
            .str.strip()
            .str.lower()
            .replace("", NORMAL_LABEL)
        )

    blacklist = load_blacklist(blacklist_file)
    working = df.copy()
    working["_original_order"] = range(len(working))
    working["_time"] = pd.to_numeric(working["time"], errors="raise")
    working["_endpoint"] = working["IP"].astype(str).str.strip().str.lower()
    working["_host"] = working["_endpoint"].map(extract_host)
    working = working.sort_values(["_time", "_original_order"]).reset_index(drop=True)

    host_windows_5 = defaultdict(deque)
    host_windows_30 = defaultdict(deque)
    labels = []
    reasons = []
    counts_5 = []
    counts_30 = []
    newly_blacklisted = set()

    events = zip(working["_host"], working["_endpoint"], working["_time"])
    for host, endpoint, event_time in events:
        window_5 = host_windows_5[host]
        window_30 = host_windows_30[host]

        while window_5 and window_5[0] < event_time - 5:
            window_5.popleft()
        while window_30 and window_30[0] < event_time - 30:
            window_30.popleft()

        window_5.append(event_time)
        window_30.append(event_time)
        count_5 = len(window_5)
        count_30 = len(window_30)

        if host in blacklist or endpoint in blacklist:
            label = ATTACK_LABEL
            reason = "blacklist"
        elif count_5 >= 3:
            label = ATTACK_LABEL
            reason = "3_or_more_events_from_same_host_within_5_seconds"
        elif count_30 >= 5:
            label = ATTACK_LABEL
            reason = "5_or_more_events_from_same_host_within_30_seconds"
        else:
            label = NORMAL_LABEL
            reason = "no_rule_matched"

        if (
            label == ATTACK_LABEL
            and reason != "blacklist"
            and is_valid_host(host)
        ):
            blacklist.add(host)
            newly_blacklisted.add(host)

        labels.append(label)
        reasons.append(reason)
        counts_5.append(count_5)
        counts_30.append(count_30)

    working[target_column] = labels
    working["rule_match"] = reasons
    working["same_host_events_last_5_seconds"] = counts_5
    working["same_host_events_last_30_seconds"] = counts_30
    working = working.sort_values("_original_order")

    output_columns = list(df.columns)
    if target_column not in output_columns:
        output_columns.append(target_column)

    results = working[
        output_columns
        + [
            "rule_match",
            "same_host_events_last_5_seconds",
            "same_host_events_last_30_seconds",
        ]
    ].copy()

    output_file.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_file, index=False)
    save_new_blacklist_entries(blacklist_file, newly_blacklisted)

    accuracy = None
    if expected_labels is not None:
        predicted_labels = results[target_column].reset_index(drop=True)
        accuracy = float((predicted_labels == expected_labels.reset_index(drop=True)).mean())

    return {
        "data_file": data_file,
        "blacklist_file": blacklist_file,
        "output_file": output_file,
        "rows_checked": len(results),
        "attacks_found": int((results[target_column] == ATTACK_LABEL).sum()),
        "newly_blacklisted": sorted(newly_blacklisted),
        "accuracy": accuracy,
        "results": results,
        "target_column": target_column,
    }
