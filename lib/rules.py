from collections import defaultdict, deque
from ipaddress import ip_address
from pathlib import Path
import re

import pandas as pd

ATTACK_LABEL = "attack"
NORMAL_LABEL = "normal"
BURST_HOST_THRESHOLD = 5
BURST_WINDOW_SECONDS = 5
EXTREME_BURST_THRESHOLD = 50
EXTREME_BURST_WINDOW_SECONDS = 2


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


def save_new_candidate_entries(candidate_file, entries):
    if not entries:
        return

    existing_entries = load_blacklist(candidate_file)
    new_entries = sorted(set(entries).difference(existing_entries))

    if not new_entries:
        return

    candidate_file.parent.mkdir(parents=True, exist_ok=True)
    needs_leading_newline = (
        candidate_file.exists()
        and candidate_file.stat().st_size > 0
        and not candidate_file.read_bytes().endswith(b"\n")
    )

    with candidate_file.open("a", encoding="utf-8") as file:
        if needs_leading_newline:
            file.write("\n")
        for entry in new_entries:
            file.write(f"{entry}\n")


def append_unique_entries(target_file, entries):
    target_file = Path(target_file)
    existing_entries = load_blacklist(target_file)
    new_entries = sorted(set(entries).difference(existing_entries))

    if not new_entries:
        return []

    target_file.parent.mkdir(parents=True, exist_ok=True)
    needs_leading_newline = (
        target_file.exists()
        and target_file.stat().st_size > 0
        and not target_file.read_bytes().endswith(b"\n")
    )

    with target_file.open("a", encoding="utf-8") as file:
        if needs_leading_newline:
            file.write("\n")
        for entry in new_entries:
            file.write(f"{entry}\n")

    return new_entries


def remove_entries(target_file, entries):
    target_file = Path(target_file)

    if not target_file.exists():
        return

    entries = set(entries)
    kept_lines = []

    for line in target_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip().lower()
        if stripped in entries:
            continue
        kept_lines.append(line)

    target_file.write_text("\n".join(kept_lines) + "\n", encoding="utf-8")


def normalize_event_columns(df):
    renamed_columns = {}

    for column in df.columns:
        normalized = str(column).strip().lower()
        if normalized == "time":
            renamed_columns[column] = "time"
        elif normalized == "ip":
            renamed_columns[column] = "IP"
        elif normalized.startswith("source"):
            renamed_columns[column] = "Source"
        else:
            renamed_columns[column] = str(column).strip()

    return df.rename(columns=renamed_columns)


def find_header_row(raw_df):
    for index, row in raw_df.iterrows():
        values = {str(value).strip().lower() for value in row.dropna()}
        if "time" in values and "ip" in values:
            return index

    raise ValueError("Could not find a header row containing time and IP")


def read_event_file(data_file):
    suffix = data_file.suffix.lower()

    if suffix == ".csv":
        return normalize_event_columns(pd.read_csv(data_file))
    if suffix == ".xlsx":
        raw_df = pd.read_excel(data_file, header=None)
        header_row = find_header_row(raw_df)
        df = raw_df.iloc[header_row + 1:].copy()
        df.columns = raw_df.iloc[header_row].astype(str).str.strip()
        df = df.dropna(how="all").reset_index(drop=True)
        return normalize_event_columns(df)

    raise ValueError(f"Unsupported input file type: {data_file.suffix}")


def max_events_in_window(times, window_seconds):
    sorted_times = sorted(times)
    best_count = 0
    window_start = 0

    for window_end, event_time in enumerate(sorted_times):
        while sorted_times[window_start] < event_time - window_seconds:
            window_start += 1
        best_count = max(best_count, window_end - window_start + 1)

    return best_count


def apply_rules(
    data_file,
    blacklist_file="data/blacklist.txt",
    blacklist_candidates_file="data/blacklist_candidates.txt",
    output_file="data/predictions.csv",
    target_column="Source",
):
    data_file = Path(data_file)
    blacklist_file = Path(blacklist_file)
    blacklist_candidates_file = Path(blacklist_candidates_file)
    output_file = Path(output_file)

    df = read_event_file(data_file)
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
    max_burst_counts = (
        working.groupby("_host")["_time"]
        .apply(lambda times: max_events_in_window(times, BURST_WINDOW_SECONDS))
        .to_dict()
    )
    working["_host_max_burst_events"] = working["_host"].map(max_burst_counts)
    working = working.sort_values(["_time", "_original_order"]).reset_index(drop=True)

    host_windows_5 = defaultdict(deque)
    host_windows_30 = defaultdict(deque)
    host_windows_extreme_burst = defaultdict(deque)
    labels = []
    reasons = []
    counts_5 = []
    counts_30 = []
    counts_extreme_burst = []
    candidate_hosts = set()

    events = zip(
        working["_host"],
        working["_endpoint"],
        working["_time"],
        working["_host_max_burst_events"],
    )
    for host, endpoint, event_time, host_max_burst_events in events:
        window_5 = host_windows_5[host]
        window_30 = host_windows_30[host]
        window_extreme_burst = host_windows_extreme_burst[host]

        while window_5 and window_5[0] < event_time - 5:
            window_5.popleft()
        while window_30 and window_30[0] < event_time - 30:
            window_30.popleft()
        while (
            window_extreme_burst
            and window_extreme_burst[0] < event_time - EXTREME_BURST_WINDOW_SECONDS
        ):
            window_extreme_burst.popleft()

        window_5.append(event_time)
        window_30.append(event_time)
        window_extreme_burst.append(event_time)
        count_5 = len(window_5)
        count_30 = len(window_30)
        count_extreme_burst = len(window_extreme_burst)

        if host in blacklist or endpoint in blacklist:
            label = ATTACK_LABEL
            reason = "blacklist"
        elif host_max_burst_events >= BURST_HOST_THRESHOLD:
            label = ATTACK_LABEL
            reason = (
                f"{BURST_HOST_THRESHOLD}_or_more_events_from_same_host_within_"
                f"{BURST_WINDOW_SECONDS}_seconds"
            )
        elif count_extreme_burst >= EXTREME_BURST_THRESHOLD:
            label = ATTACK_LABEL
            reason = (
                f"{EXTREME_BURST_THRESHOLD}_or_more_events_from_same_host_within_"
                f"{EXTREME_BURST_WINDOW_SECONDS}_seconds"
            )
        else:
            label = NORMAL_LABEL
            reason = "no_rule_matched"

        if (
            label == ATTACK_LABEL
            and reason != "blacklist"
            and is_valid_host(host)
        ):
            candidate_hosts.add(host)

        labels.append(label)
        reasons.append(reason)
        counts_5.append(count_5)
        counts_30.append(count_30)
        counts_extreme_burst.append(count_extreme_burst)

    working[target_column] = labels
    working["rule_match"] = reasons
    working[
        f"max_same_host_events_within_{BURST_WINDOW_SECONDS}_seconds"
    ] = working["_host_max_burst_events"]
    working[
        f"same_host_events_last_{EXTREME_BURST_WINDOW_SECONDS}_seconds"
    ] = counts_extreme_burst
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
            f"max_same_host_events_within_{BURST_WINDOW_SECONDS}_seconds",
            f"same_host_events_last_{EXTREME_BURST_WINDOW_SECONDS}_seconds",
            "same_host_events_last_5_seconds",
            "same_host_events_last_30_seconds",
        ]
    ].copy()

    output_file.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_file, index=False)
    save_new_candidate_entries(blacklist_candidates_file, candidate_hosts)

    accuracy = None
    if expected_labels is not None:
        predicted_labels = results[target_column].reset_index(drop=True)
        accuracy = float((predicted_labels == expected_labels.reset_index(drop=True)).mean())

    return {
        "data_file": data_file,
        "blacklist_file": blacklist_file,
        "blacklist_candidates_file": blacklist_candidates_file,
        "output_file": output_file,
        "rows_checked": len(results),
        "attacks_found": int((results[target_column] == ATTACK_LABEL).sum()),
        "candidate_hosts": sorted(candidate_hosts),
        "accuracy": accuracy,
        "results": results,
        "target_column": target_column,
    }
