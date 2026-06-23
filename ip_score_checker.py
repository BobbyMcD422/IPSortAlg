"""Optional AbuseIPDB scoring utility kept separate from the main workflow.

The rule engine does not call this module. Run it directly when you want to
annotate sample files with AbuseIPDB scores.
"""

import argparse
import importlib
import os
from ipaddress import ip_address
from pathlib import Path
from time import perf_counter

import pandas as pd

from lib.rules import extract_host, read_event_file

SAMPLE_DATA_DIR = Path("data/sample_data")
OUTPUT_DIR = Path("data/ip_scores")
ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"


def is_ip_host(host):
    """Return True when the extracted host is an IP address."""
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def output_path_for(data_file):
    """Build the CSV output path for one scored input file."""
    return OUTPUT_DIR / f"{data_file.stem}_ip_scores.csv"


def extract_score(response):
    """Pull an AbuseIPDB confidence score from common wrapper response shapes."""
    if isinstance(response, dict):
        data = response.get("data", response)

        for key in (
            "abuseConfidenceScore",
            "abuse_confidence_score",
            "confidence_score",
            "score",
        ):
            if key in data:
                return data[key]

    for attr in (
        "abuseConfidenceScore",
        "abuse_confidence_score",
        "confidence_score",
        "score",
    ):
        if hasattr(response, attr):
            return getattr(response, attr)

    return None


def build_abuseipdb_client(api_key):
    """Create a small adapter around the installed abuseipdb-wrapper package."""
    try:
        module = importlib.import_module("abuseipdb_wrapper")
    except ImportError as error:
        raise ImportError(
            "Install abuseipdb-wrapper before setting usesIPChecker=True."
        ) from error

    client_class = (
        getattr(module, "AbuseIPDB", None)
        or getattr(module, "AbuseIPDBClient", None)
        or getattr(module, "Client", None)
    )

    if client_class is None:
        raise ImportError(
            "Could not find an AbuseIPDB client class in abuseipdb_wrapper."
        )

    for kwargs in ({"api_key": api_key}, {"key": api_key}, {"apiKey": api_key}):
        try:
            client = client_class(**kwargs)
            break
        except TypeError:
            client = None
    else:
        try:
            client = client_class(api_key)
        except TypeError as error:
            raise TypeError(
                "Could not initialize abuseipdb-wrapper with the provided API key."
            ) from error

    for method_name in ("check", "check_ip", "check_address", "ip_check"):
        if hasattr(client, method_name):
            method = getattr(client, method_name)

            def check_ip(ip_value):
                return extract_score(method(ip_value))

            return check_ip

    raise AttributeError(
        "Could not find a supported IP-check method on the AbuseIPDB client."
    )


def score_ip(ip_value, checker):
    """Return a score for one IP, or None when no checker is enabled."""
    if checker is None:
        return None

    return checker(ip_value)


def score_file(
    data_file,
    output_file=None,
    testing=False,
    usesIPChecker=False,
    api_key=None,
):
    """Annotate one input file with IP score columns.

    testing=True records elapsed runtime for local checks and AbuseIPDB checks.
    usesIPChecker=True calls abuseipdb-wrapper; otherwise scores remain blank.
    """
    start_time = perf_counter()
    checker_elapsed_seconds = 0.0
    data_file = Path(data_file)
    output_file = Path(output_file) if output_file else output_path_for(data_file)
    api_key = api_key or os.getenv(ABUSEIPDB_API_KEY_ENV)

    if usesIPChecker and not api_key:
        raise ValueError(f"Set {ABUSEIPDB_API_KEY_ENV} before using AbuseIPDB.")

    checker = build_abuseipdb_client(api_key) if usesIPChecker else None
    local_check_start = perf_counter()
    df = read_event_file(data_file)

    if "IP" not in df.columns:
        raise ValueError(f"Missing required IP column in {data_file}")

    hosts = df["IP"].astype(str).map(extract_host)
    ip_host_flags = hosts.map(is_ip_host)
    local_elapsed_seconds = perf_counter() - local_check_start
    score_cache = {}
    scores = []
    statuses = []

    for host, is_ip in zip(hosts, ip_host_flags):
        if not is_ip:
            scores.append(None)
            statuses.append("not_ip_address")
            continue

        if host not in score_cache:
            checker_start = perf_counter()
            try:
                score_cache[host] = score_ip(host, checker)
            except Exception as error:
                score_cache[host] = None
                statuses.append(f"checker_error: {error}")
                scores.append(None)
                continue
            finally:
                checker_elapsed_seconds += perf_counter() - checker_start

        scores.append(score_cache[host])
        statuses.append("checked" if usesIPChecker else "checker_disabled")

    results = df.copy()
    results["ip_score_host"] = hosts
    results["abuseipdb_score"] = scores
    results["ip_score_status"] = statuses

    output_file.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_file, index=False)

    elapsed_seconds = perf_counter() - start_time

    return {
        "data_file": data_file,
        "output_file": output_file,
        "rows_checked": len(results),
        "unique_ip_hosts": len(set(hosts[ip_host_flags])),
        "usesIPChecker": usesIPChecker,
        "elapsed_seconds": elapsed_seconds if testing else None,
        "local_check_elapsed_seconds": local_elapsed_seconds if testing else None,
        "abuseipdb_elapsed_seconds": (
            checker_elapsed_seconds if testing and usesIPChecker else None
        ),
    }


def supported_sample_files():
    """Return CSV/XLSX files from the sample data folder."""
    return sorted(
        path
        for path in SAMPLE_DATA_DIR.iterdir()
        if path.suffix.lower() in {".csv", ".xlsx"}
    )


def main():
    """CLI entrypoint for scoring every sample file."""
    parser = argparse.ArgumentParser(description="Annotate sample files with IP scores.")
    parser.add_argument("--testing", action="store_true", help="print elapsed runtime")
    parser.add_argument(
        "--use-ip-checker",
        dest="usesIPChecker",
        action="store_true",
        help="call abuseipdb-wrapper and assign AbuseIPDB scores",
    )
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for data_file in supported_sample_files():
        result = score_file(
            data_file,
            testing=args.testing,
            usesIPChecker=args.usesIPChecker,
        )

        print(f"Scored {result['data_file']}")
        print(f"Rows checked: {result['rows_checked']}")
        print(f"Unique IP hosts: {result['unique_ip_hosts']}")
        print(f"Used AbuseIPDB checker: {result['usesIPChecker']}")
        if result["elapsed_seconds"] is not None:
            print(
                "Built-in check elapsed seconds: "
                f"{result['local_check_elapsed_seconds']:.4f}"
            )
            if result["abuseipdb_elapsed_seconds"] is None:
                print("AbuseIPDB elapsed seconds: skipped")
            else:
                print(
                    "AbuseIPDB elapsed seconds: "
                    f"{result['abuseipdb_elapsed_seconds']:.4f}"
                )
            print(f"Elapsed seconds: {result['elapsed_seconds']:.4f}")
        print(f"Saved scores to {result['output_file']}")
        print()


if __name__ == "__main__":
    main()
