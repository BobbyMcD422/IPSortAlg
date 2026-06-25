"""Optional AlienVault OTX lookup utility kept separate from the main workflow.

The rule engine does not call this module. Run it directly when you want to
annotate sample files with AlienVault OTX threat-pulse information.
"""

import argparse
import importlib
import os
from ipaddress import ip_address
from pathlib import Path
from time import perf_counter

import pandas as pd
from dotenv import load_dotenv

from lib.rules import extract_host, read_event_file

SAMPLE_DATA_DIR = Path("data/sample_data")
OUTPUT_DIR = Path("data/ip_scores")
OTX_API_KEY_ENV = "OTX_API_KEY"

load_dotenv()


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


def build_otx_checker(api_key):
    """Create an AlienVault OTX checker from the optional OTXv2 package."""
    try:
        otx_module = importlib.import_module("OTXv2")
        indicator_types = importlib.import_module("IndicatorTypes")
    except ImportError as error:
        raise ImportError(
            "Install OTXv2 before setting usesIPChecker=True."
        ) from error

    otx = otx_module.OTXv2(api_key)

    def check_ip(ip_value):
        """Return OTX pulse details for one IPv4 or IPv6 address."""
        address = ip_address(ip_value)
        indicator_type = (
            indicator_types.IPv4 if address.version == 4 else indicator_types.IPv6
        )
        result = otx.get_indicator_details_by_section(
            indicator_type=indicator_type,
            indicator=ip_value,
            section="general",
        )
        pulse_info = result.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        report_names = [
            pulse.get("name", "Unknown Threat")
            for pulse in pulses
            if isinstance(pulse, dict)
        ]
        return {
            "pulse_count": pulse_info.get("count", 0),
            "report_names": report_names,
        }

    return check_ip


def score_file(
    data_file,
    output_file=None,
    testing=False,
    usesIPChecker=False,
    api_key=None,
):
    """Annotate one input file with AlienVault OTX columns.

    testing=True records elapsed runtime for local checks and OTX requests.
    usesIPChecker=True calls AlienVault OTX; otherwise OTX values remain blank.
    """
    start_time = perf_counter()
    checker_elapsed_seconds = 0.0
    data_file = Path(data_file)
    output_file = Path(output_file) if output_file else output_path_for(data_file)
    api_key = api_key or os.getenv(OTX_API_KEY_ENV)

    if usesIPChecker and not api_key:
        raise ValueError(
            f"Set {OTX_API_KEY_ENV} in .env or your environment before using "
            "AlienVault OTX."
        )

    checker = build_otx_checker(api_key) if usesIPChecker else None
    local_check_start = perf_counter()
    df = read_event_file(data_file)

    if "IP" not in df.columns:
        raise ValueError(f"Missing required IP column in {data_file}")

    hosts = df["IP"].astype(str).map(extract_host)
    ip_host_flags = hosts.map(is_ip_host)
    local_elapsed_seconds = perf_counter() - local_check_start
    score_cache = {}
    pulse_counts = []
    recent_reports = []
    statuses = []

    for host, is_ip in zip(hosts, ip_host_flags):
        if not is_ip:
            pulse_counts.append(None)
            recent_reports.append("")
            statuses.append("not_ip_address")
            continue

        if host not in score_cache:
            checker_start = perf_counter()
            try:
                if checker is None:
                    score_cache[host] = (None, "", "checker_disabled")
                else:
                    details = checker(host)
                    score_cache[host] = (
                        details["pulse_count"],
                        " | ".join(details["report_names"][:5]),
                        "checked",
                    )
            except Exception as error:
                score_cache[host] = (None, "", f"checker_error: {error}")
            finally:
                checker_elapsed_seconds += perf_counter() - checker_start

        pulse_count, reports, status = score_cache[host]
        pulse_counts.append(pulse_count)
        recent_reports.append(reports)
        statuses.append(status)

    results = df.copy()
    results["ip_score_host"] = hosts
    results["otx_pulse_count"] = pulse_counts
    results["otx_recent_threat_reports"] = recent_reports
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
        "otx_elapsed_seconds": (
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
        help="call AlienVault OTX and add threat-pulse details",
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
        print(f"Used AlienVault OTX checker: {result['usesIPChecker']}")
        if result["elapsed_seconds"] is not None:
            print(
                "Built-in check elapsed seconds: "
                f"{result['local_check_elapsed_seconds']:.4f}"
            )
            if result["otx_elapsed_seconds"] is None:
                print("AlienVault OTX elapsed seconds: skipped")
            else:
                print(
                    "AlienVault OTX elapsed seconds: "
                    f"{result['otx_elapsed_seconds']:.4f}"
                )
            print(f"Elapsed seconds: {result['elapsed_seconds']:.4f}")
        print(f"Saved scores to {result['output_file']}")
        print()


if __name__ == "__main__":
    main()
