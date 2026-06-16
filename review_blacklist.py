from pathlib import Path

import pandas as pd

from lib.rules import append_unique_entries, extract_host, load_blacklist, remove_entries

BLACKLIST_FILE = Path("data/blacklist.txt")
CANDIDATES_FILE = Path("data/blacklist_candidates.txt")
PREDICTIONS_DIR = Path("data/predictions")


def load_candidate_hosts():
    return sorted(load_blacklist(CANDIDATES_FILE))


def collect_candidate_reasons(candidate_hosts):
    evidence = {
        host: {
            "reasons": set(),
            "files": set(),
            "attack_rows": 0,
        }
        for host in candidate_hosts
    }

    for prediction_file in sorted(PREDICTIONS_DIR.glob("*.csv")):
        df = pd.read_csv(prediction_file)

        if "IP" not in df.columns or "rule_match" not in df.columns:
            continue

        hosts = df["IP"].astype(str).map(extract_host)

        for host in candidate_hosts:
            rows = df[hosts == host]

            if rows.empty:
                continue

            attack_rows = rows[rows["Source"].astype(str).str.lower() == "attack"]
            evidence[host]["files"].add(prediction_file.name)
            evidence[host]["attack_rows"] += len(attack_rows)
            evidence[host]["reasons"].update(
                reason
                for reason in attack_rows["rule_match"].dropna().astype(str)
                if reason != "blacklist"
            )

    return evidence


def ask_to_add(host, details):
    reasons = sorted(details["reasons"]) or ["no matching prediction reason found"]
    files = sorted(details["files"]) or ["no prediction file found"]

    print()
    print(f"Candidate: {host}")
    print(f"Attack rows: {details['attack_rows']}")
    print("Reason(s):")
    for reason in reasons:
        print(f"  - {reason}")
    print("Seen in:")
    for file_name in files:
        print(f"  - {file_name}")

    answer = input("Add this host to blacklist.txt? [y/N/q]: ").strip().lower()
    return answer


def main():
    candidate_hosts = load_candidate_hosts()

    if not candidate_hosts:
        print(f"No candidates found in {CANDIDATES_FILE}")
        return

    existing_blacklist = load_blacklist(BLACKLIST_FILE)
    candidate_hosts = [
        host for host in candidate_hosts if host not in existing_blacklist
    ]

    if not candidate_hosts:
        print("All candidates are already in the blacklist.")
        return

    evidence = collect_candidate_reasons(candidate_hosts)
    approved_hosts = []

    print(f"Reviewing {len(candidate_hosts)} blacklist candidate(s).")

    for host in candidate_hosts:
        answer = ask_to_add(host, evidence[host])

        if answer == "q":
            break
        if answer == "y":
            approved_hosts.append(host)

    added_hosts = append_unique_entries(BLACKLIST_FILE, approved_hosts)
    remove_entries(CANDIDATES_FILE, added_hosts)

    print()
    print(f"Added {len(added_hosts)} host(s) to {BLACKLIST_FILE}.")
    for host in added_hosts:
        print(f"  {host}")


if __name__ == "__main__":
    main()
