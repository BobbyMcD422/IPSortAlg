from pathlib import Path

from lib.rules import apply_rules

SAMPLE_DATA_DIR = Path("data/sample_data")
OUTPUT_DIR = Path("data/predictions")


def prediction_output_path(data_file):
    return OUTPUT_DIR / f"{data_file.stem}_predictions.csv"


def print_result(result):
    print(f"Applied rules to {result['data_file']}")
    print(f"Rows checked: {result['rows_checked']}")
    print(f"Attacks found: {result['attacks_found']}")
    if result["accuracy"] is not None:
        print(
            "Accuracy against original Source "
            f"(blank treated as normal): {result['accuracy']:.4f}"
        )
    print(f"Blacklist: {result['blacklist_file']}")
    print(f"New hosts added to blacklist: {len(result['newly_blacklisted'])}")
    for host in result["newly_blacklisted"]:
        print(f"  {host}")
    print(f"Saved filled sheet to {result['output_file']}")
    print()


def main():
    data_files = sorted(SAMPLE_DATA_DIR.glob("*.csv"))

    if not data_files:
        print(f"No CSV files found in {SAMPLE_DATA_DIR}")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []

    for data_file in data_files:
        result = apply_rules(
            data_file=data_file,
            output_file=prediction_output_path(data_file),
        )
        results.append(result)
        print_result(result)

    rows_checked = sum(result["rows_checked"] for result in results)
    attacks_found = sum(result["attacks_found"] for result in results)
    newly_blacklisted = sorted(
        {
            host
            for result in results
            for host in result["newly_blacklisted"]
        }
    )

    print("Run summary:")
    print(f"Files processed: {len(results)}")
    print(f"Rows checked: {rows_checked}")
    print(f"Attacks found: {attacks_found}")
    print(f"New hosts added to blacklist: {len(newly_blacklisted)}")


if __name__ == "__main__":
    main()
