# IP Sort

IP Sort is a deterministic network-event classifier. It reads CSV and Excel
files,
applies an ordered set of security rules, and labels each row as `attack` or
`normal`.

The application does not use machine learning or generic AI inference.

## Rules

Rules are evaluated in this order:

1. Mark the event as an attack if its IP, hostname, or full `host:port` value
   appears in `data/blacklist.txt`.
2. Mark the event as an attack if the same host appears at least 3 times within
   5 seconds.
3. Mark the event as an attack if the same host appears at least 5 times within
   30 seconds.
4. Otherwise, mark the event as normal.

When an IP address or hostname triggers rule 2 or rule 3, it is automatically
added to the blacklist. Later events from that host, including events in future
runs, will match the blacklist rule.

## Project Structure

```text
ipsort/
  main.py
  predict.py
  requirements.txt
  lib/
    __init__.py
    rules.py
  data/
    blacklist.txt
    predictions/
    sample_data/
      Honeynet botnet attack timestamp 32 qubits final copy - Sheet1.csv
```

## Requirements

- Python 3
- pandas 2.0 or newer
- openpyxl 3.1 or newer

Install dependencies:

```powershell
pip install -r requirements.txt
```

If you are using the included virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Input Format

The input must be a `.csv` or `.xlsx` file containing at least:

```csv
time,IP
1.457799704,142.93.3.154:8080
1.487278380,142.93.3.154:8080
3.257728777,142.93.3.154:8080
```

- `time` must be numeric and use the same unit for every row.
- `IP` may contain an IPv4 address, hostname, or a value with a port.
- A preexisting `Source` column is optional and will be replaced in the output.
- Other input columns are preserved.

## Run

Place `.csv` or `.xlsx` files in `data/sample_data/`.

Then run:

```powershell
python predict.py
```

Each processed sheet is saved to:

```text
data/predictions/<original_file_name>_predictions.csv
```

Excel files are read from the first sheet and are also written back out as CSV
prediction files.
If an Excel sheet has title rows before the table, IP Sort looks for the first
row containing both `time` and `IP` and uses that as the header row. Source
columns named like `Source (attack or not)` are normalized to `Source`.

If the input already contains a `Source` column, the program prints its
accuracy against those original labels before replacing them in the output.
Blank original `Source` values are treated as `normal`.

## Output

The output preserves the original columns and adds or fills:

```text
Source
rule_match
same_host_events_last_5_seconds
same_host_events_last_30_seconds
```

Example:

```csv
time,IP,Source,rule_match
1.457799704,142.93.3.154:8080,normal,no_rule_matched
3.257728777,142.93.3.154:8080,attack,3_or_more_events_from_same_host_within_5_seconds
```

## Blacklist

Edit `data/blacklist.txt` to add permanent entries. Use one entry per line:

```text
192.0.2.10
malicious.example.com
198.51.100.7:8080
```

Blank lines and lines beginning with `#` are ignored. A host-only entry blocks
that host on every port. A full `host:port` entry blocks only that endpoint.

Review automatically added entries periodically. Once an IP address or
hostname is persisted in the blacklist, all of its events will be classified
as attacks on later runs.

## Use as a Library

```python
from lib.rules import apply_rules

result = apply_rules(
    data_file="data/sample_data/events.csv",
    blacklist_file="data/blacklist.txt",
    output_file="data/predictions.csv",
)

print(result["attacks_found"])
print(result["newly_blacklisted"])
```
