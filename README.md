# IP Sort

IP Sort is a deterministic network-event classifier. It reads CSV and Excel
files, applies an ordered set of security rules, and labels each row as
`attack` or `normal`.

The application does not use machine learning or generic AI inference.

## Rules

Rules are evaluated in this order:

1. Mark the event as an attack if its IP, hostname, or full `host:port` value
   appears in `data/blacklist.txt`.
2. Mark every event from a host as an attack if that same host appears at
   least 5 times within any 5-second window in the input file.
3. Mark the event as an attack if the same source host appears at least 50
   times within 2 seconds.
4. Otherwise, mark the event as normal.

When an IP address or hostname triggers rule 2 or rule 3, it is written to
`data/blacklist_candidates.txt` for review. It is not automatically added to
the permanent blacklist because the sample data shows the same host can be
malicious in one file and normal in another.

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
    blacklist_candidates.txt
    predictions/
    sample_data/
      Honeynet botnet attack timestamp 32 qubits final copy - Sheet1.csv
```

## Requirements

- Python 3
- pandas 2.0 or newer
- openpyxl 3.1 or newer
- OTXv2, only needed when using `ip_score_checker.py` with
  `--use-ip-checker`

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

Or run the full console workflow:

```powershell
python main.py
```

`main.py` applies the rules to every sample file, then opens an interactive
review step where you can approve candidate hosts for `data/blacklist.txt`.

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
max_same_host_events_within_5_seconds
same_host_events_last_2_seconds
same_host_events_last_5_seconds
same_host_events_last_30_seconds
```

Example:

```csv
time,IP,Source,rule_match,max_same_host_events_within_5_seconds
1.457799704,142.93.3.154:8080,attack,5_or_more_events_from_same_host_within_5_seconds,10
3.512656598,149.28.57.219:80,normal,no_rule_matched,2
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

Review `data/blacklist_candidates.txt` periodically. Move only confirmed bad
entries into `data/blacklist.txt`. Once an IP address or hostname is persisted
in the blacklist, all of its events will be classified as attacks on later
runs.

You can review candidates interactively:

```powershell
python review_blacklist.py
```

The review tool shows each candidate host, the rule reason that flagged it,
the prediction files where it appeared, and asks whether to add it to the
permanent blacklist.

When prompted:

```text
Add this host to blacklist.txt? [y/N/q]:
```

- Type `y` to approve the host and add it to `data/blacklist.txt`.
- Type `n` or press Enter to skip that host.
- Type `q` to stop reviewing the remaining candidates. Any hosts already
  approved with `y` are still added.

## Use as a Library

```python
from lib.rules import apply_rules

result = apply_rules(
    data_file="data/sample_data/events.csv",
    blacklist_file="data/blacklist.txt",
    output_file="data/predictions.csv",
)

print(result["attacks_found"])
print(result["candidate_hosts"])
```

## Optional IP Scoring

`ip_score_checker.py` is separate from the main rules workflow. It can annotate
sample files with `otx_pulse_count` and `otx_recent_threat_reports` columns.

Run without API calls:

```powershell
python ip_score_checker.py --testing
```

Run with AlienVault OTX lookups:

1. Create a `.env` file in the project directory:

```dotenv
OTX_API_KEY=your_otx_api_key
```

You can use `.env.example` as the template. The real `.env` file is ignored by
Git.

2. Run the checker:

```powershell
python ip_score_checker.py --testing --use-ip-checker
```

The script loads `OTX_API_KEY` from `.env` automatically. An operating-system
environment variable or the `api_key` argument to `score_file()` can also be
used.

The `testing` boolean reports elapsed runtime. The `usesIPChecker` boolean
controls whether the utility calls AlienVault OTX or leaves pulse values blank.
Each unique IP is requested once per file. `otx_pulse_count` is the number of
OTX threat pulses containing that address; it is threat-intelligence context,
not a probability or an AI prediction.

## Possible Next Steps / Improvements
* Dynamic Time Range / Rules Based On Average Vs. Above Average Time
* Test Known DDoS Attackers Wrapper Library 
* Move Rules into a Seperate File / Config File (?)
* Maybe a Jupyter Notebook or Webpage / Something to Graphically Display the Results (may be a little more structured or convenient)
* Set Rule Function (?)
* Queue Feature
* Risk Score based on Average Requests Per Second -> A Constraint In QAOA | Edge Weight?
