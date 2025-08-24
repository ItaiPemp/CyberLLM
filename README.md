# 1. Using the Parser

This parser analyzes `.pcap` files to extract network flows and detect potential attacks using signature matching and heuristics.

It processes packets in time-based windows, groups them into flows, analyzes payloads and metadata, and writes a detailed `.txt` report with flow-level insights and possible attack indicators.

---

## 🛠 Parameters

| Parameter         | Description                                      | Default           |
|------------------|--------------------------------------------------|-------------------|
| `pcap_path`      | Path to the input `.pcap` file                   | **Required**      |
| `--window_size`  | Time window size in seconds for analysis         | `60`              |
| `--step_size`    | Step size in seconds between windows             | `60`              |
| `--output_path`  | File path for the output `.txt` report           | `output_llm.txt`  |


# 2. Evaluating LLMs automatically - Windows quick start (PowerShell)
## 2.1) Go to your project folder
cd C:\path\to\your\project

## 2.2) Create & activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

## 2.3) Install deps
pip install fastapi-poe rich

## 2.4) API key
$env:POE_API_KEY="YOUR_POE_API_KEY"

## 2.5) Run multiple models over your wireshark_txt tree
```
python .\poe_eval_multi.py `
  --tested-bots "GPT-OSS-120B-CS,Claude-3.5-Sonnet-200k" `
  --judge-bot "GPT-OSS-120B-CS" `
  --input .\wireshark_txt `
  --glob '**/*.txt' `
  --max-workers 6 `
  --out results_txt_multi.csv
```

# 3. Dataset Available
https://postbguacil-my.sharepoint.com/personal/gala0_post_bgu_ac_il/_layouts/15/onedrive.aspx?id=%2Fpersonal%2Fgala0%5Fpost%5Fbgu%5Fac%5Fil%2FDocuments%2F2024%2D2025%2FASAF&ga=1

# 4. Results Available
https://docs.google.com/spreadsheets/d/1dpsvSy_fOxWEg8lDZversuRRWiP2S14wkEpeB9fCjiE/edit?usp=sharing
