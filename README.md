# Windows quick start (PowerShell)
## 1) Go to your project folder
cd C:\path\to\your\project

## 2) Create & activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

## 3) Install deps
pip install fastapi-poe rich

## 4) API key
$env:POE_API_KEY="YOUR_POE_API_KEY"

## 5) Run multiple models over your wireshark_txt tree
python .\poe_eval_mt.py `
  --tested-bots "GPT-OSS-120B-CS,Claude-3.5-Sonnet-200k" `
  --judge-bot "GPT-OSS-120B-CS" `
  --input .\wireshark_txt `
  --glob '**/*.txt' `
  --max-workers 6 `
  --out results_txt_multi.csv
