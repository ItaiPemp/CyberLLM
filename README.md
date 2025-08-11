python .\poe_eval_multi.py `
  --tested-bots "GPT-5-mini, GPT-5-nano" `
  --judge-bot "Deepseek-R1-70B-CS" `
  --input .\wireshark_txt_test `
  --glob '**/*.txt' `
  --max-workers 6 `
  --out results_demo.csv
