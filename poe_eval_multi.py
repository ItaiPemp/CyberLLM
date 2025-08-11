#!/usr/bin/env python3
# poe_eval_mt.py
import argparse
import csv
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import fastapi_poe as fp         # pip install fastapi-poe
from rich.console import Console  # pip install rich
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, TaskID

console = Console()

###############################################################################
# Prompts
###############################################################################

DEFAULT_TASK_PROMPT = (
    "I will provide you an information captured in the network. "
    "This information was parsed from pcap to text for you. Your job is to analyze the data and output two things:\n"
    "1. Whether the content of this capture is malicious or benign. (short answer)\n"
    "2. If there is something malicious, what kind of attack do you detect?\n"
    "If it's benign what action was performed by the user?\n"
    "Please provide short and concise answers and if possible short snippet of what indicated the attack."
)

# Judge only needs to fill two booleans. We still keep a couple of fields for audit.
JUDGE_SYSTEM_PROMPT = (
    "You are a strict evaluator for network-capture analyses.\n"
    "Inputs you will receive:\n"
    "- FILE PATH: the original Windows-like path of the capture text. The path may include ground-truth hints like 'Benign' or 'Malicious' and subfolders such as attack families (e.g., 'nmap').\n"
    "- GROUND TRUTH LABEL: 'Benign' or 'Malicious' derived from the directory name.\n"
    "- ATTACK HINT: a short attack name inferred from the path and/or file name (empty for benign samples).\n"
    "- MODEL ANSWER: the tested model's output.\n\n"
    "Your tasks (return integers only):\n"
    "1) detected_malicious = 1 if the MODEL ANSWER judged the capture as malicious; 0 if it judged benign or was unclear.\n"
    "2) detected_correct_attack = 1 if the MODEL ANSWER correctly identified the attack matching the ATTACK HINT (semantic match allowed: e.g., 'port scan' ≈ 'nmap'); otherwise 0. For Benign ground truth, set detected_correct_attack=1 only if the MODEL ANSWER correctly states a benign action (no attack), otherwise 0.\n\n"
    "Return STRICT JSON ONLY:\n"
    "{\n"
    '  "detected_malicious": 0 or 1,\n'
    '  "detected_correct_attack": 0 or 1,\n'
    '  "resolved_attack_name": "<your short attack name or empty for benign>",\n'
    '  "reasons": "<one short line>"\n'
    "}\n"
    "No extra text or markdown, only the JSON object."
)

###############################################################################
# Models & Results
###############################################################################

@dataclass
class EvalJob:
    file_path: Path
    tested_bot: str
    judge_bot: str
    gt_label: str           # 'Benign' or 'Malicious'
    attack_hint: str        # empty for benign

@dataclass
class EvalResult:
    tested_bot: str
    file_path: Path
    llm_output: str
    gt_label: str
    judge_bot: str
    judge_json: Dict[str, Any]

###############################################################################
# Utilities
###############################################################################

def collect_files(root: Path, glob: str, extensions: Optional[List[str]]) -> List[Path]:
    if root.is_file():
        return [root]
    out = []
    for p in root.glob(glob):
        if p.is_file():
            if (not extensions) or p.suffix.lower().lstrip(".") in extensions:
                out.append(p)
    out.sort()
    return out

def detect_ground_truth_label(p: Path) -> str:
    """Return 'Benign' or 'Malicious' (case-insensitive dir match), else ''."""
    parts = [s.lower() for s in p.parts]
    if any(s == "benign" for s in parts):
        return "Benign"
    if any(s == "malicious" for s in parts):
        return "Malicious"
    # fallback: look for substring match in any part (less strict)
    if any("benign" in s for s in parts):
        return "Benign"
    if any("malicious" in s for s in parts):
        return "Malicious"
    return ""

def infer_attack_hint(p: Path, gt_label: str) -> str:
    """
    Derive a concise attack hint for the judge:
    - Prefer immediate subfolder under 'Malicious' (e.g., Malicious/nmap/… -> 'nmap')
    - Fall back to file stem (e.g., 'brute force - ftp.txt' -> 'ftp brute force')
    - For Benign, return '' (judge expects benign)
    """
    if gt_label != "Malicious":
        return ""

    parts = [s for s in p.parts]
    # find index of 'Malicious' and take next segment if exists
    try:
        idx = [s.lower() for s in parts].index("malicious")
        if idx + 1 < len(parts) - 1:  # ensure there's a subfolder before the filename
            sub = parts[idx + 1]
            if "." not in sub:
                return sub.replace("_", " ").replace("-", " ").strip()
    except ValueError:
        pass

    # fallback: clean file stem
    stem = p.stem
    return stem.replace("_", " ").strip()

def parse_label_from_output(text: str) -> str:
    t = text.lower()
    if "malicious" in t and "benign" in t:
        return "Malicious" if t.find("malicious") < t.find("benign") else "Benign"
    if "malicious" in t:
        return "Malicious"
    if "benign" in t:
        return "Benign"
    return ""

###############################################################################
# Poe client helpers (external app mode)
###############################################################################

def stream_to_text(messages: List[fp.ProtocolMessage], bot_name: str, api_key: str,
                   progress: Optional[Progress] = None, task_id: Optional[TaskID] = None) -> str:
    """Stream a Poe response and return the full text. Updates progress with char count if provided."""
    chunks = []
    char_count = 0
    for partial in fp.get_bot_response_sync(messages=messages, bot_name=bot_name, api_key=api_key):
        text = getattr(partial, "text", None)
        if text:
            chunks.append(text)
            char_count += len(text)
            if progress and task_id is not None:
                progress.update(task_id, total=None, advance=0, description=f"[{bot_name}] {char_count} chars …")
    time.sleep(0.03)
    return "".join(chunks).strip()

def run_tested_model_inline(api_key: str, bot_name: str, system_prompt: str, file_text: str,
                            tested_user_text: str, progress: Optional[Progress], task_id: Optional[TaskID]) -> str:
    messages = [
        fp.ProtocolMessage(role="system", content=system_prompt),
        fp.ProtocolMessage(role="user", content=(tested_user_text + "\n\n" + file_text).strip()),
    ]
    return stream_to_text(messages, bot_name, api_key, progress, task_id)

def run_judge_model_inline(api_key: str, judge_bot: str, task_prompt: str,
                           tested_output: str, file_path: Path, gt_label: str, attack_hint: str,
                           file_text: str,
                           progress: Optional[Progress], task_id: Optional[TaskID]) -> Dict[str, Any]:
    """
    Judge sees filename/path and ground-truth label + attack hint.
    """
    user_payload = (
        f"FILE PATH:\n{str(file_path)}\n\n"
        f"GROUND TRUTH LABEL:\n{gt_label}\n\n"
        f"ATTACK HINT:\n{attack_hint}\n\n"
        f"MODEL ANSWER:\n{tested_output}\n\n"
        "CAPTURE TEXT (INLINE) [for context only — do not reveal in output]:\n"
        f"{file_text}\n\n"
        "Return ONLY the required JSON."
    )
    judge_messages = [
        fp.ProtocolMessage(role="system", content=JUDGE_SYSTEM_PROMPT),
        fp.ProtocolMessage(role="user", content=user_payload),
    ]
    raw = stream_to_text(judge_messages, judge_bot, api_key, progress, task_id)
    # parse strict JSON
    try:
        parsed = json.loads(raw)
        parsed["_raw_judge"] = raw
        return parsed
    except Exception:
        try:
            s, e = raw.find("{"), raw.rfind("}")
            if 0 <= s < e:
                parsed = json.loads(raw[s:e+1])
                parsed["_raw_judge"] = raw
                return parsed
        except Exception:
            pass
    return {
        "detected_malicious": "",
        "detected_correct_attack": "",
        "resolved_attack_name": "",
        "reasons": f"Could not parse judge JSON. Raw prefix: {raw[:300]}",
        "_raw_judge": raw,
    }

###############################################################################
# Worker
###############################################################################

@dataclass
class WorkerConfig:
    api_key: str
    task_prompt: str
    tested_user_text: str
    max_chars: int
    no_truncate: bool
    progress: Progress
    parent_task: TaskID
    print_lock: Lock

def eval_one(job: EvalJob, cfg: WorkerConfig) -> EvalResult:
    file_text = job.file_path.read_text(encoding="utf-8", errors="replace")
    truncated = False
    if (not cfg.no_truncate) and len(file_text) > cfg.max_chars:
        file_text = file_text[:cfg.max_chars]
        truncated = True

    sub_task = cfg.progress.add_task(f"[{job.tested_bot}] starting…", total=None)

    if truncated:
        with cfg.print_lock:
            console.log(f"[yellow]Truncated[/yellow] {job.file_path} -> {cfg.max_chars} chars")

    # Tested model
    try:
        cfg.progress.update(sub_task, description=f"[{job.tested_bot}] generating…")
        tested_output = run_tested_model_inline(
            api_key=cfg.api_key,
            bot_name=job.tested_bot,
            system_prompt=cfg.task_prompt,
            file_text=file_text,
            tested_user_text=cfg.tested_user_text,
            progress=cfg.progress,
            task_id=sub_task
        )
    except Exception as e:
        tested_output = f"[ERROR calling tested bot {job.tested_bot}: {e}]"

    # Judge (has filename + gt label + attack hint)
    try:
        cfg.progress.update(sub_task, description=f"[{job.judge_bot}] judging…")
        judge_json = run_judge_model_inline(
            api_key=cfg.api_key,
            judge_bot=job.judge_bot,
            task_prompt=cfg.task_prompt,
            tested_output=tested_output,
            file_path=job.file_path,
            gt_label=job.gt_label,
            attack_hint=job.attack_hint,
            file_text=file_text,
            progress=cfg.progress,
            task_id=sub_task
        )
    except Exception as e:
        judge_json = {
            "detected_malicious": "",
            "detected_correct_attack": "",
            "resolved_attack_name": "",
            "reasons": f"[ERROR calling judge bot {job.judge_bot}: {e}]",
            "_raw_judge": f"[ERROR calling judge bot {job.judge_bot}: {e}]",
        }

    cfg.progress.update(sub_task, description=f"[{job.tested_bot}] done")
    cfg.progress.remove_task(sub_task)
    cfg.progress.advance(cfg.parent_task, 1)

    return EvalResult(
        tested_bot=job.tested_bot,
        file_path=job.file_path,
        llm_output=tested_output,
        gt_label=job.gt_label,
        judge_bot=job.judge_bot,
        judge_json=judge_json,
    )

###############################################################################
# Main
###############################################################################

def main():
    ap = argparse.ArgumentParser(description="Evaluate multiple LLMs on capture files with a Judge LLM (Poe API). Multithreaded with rich progress.")
    ap.add_argument("--api-key", default=os.getenv("POE_API_KEY"), help="Poe API key or set POE_API_KEY")
    ap.add_argument("--tested-bots", required=True, help="Comma-separated tested bot names (e.g., GPT-OSS-120B-CS,Claude-3.5-Sonnet-200k)")
    ap.add_argument("--judge-bot", default="GPT-OSS-120B-CS", help="Judge bot name")
    ap.add_argument("--input", required=True, help="File or directory (e.g., wireshark_txt/)")
    ap.add_argument("--glob", default="**/*.txt", help="Glob under directories (default: **/*.txt)")
    ap.add_argument("--extensions", default="", help="Comma-separated extensions (e.g., txt,pcap). Empty = ignore")
    ap.add_argument("--system-prompt-file", default=None, help="Path to system prompt file for the tested bots.")
    ap.add_argument("--system-prompt", default=None, help="Inline system prompt for the tested bots (overrides file).")
    ap.add_argument("--tested-user-text", default="", help="Optional user text for the tested bots.")
    ap.add_argument("--out", default="poe_results.csv", help="Output CSV path")
    ap.add_argument("--max-chars", type=int, default=250_000, help="Max characters from each file (truncate if longer).")
    ap.add_argument("--no-truncate", action="store_true", help="Disable truncation.")
    ap.add_argument("--max-workers", type=int, default=4, help="Max concurrent worker threads.")
    args = ap.parse_args()

    if not args.api_key:
        console.print("[red]Error:[/red] provide --api-key or set POE_API_KEY")
        sys.exit(2)

    # System prompt
    if args.system_prompt is not None:
        task_prompt = args.system_prompt
    elif args.system_prompt_file:
        task_prompt = Path(args.system_prompt_file).read_text(encoding="utf-8", errors="replace")
    else:
        task_prompt = DEFAULT_TASK_PROMPT

    tested_bots = [b.strip() for b in args.tested_bots.split(",") if b.strip()]
    if not tested_bots:
        console.print("[red]Error:[/red] No tested bots provided.")
        sys.exit(2)

    # Files
    extensions = [e.strip().lower() for e in args.extensions.split(",") if e.strip()] if args.extensions else None
    root = Path(args.input)
    files = collect_files(root, args.glob, extensions)
    if not files:
        console.print("[red]Error:[/red] No files matched your input/glob.")
        sys.exit(1)

    # Build jobs: each file × each tested model, with ground truth label and attack hint from path
    jobs: List[EvalJob] = []
    for f in files:
        gt = detect_ground_truth_label(f)
        attack_hint = infer_attack_hint(f, gt)
        jobs.extend(EvalJob(file_path=f, tested_bot=tb, judge_bot=args.judge_bot, gt_label=gt, attack_hint=attack_hint)
                    for tb in tested_bots)

    total_jobs = len(jobs)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "Tested Model",                               # <-- renamed
        "Malicious / Benign",                         # <-- ground truth from path
        "File",
        "Detected Malicious (1 == True)",             # judge JSON
        "Detected the correct attack (question 2)",   # judge JSON
        "LLM output",
        "System Prompt",
        "Judge Bot",
        "Judge JSON",
    ]

    results: List[EvalResult] = []
    results_lock = Lock()
    print_lock = Lock()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Tasks[/bold]"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        parent = progress.add_task(f"Evaluating {total_jobs} jobs ({len(files)} files × {len(tested_bots)} models)", total=total_jobs)

        cfg = WorkerConfig(
            api_key=args.api_key,
            task_prompt=task_prompt,
            tested_user_text=args.tested_user_text,
            max_chars=args.max_chars,
            no_truncate=args.no_truncate,
            progress=progress,
            parent_task=parent,
            print_lock=print_lock,
        )

        with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
            fut2job: Dict[Any, EvalJob] = {ex.submit(eval_one, job, cfg): job for job in jobs}

            for fut in as_completed(fut2job):
                job = fut2job[fut]
                try:
                    res: EvalResult = fut.result()
                except Exception as e:
                    with print_lock:
                        console.log(f"[red]Worker exception[/red] on {job.file_path} / {job.tested_bot}: {e}")
                    res = EvalResult(
                        tested_bot=job.tested_bot,
                        file_path=job.file_path,
                        llm_output=f"[ERROR worker exception: {e}]",
                        gt_label=job.gt_label,
                        judge_bot=job.judge_bot,
                        judge_json={
                            "detected_malicious": "",
                            "detected_correct_attack": "",
                            "resolved_attack_name": "",
                            "reasons": f"[ERROR worker exception: {e}]",
                            "_raw_judge": f"[ERROR worker exception: {e}]",
                        },
                    )
                with results_lock:
                    results.append(res)

    # Write CSV (single thread)
    with out_path.open("w", newline="", encoding="utf-8") as fcsv:
        writer = csv.DictWriter(fcsv, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "Tested Model": r.tested_bot,
                "Malicious / Benign": r.gt_label,
                "File": str(r.file_path),
                "Detected Malicious (1 == True)": r.judge_json.get("detected_malicious", ""),
                "Detected the correct attack (question 2)": r.judge_json.get("detected_correct_attack", ""),
                "LLM output": r.llm_output,
                "System Prompt": task_prompt.strip(),
                "Judge Bot": r.judge_bot,
                "Judge JSON": json.dumps(r.judge_json, ensure_ascii=False),
            })

    console.print(f"\n[bold green]Saved results ->[/bold green] {out_path}")

if __name__ == "__main__":
    main()
