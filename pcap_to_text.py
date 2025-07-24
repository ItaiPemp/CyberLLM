import os
from parser import write_llm_txt  # This must be your existing parser module

INPUT_DIR = "wireshark"
OUTPUT_DIR = "wireshark_txt"
WINDOW_SIZE = 60
STEP_SIZE = 60

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def process_all_pcaps():
    for root, dirs, files in os.walk(INPUT_DIR):
        for file in files:
            if file.endswith(".pcap") or file.endswith(".pcapng"):
                full_input_path = os.path.join(root, file)

                # Create equivalent output path
                rel_path = os.path.relpath(full_input_path, INPUT_DIR)
                output_txt_path = os.path.join(OUTPUT_DIR, os.path.splitext(rel_path)[0] + ".txt")
                output_dir = os.path.dirname(output_txt_path)
                ensure_dir(output_dir)

                print(f"Processing: {rel_path}")
                try:
                    write_llm_txt(
                        pcap_path=full_input_path,
                        window_size=WINDOW_SIZE,
                        step_size=STEP_SIZE,
                        output_txt=output_txt_path
                    )
                except Exception as e:
                    print(f"❌ Failed to process {file}: {e}")

if __name__ == "__main__":
    process_all_pcaps()
