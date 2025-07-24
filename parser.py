import re
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNSQR
from collections import defaultdict
from datetime import datetime, timedelta

# Constants
ATTACK_PATTERNS = {
    "ftp_user": r"USER\s+\w+",
    "ftp_pass": r"PASS\s+\w+",
    "ssh_banner": r"SSH-\d\.\d-",
    "http_exploit": r"(POST|GET)\s+.*(\/cgi-bin\/|cmd\.exe|\/etc\/passwd)",
    "metasploit": r"ms17_010|meterpreter|exploit",
    "nmap_probe": r"nmap|Nmap",
    "enum4linux": r"OS:\s+Windows|Workgroup|Domain",
    "hydra_marker": r"hydra",
    "gobuster": r"gobuster",
    "nikto": r"nikto",
    "apache_2_4_49": r"Apache\/2\.4\.49",
    "ftp_backdoor": r"220\s+.*2\.3\.4"
}
AUTH_PORTS = {21, 22, 23, 445, 3389}
BRUTE_FORCE_FLOW_THRESHOLD = 5
MAX_FLOWS_PER_WINDOW = 500

# Constants
ATTACK_PATTERNS = {
    "ftp_user": r"USER\s+\w+",
    "ftp_pass": r"PASS\s+\w+",
    "ssh_banner": r"SSH-\d\.\d-",
    "http_exploit": r"(POST|GET)\s+.*(\/cgi-bin\/|cmd\.exe|\/etc\/passwd)",
    "metasploit": r"ms17_010|meterpreter|exploit",
    "nmap_probe": r"nmap|Nmap",
    "enum4linux": r"OS:\s+Windows|Workgroup|Domain",
    "hydra_marker": r"hydra",
    "gobuster": r"gobuster",
    "nikto": r"nikto",
    "apache_2_4_49": r"Apache\/2\.4\.49",
    "ftp_backdoor": r"220\s+.*2\.3\.4"
}
AUTH_PORTS = {21, 22, 23, 445, 3389}
BRUTE_FORCE_FLOW_THRESHOLD = 5
MAX_FLOWS_PER_WINDOW = 50

def extract_flow_key(pkt):
    if IP in pkt and (TCP in pkt or UDP in pkt):
        proto = "TCP" if TCP in pkt else "UDP"
        return (pkt[IP].src, pkt[IP].dst, pkt.sport, pkt.dport, proto)
    return None

def detect_attack_signatures(payloads):
    matches = []
    for text in payloads:
        for label, pattern in ATTACK_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(label)
    return list(set(matches))

def extract_flow_info(pkts, flow_key, auth_flow_counts):
    src_ip, dst_ip, sport, dport, proto = flow_key
    timestamps = [datetime.fromtimestamp(float(pkt.time)) for pkt in pkts]
    duration = (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0.0
    total_bytes = sum(len(pkt) for pkt in pkts)
    flags = list({str(pkt[TCP].flags) for pkt in pkts if TCP in pkt})
    dns_queries = list({pkt[DNSQR].qname.decode(errors='ignore') for pkt in pkts if pkt.haslayer(DNSQR)})
    direction = "outbound" if src_ip.startswith("192.168.") else "inbound"

    app_protocol = None
    if dport == 21:
        app_protocol = "FTP"
    elif dport == 22:
        app_protocol = "SSH"
    elif dport == 23:
        app_protocol = "Telnet"
    elif dport == 80 or dport == 443:
        app_protocol = "HTTP"
    elif dport == 445:
        app_protocol = "SMB"

    payloads = []
    for pkt in pkts:
        if TCP in pkt and bytes(pkt[TCP].payload):
            try:
                decoded = bytes(pkt[TCP].payload).decode(errors='ignore').strip()
                if decoded:
                    payloads.append(decoded)
            except:
                continue

    preview = payloads[:3]
    attack_signatures = detect_attack_signatures(payloads)

    # SSH scan heuristic
    if dport == 22 and len(pkts) <= 3 and duration <= 2 and total_bytes < 500 and not payloads:
        attack_signatures.append("ssh_scan")

    # General brute-force heuristic
    if (src_ip, dst_ip, dport) in auth_flow_counts and auth_flow_counts[(src_ip, dst_ip, dport)] > BRUTE_FORCE_FLOW_THRESHOLD:
        attack_signatures.append("brute_force_heuristic")

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": sport,
        "dst_port": dport,
        "protocol": proto,
        "packet_count": len(pkts),
        "total_bytes": total_bytes,
        "duration": duration,
        "tcp_flags": flags,
        "dns_queries": dns_queries[:2],
        "direction": direction,
        "app_protocol": app_protocol,
        "payload_preview": preview,
        "attack_signatures": attack_signatures
    }

def generate_windows(packets, window_size, step_size):
    start_time = min(datetime.fromtimestamp(float(pkt.time)) for pkt in packets)
    end_time = max(datetime.fromtimestamp(float(pkt.time)) for pkt in packets)
    current = start_time
    windows = []

    while current < end_time:
        next_window = current + timedelta(seconds=window_size)
        window_packets = [
            pkt for pkt in packets
            if current <= datetime.fromtimestamp(float(pkt.time)) < next_window
        ]
        windows.append((current, next_window, window_packets))
        current += timedelta(seconds=step_size)

    return windows, start_time, end_time

def write_llm_txt(pcap_path, window_size=60, step_size=60, output_txt="/mnt/data/output_llm.txt"):
    packets = rdpcap(pcap_path)
    windows, start_time, end_time = generate_windows(packets, window_size, step_size)

    total_ports = set()
    total_ips = set()
    protocols = set()

    for pkt in packets:
        if IP in pkt:
            total_ips.add(pkt[IP].src)
            total_ips.add(pkt[IP].dst)
        if TCP in pkt or UDP in pkt:
            total_ports.add(pkt.sport)
            total_ports.add(pkt.dport)
            protocols.add("TCP" if TCP in pkt else "UDP")

    capture_duration = str(end_time - start_time)

    with open(output_txt, "w") as f:
        f.write("[PCAP SUMMARY]\n")
        f.write(f"Total packets: {len(packets)}\n")
        f.write(f"Capture duration: {capture_duration}\n")
        f.write(f"Start time: {start_time}\n")
        f.write(f"End time: {end_time}\n")
        f.write(f"Unique IPs: {len(total_ips)}\n")
        f.write(f"Unique Ports: {len(total_ports)}\n")
        f.write(f"Protocols Seen: {', '.join(protocols)}\n")
        f.write(f"Window size (s): {window_size}\n")
        f.write(f"Step size (s): {step_size}\n\n")

        for i, (start, end, pkts) in enumerate(windows, 1):
            f.write(f"[WINDOW {i}]\n")
            f.write(f"Time: {start} to {end}\n")

            flows = defaultdict(list)
            for pkt in pkts:
                key = extract_flow_key(pkt)
                if key:
                    flows[key].append(pkt)

            # brute force flow count
            auth_flow_counts = defaultdict(int)
            for key in flows:
                src_ip, dst_ip, sport, dport, proto = key
                if dport in AUTH_PORTS:
                    auth_flow_counts[(src_ip, dst_ip, dport)] += 1

            f.write(f"Flows: {min(len(flows), MAX_FLOWS_PER_WINDOW)}\n\n")

            for j, (key, flow_pkts) in enumerate(list(flows.items())[:MAX_FLOWS_PER_WINDOW], 1):
                info = extract_flow_info(flow_pkts, key, auth_flow_counts)
                f.write(f"Flow {j}:\n")
                f.write(f"{info['src_ip']} → {info['dst_ip']} [{info['protocol']} {info['src_port']}→{info['dst_port']}]\n")
                f.write(f"Packets: {info['packet_count']}, Bytes: {info['total_bytes']}, Duration: {info['duration']:.2f}s\n")
                f.write(f"TCP Flags: {', '.join(info['tcp_flags']) if info['tcp_flags'] else '-'}\n")
                f.write(f"DNS Queries: {', '.join(info['dns_queries']) if info['dns_queries'] else '-'}\n")
                f.write(f"App Protocol: {info['app_protocol'] or '-'}\n")
                f.write(f"Payload Preview: {info['payload_preview'][0] if info['payload_preview'] else '-'}\n")
                f.write(f"Attack Indicators: {', '.join(info['attack_signatures']) if info['attack_signatures'] else '-'}\n")
                f.write(f"Direction: {info['direction']}\n\n")

            f.write(f"[END WINDOW {i}]\n\n")

    return output_txt

