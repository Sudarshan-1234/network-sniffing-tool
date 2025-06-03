from scapy.all import sniff, IP, TCP, UDP
from scapy.utils import wrpcap
from datetime import datetime
import argparse
import csv
import os
import pandas as pd
import matplotlib.pyplot as plt

# ----------- CLI Argument Parser -----------
parser = argparse.ArgumentParser(description="Network Sniffing Tool with Filters, PCAP, Visualization & Reporting")
parser.add_argument('--protocols', nargs='+', default=['TCP', 'UDP'], help='Protocols to capture (e.g., TCP UDP)')
parser.add_argument('--src-ports', nargs='+', type=int, default=[], help='Source ports to filter')
parser.add_argument('--dst-ports', nargs='+', type=int, default=[], help='Destination ports to filter')
parser.add_argument('--duration', type=int, default=None, help='Capture duration in seconds (optional)')
args = parser.parse_args()

# ----------- File Setup -----------
script_dir = os.path.dirname(os.path.abspath(_file_))
timestamp_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

csv_filename = os.path.join(script_dir, f"network_traffic_{timestamp_str}.csv")
pcap_filename = os.path.join(script_dir, f"network_traffic_{timestamp_str}.pcap")
report_filename = os.path.join(script_dir, f"summary_report_{timestamp_str}.txt")

csv_file = open(csv_filename, 'w', newline='')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Length'])

captured_packets = []

# ----------- Sniff Callback -----------
def packet_callback(packet):
    if IP in packet:
        proto = packet[IP].proto

        if proto == 6 and TCP in packet:
            proto_name = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif proto == 17 and UDP in packet:
            proto_name = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            return  # Skip non-TCP/UDP

        if proto_name in args.protocols:
            if (not args.src_ports or src_port in args.src_ports) and \
               (not args.dst_ports or dst_port in args.dst_ports):

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_len = len(packet)

                print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {proto_name} | Length: {packet_len}")
                csv_writer.writerow([timestamp, src_ip, dst_ip, proto_name, src_port, dst_port, packet_len])
                captured_packets.append(packet)

# ----------- Start Sniffing -----------
print("[*] Sniffing started... Press Ctrl+C to stop.\n")
try:
    sniff(prn=packet_callback, store=0, timeout=args.duration)
except KeyboardInterrupt:
    print("\n[*] Sniffing stopped by user.")
finally:
    csv_file.close()
    wrpcap(pcap_filename, captured_packets)
    print(f"[*] CSV saved to: {csv_filename}")
    print(f"[*] PCAP saved to: {pcap_filename}")

    # ----------- Visualization -----------
    try:
        df = pd.read_csv(csv_filename)
        protocol_counts = df['Protocol'].value_counts()

        plt.figure(figsize=(10, 6))
        protocol_counts.plot(kind='bar', color='orange')
        plt.title('Captured Protocol Distribution')
        plt.xlabel('Protocol')
        plt.ylabel('Packet Count')
        plt.tight_layout()
        plt.show()
    except Exception as e:
        print(f"[!] Visualization error: {e}")

    # ----------- Summary Report -----------
    try:
        total_packets = len(df)
        top_src_ips = df['Source IP'].value_counts().head(5)
        top_dst_ips = df['Destination IP'].value_counts().head(5)
        top_src_ports = df['Source Port'].value_counts().head(5)
        top_dst_ports = df['Destination Port'].value_counts().head(5)

        lines = [
            f"Packet Sniffing Summary Report - {timestamp_str}",
            f"Total Packets Captured: {total_packets}\n",
            "Top 5 Source IPs:",
            top_src_ips.to_string(), "\n",
            "Top 5 Destination IPs:",
            top_dst_ips.to_string(), "\n",
            "Protocol Usage:",
            protocol_counts.to_string(), "\n",
            "Top 5 Source Ports:",
            top_src_ports.to_string(), "\n",
            "Top 5 Destination Ports:",
            top_dst_ports.to_string(), "\n"
        ]

        with open(report_filename, 'w') as f:
            f.write('\n'.join(lines))

        print(f"[*] Summary report saved to: {report_filename}")

    except Exception as e:
        print(f"[!] Summary generation error: {e}")