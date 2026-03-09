from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

# Log file to save captured packets
LOG_FILE = "captured_packets.txt"

def analyze_packet(packet):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        if TCP in packet:
            line = f"[{timestamp}] [TCP] {src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}"
        elif UDP in packet:
            line = f"[{timestamp}] [UDP] {src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}"
        elif ICMP in packet:
            line = f"[{timestamp}] [ICMP] {src} -> {dst} | Type: {packet[ICMP].type}"
        else:
            line = f"[{timestamp}] [OTHER] {src} -> {dst} | Proto: {packet[IP].proto}"

        # Print to terminal
        print(line)

        # Save to log file
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

# Stats counter
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

def analyze_packet_with_stats(packet):
    if IP in packet:
        if TCP in packet:
            stats["TCP"] += 1
        elif UDP in packet:
            stats["UDP"] += 1
        elif ICMP in packet:
            stats["ICMP"] += 1
        else:
            stats["OTHER"] += 1
    analyze_packet(packet)

print("=" * 50)
print("   BASIC NETWORK SNIFFER - ARCH TECHNOLOGIES")
print("=" * 50)
print(f"Capturing 50 packets... Saving to '{LOG_FILE}'")
print("Press Ctrl+C to stop early.\n")

try:
    sniff(filter="ip", prn=analyze_packet_with_stats, store=False, count=50, iface=None)
except KeyboardInterrupt:
    pass

# Print summary
print("\n" + "=" * 50)
print("CAPTURE SUMMARY:")
print(f"  TCP  packets: {stats['TCP']}")
print(f"  UDP  packets: {stats['UDP']}")
print(f"  ICMP packets: {stats['ICMP']}")
print(f"  OTHER packets: {stats['OTHER']}")
print(f"  TOTAL: {sum(stats.values())}")
print("=" * 50)
print(f"Log saved to: {LOG_FILE}")