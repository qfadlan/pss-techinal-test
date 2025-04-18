from scapy.all import rdpcap, IP, ICMP, ARP, TCP
from collections import defaultdict

# Load file PCAP
pcap_file = "/home/cimol/naissur.pcap"
packets = rdpcap(pcap_file)

# Dictionary untuk mencatat IP yang mencoba scan banyak host
icmp_scans = defaultdict(set)
arp_scans = defaultdict(set)
tcp_scans = defaultdict(set)

# Threshold: berapa banyak IP yang di-scan untuk dikategorikan sebagai host discovery
THRESHOLD = 10

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        # ICMP Ping Sweep
        if ICMP in pkt and pkt[ICMP].type == 8:  # Echo request
            icmp_scans[src].add(dst)

        # TCP SYN ke banyak host (port scanning juga bisa ikut terdeteksi)
        if TCP in pkt and pkt[TCP].flags == 'S':
            tcp_scans[src].add(dst)

    # ARP scan (biasanya broadcast)
    elif ARP in pkt and pkt[ARP].op == 1:  # who-has
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
        arp_scans[src].add(dst)

# Filter IP yang melakukan scan lebih dari threshold
suspected_hosts = {
    "ICMP Host Discovery": [ip for ip, targets in icmp_scans.items() if len(targets) >= THRESHOLD],
    "ARP Discovery": [ip for ip, targets in arp_scans.items() if len(targets) >= THRESHOLD],
    "TCP SYN Discovery": [ip for ip, targets in tcp_scans.items() if len(targets) >= THRESHOLD]
}

# Tampilkan hasil
for method, ips in suspected_hosts.items():
    if ips:
        print(f"\n[*] Suspected {method} activity detected from:")
        for ip in ips:
            print(f"   - {ip}")
    else:
        print(f"\n[✓] No significant {method} activity found.")
