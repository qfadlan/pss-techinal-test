from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

# File PCAP kamu
pcap_file = '/home/cimol/naissur.pcap'

# Baca semua paket dari file pcap
packets = rdpcap(pcap_file)

# Dictionary: scanner IP → set of target IPs
scan_activity = defaultdict(lambda: {'targets': set(), 'ports': set(), 'protocols': set()})

# Threshold jumlah target unik (jika melebihi ini, diasumsikan scanning)
SCAN_THRESHOLD = 10

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Scan biasanya menggunakan TCP SYN atau UDP, dst port penting
        if TCP in pkt:
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            scan_activity[src]['protocols'].add('TCP')
            scan_activity[src]['ports'].add(dport)
            scan_activity[src]['targets'].add(dst)
        elif UDP in pkt:
            dport = pkt[UDP].dport
            scan_activity[src]['protocols'].add('UDP')
            scan_activity[src]['ports'].add(dport)
            scan_activity[src]['targets'].add(dst)

# Tampilkan host yang diduga melakukan scanning
print("\n🔍 Identifikasi Aktivitas Scanning:\n")

found = False
for scanner_ip, details in scan_activity.items():
    if len(details['targets']) >= SCAN_THRESHOLD:
        found = True
        print(f"🛑 Scanner IP       : {scanner_ip}")
        print(f"📦 Jumlah Target    : {len(details['targets'])}")
        print(f"🎯 Daftar Target    : {', '.join(sorted(details['targets']))}")
        print(f"📡 Protokol Terdeteksi: {', '.join(details['protocols'])}")
        print(f"🔢 Port Tujuan      : {', '.join(map(str, sorted(details['ports'])))[:100]}...")
        print("-" * 60)

if not found:
    print("✅ Tidak ditemukan aktivitas scanning yang signifikan (dalam ambang threshold).")
