from scapy.all import IP, TCP, UDP, ICMP, wrpcap
import random
import time

def generate_test_pcap(filename="test_traffic.pcap"):
    packets = []
    
    # 1. Generate normal web traffic (HTTP/HTTPS)
    print("Generating normal web traffic...")
    for _ in range(50):
        src_ip = f"192.168.1.{random.randint(2, 20)}"
        dst_ip = "93.184.216.34" # example.com
        
        # Simulate small normal packets
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=443, flags="PA") / (b"X" * random.randint(40, 500))
        pkt.time = time.time() - random.randint(10, 3600)
        packets.append(pkt)

    # 2. Generate a suspicious port scan / exploit (High Risk anomaly)
    print("Generating malicious SSH/RDP sweep...")
    target_ip = "192.168.1.100"
    for _ in range(30):
        # Anomalous: Target is SSH (22) and RDP (3389), weird source ports, larger than normal sizes
        spoofed_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        dport = random.choice([22, 3389, 4444, 445])
        pkt = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=random.randint(1, 1023), dport=dport, flags="S") / (b"X" * random.randint(2000, 4000))
        pkt.time = time.time() - random.randint(1, 10)
        packets.append(pkt)
        
    # 3. Generate unusual UDP exfiltration (High Risk)
    print("Generating unusual UDP traffic...")
    for _ in range(15):
        # Anomalous: Huge UDP packets to a highly unusual port
        pkt = IP(src="192.168.1.5", dst="104.28.14.9") / UDP(sport=53, dport=31337) / (b"M" * 4500)
        pkt.time = time.time() - random.randint(1, 100)
        packets.append(pkt)

    # Sort packets by time to make it realistic
    packets.sort(key=lambda x: x.time)
    
    # Write to file
    wrpcap(filename, packets)
    print(f"[*] Successfully generated '{filename}' with {len(packets)} packets!")

if __name__ == "__main__":
    generate_test_pcap()
