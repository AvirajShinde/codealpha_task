from tkinter import TOP
from scapy.all import *

def analyze_packet(pkt):
    print("="*60)
    print(f"Packet captured at: {pkt.time}")
    print(f"Packet length: {len(pkt)} bytes")

    # --- Ethernet Layer ---
    if ether in pkt:
        ether = pkt[ether]
        print("\n[Ethernet]")
        print(f"Source MAC: {ether.src}")
        print(f"Destination MAC: {ether.dst}")
        print(f"Type: {hex(ether.type)}")

    # --- IP Layer ---
    if ip in pkt:
        ip = pkt[ip]
        print("\n[IP Layer]")
        print(f"Version: {ip.version}")
        print(f"Header Length: {ip.ihl * 4} bytes")
        print(f"Source IP: {ip.src}")
        print(f"Destination IP: {ip.dst}")
        print(f"Protocol: {ip.proto}")
        print(f"TTL: {ip.ttl}")

    # --- TCP Layer ---
    if TOP in pkt:
        tcp = pkt[TOP]
        print("\n[TCP Layer]")
        print(f"Source Port: {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print(f"Sequence Number: {tcp.seq}")
        print(f"Acknowledgment Number: {tcp.ack}")
        print(f"Flags: {tcp.flags}")

    # --- UDP Layer ---
    elif udp in pkt:
        udp = pkt[udp]
        print("\n[UDP Layer]")
        print(f"Source Port: {udp.sport}")
        print(f"Destination Port: {udp.dport}")
        print(f"Length: {udp.len}")

    # --- ICMP Layer ---
    elif icmp in pkt:
        icmp = pkt[icmp]
        print("\n[ICMP Layer]")
        print(f"Type: {icmp.type}")
        print(f"Code: {icmp.code}")

    # --- Payload (Raw data) ---
    if Raw in pkt:
        raw_data = pkt[Raw].load
        print("\n[Raw Payload]")
        try:
            print(raw_data.decode('utf-8', errors='ignore'))
        except:
            print("Binary data (not printable)")

    print("="*60)


# 🔍 Capture and analyze packets live
def main():
    print("Starting packet capture... Press Ctrl+C to stop.\n")
    sniff(prn=analyze_packet, count=5)  # capture and analyze 5 packets

if __name__ == "__main__":
    main()
