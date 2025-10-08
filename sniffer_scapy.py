"""
sniffer_scapy.py
Capture packets using Scapy, print summaries, and write to a pcap file incrementally.

Usage examples:
sudo python3 sniffer_scapy.py                # default: capture on first iface, unlimited until Ctrl-C
sudo python3 sniffer_scapy.py -i eth0 -c 100 -w capture.pcap -f "tcp and port 80"
"""
import argparse
import sys
import time
from scapy.all import sniff, PcapWriter, conf

def human_time(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

def packet_summary(pkt):
    # Build a concise summary string
    ts = getattr(pkt, 'time', None)
    tstr = human_time(ts) if ts else "-"
    src = pkt.sprintf("%IP.src%") if pkt.haslayer("IP") else pkt.sprintf("%Ether.src%")
    dst = pkt.sprintf("%IP.dst%") if pkt.haslayer("IP") else pkt.sprintf("%Ether.dst%")
    proto = pkt.lastlayer().name if pkt.lastlayer() is not None else "Unknown"
    length = len(pkt)
    # Ports if present
    sport = pkt.sprintf("%TCP.sport%") if pkt.haslayer("TCP") else (pkt.sprintf("%UDP.sport%") if pkt.haslayer("UDP") else "")
    dport = pkt.sprintf("%TCP.dport%") if pkt.haslayer("TCP") else (pkt.sprintf("%UDP.dport%") if pkt.haslayer("UDP") else "")
    ports = f"{sport}->{dport}" if sport or dport else ""
    return f"{tstr} | {src} -> {dst} | {proto} | {ports} | {length} bytes"

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer using Scapy")
    parser.add_argument("-i", "--iface", help="Network interface to listen on (default: Scapy default)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (default: 0 = unlimited)", default=0)
    parser.add_argument("-w", "--write", help="Output pcap file (writes incrementally)", default="capture.pcap")
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g. 'tcp and port 80')", default=None)
    parser.add_argument("--promisc", action="store_true", help="Enable promiscuous mode (default: depends on OS)")
    args = parser.parse_args()

    # Choose interface
    if args.iface:
        conf.iface = args.iface

    print(f"Using Scapy version: {conf.version}")
    print(f"Listening on interface: {conf.iface}")
    print(f"BPF filter: {args.filter}")
    print(f"Writing to: {args.write}")
    print("Press Ctrl-C to stop.\n")

    pcap_writer = PcapWriter(args.write, append=True, sync=True)

    def on_packet(pkt):
        # Print a human-readable summary for quick inspection
        try:
            print(packet_summary(pkt))
        except Exception as e:
            print("Summary error:", e)
        # Write incrementally to disk
        try:
            pcap_writer.write(pkt)
        except Exception as e:
            print("PCAP write error:", e)

    try:
        sniff(iface=args.iface, prn=on_packet, filter=args.filter, store=False,
              count=args.count if args.count > 0 else 0, promisc=args.promisc)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied: run as root/Administrator or allow packet capture capability.")
        sys.exit(1)
    except Exception as e:
        print("Sniffing error:", e)
    finally:
        pcap_writer.close()
        print(f"Saved capture to {args.write}")

if __name__ == "__main__":
    main()
