from scapy.all import sniff, IP

def process_packet(packet):
    if IP in packet:
        print(f"{packet[IP].src} -> {packet[IP].dst}")

sniff(iface="eth0", prn=process_packet, count=10, store=False)