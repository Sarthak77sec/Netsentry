from scapy.all import sniff,IP,TCP,UDP,ICMP
def start_sniffing(interface=None, count=0):
    sniff(iface=interface,prn=process_packet,count=count,store=False)

def process_packet(packet):
    if IP in packet:
        src_ip= packet[IP].src
        dest_ip=packet[IP].dst
        proto=packet[IP].proto

        print(f"{src_ip}->{dest_ip}| proto:{proto}")