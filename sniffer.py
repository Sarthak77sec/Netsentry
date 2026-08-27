from scapy.all import sniff,IP,TCP,UDP,ICMP
def start_sniffing(interface=None, count=0):
    sniff(iface=interface,prn=process_packet,count=count,store=False)

def process_packet(packet):
    if IP in packet:
        src_ip= packet[IP].src
        dest_ip=packet[IP].dst
        
         if TCP in packet:
            src_port=packet[TCP].sport
            dest_port=packet[TCP].dport
            flags=packet[TCP].flags
            
            

        
