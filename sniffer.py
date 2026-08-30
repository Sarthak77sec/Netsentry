from scapy.all import sniff,IP,TCP,UDP,IPv6

def start_sniffing(interface=None, count=0):
    sniff(iface=interface,prn=process_packet,count=count,store=False)

def process_packet(packet):
    if IP in packet:
        src_ip= packet[IP].src
        dest_ip=packet[IP].dst

        if TCP in packet:
            src_port=packet[TCP].sport
            dst_port=packet[TCP].dport
            flags=packet[TCP].flags
            print(f"TCP{src_ip}:{src_port}->{dest_ip}:{dst_port} flags={flags}")

        elif UDP in packet:
             src_port=packet[UDP].sport
             dst_port=packet[UDP].dport
             print(f"UDP{src_ip}:{src_port}->{dest_ip}:{dst_port}")


        else:
            print(f"other IP proto:{src_ip}->{dest_ip}")

    elif IPv6 in packet:
            src_ip=packet[IPv6].src
            dest_ip=packet[IPv6].dst
    
            if TCP in packet:
                src_port=packet[TCP].sport
                dst_port=packet[TCP].dport
                flags=packet[TCP].flags
                print(f"TCP6{src_ip}:{src_port}->{dest_ip}:{dst_port} flags={flags}")

            elif UDP in packet:
                 src_port=packet[TCP].sport
                 dst_port=packet[UDP].dport
                 print(f"UDP6 {src_ip}:{src_port}->{dest_ip}:{dst_port}")  
            else:
                 print(f"other IPV6 proto {src_ip}->{dest_ip}")  
            