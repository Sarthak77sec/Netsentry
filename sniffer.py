from scapy.all import sniff,IP,TCP,UDP,IPv6,ICMP
import sqlite3
from db import insert_packet
from datetime import datetime
from rule_engine import*

conn=sqlite3.connect("data/netsentry.db",timeout=10)

def start_sniffing(interface=None, count=0):
    sniff(iface=interface,prn=process_packet,count=count,store=False)

def process_packet(packet):
    if IP in packet:
        src_ip= packet[IP].src
        dest_ip=packet[IP].dst

        if TCP in packet:
            src_port=packet[TCP].sport
            dst_port=packet[TCP].dport
            flags=str(packet[TCP].flags)
            timestamp=str(datetime.now())
            print(f"TCP{src_ip}:{src_port}->{dest_ip}:{dst_port} flags={flags}")
            insert_packet(conn,timestamp,src_ip,dest_ip,"TCPv4",src_port,dst_port,flags)
            record_activity(src_ip,dst_port)
            check_port_scan(src_ip)

            if flags=="S":
                 record_syn(src_ip)
                 check_syn_flood(src_ip)


        elif UDP in packet:
             src_port=packet[UDP].sport
             dst_port=packet[UDP].dport
             timestamp=str(datetime.now())
             print(f"UDP{src_ip}:{src_port}->{dest_ip}:{dst_port}")
             insert_packet(conn,
                           timestamp,
                           src_ip,
                           dest_ip,"UDPv4",src_port,dst_port,flags=None)
             record_activity(src_ip,dst_port)
             check_port_scan(src_ip)
             
        elif ICMP in packet:
             timestamp = str(datetime.now())

             print(f"ICMP {src_ip}->{dest_ip}")

             insert_packet(
                  conn,
                  timestamp,
                  src_ip,
                  dest_ip,
                  "ICMPv4",
                  src_port=None,
                  dst_port=None,
                  flags=None)

             record_icmp(src_ip)
             check_icmp_flood(src_ip)

        else:
            print(f"other IP proto:{src_ip}->{dest_ip}")
            timestamp=str(datetime.now())
            insert_packet(conn,timestamp,src_ip,dest_ip,
                          "other proto",
                          src_port=None,
                          dst_port=None
                          ,flags=None)
            record_icmp(src_ip)
            check_icmp_flood(src_ip)
            

    elif IPv6 in packet:
            src_ip=packet[IPv6].src
            dest_ip=packet[IPv6].dst
    
            if TCP in packet:
                src_port=packet[TCP].sport
                dst_port=packet[TCP].dport
                flags=str(packet[TCP].flags)
                timestamp=str(datetime.now())
                print(f"TCP6{src_ip}:{src_port}->{dest_ip}:{dst_port} flags={flags}")
                insert_packet(conn,timestamp,src_ip,dest_ip,"TCPv6",src_port,dst_port,flags)
                record_activity(src_ip,dst_port)
                check_port_scan(src_ip)
                
                if flags=="S":
                    record_syn(src_ip)
                    check_syn_flood(src_ip)
                

            elif UDP in packet:
                 src_port=packet[UDP].sport
                 dst_port=packet[UDP].dport
                 print(f"UDP6 {src_ip}:{src_port}->{dest_ip}:{dst_port}")
                 timestamp=str(datetime.now())
                 insert_packet(conn,timestamp,src_ip,dest_ip,"UDPv6",src_port,dst_port,flags=None)
                 record_activity(src_ip,dst_port)
                 check_port_scan(src_ip)  
                 
            else:
                 print(f"other IPV6 proto {src_ip}->{dest_ip}")  
                 timestamp=str(datetime.now())
                 insert_packet(conn,timestamp,src_ip,dest_ip,"other v6 proto",src_port=None,dst_port=None,flags=None)
                 record_icmp(src_ip)
                 check_icmp_flood(src_ip)
            