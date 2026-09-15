from collections import defaultdict
import time

recent_activity=defaultdict(list)

def record_activity(src_ip,dst_port):
    now=time.time()
    recent_activity[src_ip].append((now,dst_port))

#function for checking differnt port req from ip
def check_port_scan(src_ip,window_seconds=10, port_threshold=15):
    now=time.time()
    activity_list=recent_activity[src_ip]

    recent_entries=[entry for entry in activity_list if entry[0] > now-window_seconds]

    unique_ports=set(entry[1] for entry in recent_entries)

    if len(unique_ports) > port_threshold:
                print(f"ALERT: Possible port scan from {src_ip} - {len(unique_ports)} ports in {window_seconds}s")
                return True
    
    return False

icmp_activity=defaultdict(list)

def record_icmp(src_ip):
    now=time.time()
    icmp_activity[src_ip].append(now)

def check_icmp_flood(src_ip,window_seconds=5,packet_threshold=100):
    now=time.time()
    activity_list=icmp_activity[src_ip]

    recent_entries=[entry for entry in activity_list if entry > now-window_seconds]

    if len(recent_entries)>packet_threshold:
          print(f"Alert:Possible ICMP flood {src_ip} - {len(recent_entries)} packets in {window_seconds}s")

          return True
    
    return False
