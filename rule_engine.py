from collections import defaultdict
import time
import json

recent_activity=defaultdict(list)
def load_rules():
     with open("rules.json","r") as f:
          data=json.load(f)
          return data["rules"]
     
def get_rule(rule_type):
     rules=load_rules()
     for rule in rules:
          if rule["type"] == rule_type:
               return rule
     return None
     
     
def record_activity(src_ip,dst_port):
    now=time.time()
    recent_activity[src_ip].append((now,dst_port))

#function for checking differnt port req from ip
def check_port_scan(src_ip):
    rule = get_rule("port_scan")
    window_seconds=rule["window_seconds"]
    port_threshold=rule["unique_ports_threshold"]

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

def check_icmp_flood(src_ip):
    rule=get_rule('icmp_flood')
    window_seconds=rule['window_seconds']
    packet_threshold=rule['packet_threshold']

    now = time.time()
    activity_list = icmp_activity[src_ip]
    recent_entries = [
        entry for entry in activity_list
        if entry > now - window_seconds
    ]
    print(f"DEBUG: {src_ip} has {len(recent_entries)} recent ICMP packets (threshold={packet_threshold}, window={window_seconds})")  # <- new debug line

    if len(recent_entries) > packet_threshold:
        print(
            f"Alert: Possible ICMP flood {src_ip} - "
            f"{len(recent_entries)} packets in {window_seconds}s"
        )
        return True

    return False