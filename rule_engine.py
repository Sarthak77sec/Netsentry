from collections import defaultdict
import time

recent_activity=defaultdict(list)

def record_activity(src_ip,dst_port):
    now=time.time()
    recent_activity[src_ip,].append((now,dst_port))
