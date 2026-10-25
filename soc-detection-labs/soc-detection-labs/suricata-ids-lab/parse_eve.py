#!/usr/bin/env python3
"""Summarise Suricata alerts from eve.json: counts per signature, top sources, first/last seen."""
import json, sys
from collections import Counter, defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/suricata/eve.json"
by_sig, by_src, seen = Counter(), defaultdict(Counter), defaultdict(list)

with open(path) as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event_type") != "alert":
            continue
        sig = e["alert"]["signature"]
        by_sig[sig] += 1
        by_src[sig][e.get("src_ip", "?")] += 1
        seen[sig].append(e["timestamp"])

if not by_sig:
    print("No alerts found.")
    sys.exit(0)

for sig, n in by_sig.most_common():
    src, cnt = by_src[sig].most_common(1)[0]
    print(f"{n:>5}  {sig}\n       top source: {src} ({cnt})  first: {min(seen[sig])}  last: {max(seen[sig])}")
