# Splunk searches

All searches use `index=suricata`. In an `eval`, wrap dotted field names in single quotes, for example `'flow.pkts_toclient'`.

## 1. Alert timeline by signature
```
index=suricata event_type=alert | timechart span=10s count by alert.signature
```

## 2. Top alerting sources
```
index=suricata event_type=alert | stats count dc(alert.signature) as rules_hit by src_ip | sort - count
```

## 3. Half-open vs completed connections (SYN flood evidence)
First list the TCP states your sensor actually logged, and adjust the search below to match:
```
index=suricata event_type=flow proto=TCP | stats count by tcp.state
```
Then chart half-open flows (SYN seen, handshake never completed) over time:
```
index=suricata event_type=flow proto=TCP | eval handshake=if('tcp.state'="syn_sent" OR 'tcp.state'="syn_recv","half-open","completed or other") | timechart span=5s count by handshake
```
Note: an earlier version counted flows with no server reply (`flow.pkts_toclient=0`) as "unanswered". That does not work against a live listener, because the target answers every SYN, so every flow looked answered (16,133 of 16,133 in the lab data).

## 4. HTTP requests vs distinct sources
```
index=suricata event_type=http | bin _time span=5s | stats count as requests dc(src_ip) as sources by _time | eval per_source=round(requests/sources,1)
```

## 5. Flood vs flash-crowd classifier
The thresholds are starting points. Tune them to your own data.
```
index=suricata event_type=http | bin _time span=5s
| stats count as requests dc(src_ip) as sources by _time
| eval verdict=case(requests>=100 AND sources<=2,"Likely flood (few sources, high rate)", requests>=100 AND sources>=10,"Likely flash crowd (many sources)", true(),"Normal")
```

## 6. Alert search (flood rules)
```
index=suricata event_type=alert alert.signature_id IN (10003,10004) | stats count by src_ip
```
