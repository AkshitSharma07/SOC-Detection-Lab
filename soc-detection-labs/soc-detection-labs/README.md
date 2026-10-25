# SOC Detection Labs

Hands-on blue-team labs built in an isolated VirtualBox environment (Kali attacker, Ubuntu sensor, host-only network). Each project documents its setup, detection logic, test traffic, results and limitations so it can be reproduced.

| # | Project | Folder | Status |
|---|---|---|---|
| 1 | Suricata IDS detection lab: custom rules for port scans, SSH connection bursts, SYN floods and HTTP floods | [`suricata-ids-lab/`](suricata-ids-lab/) | Tested (baseline run pending) |
| 2 | Splunk DoS detection dashboard: searches that separate flood traffic from a legitimate traffic spike | [`splunk-dos-dashboard/`](splunk-dos-dashboard/) | In progress (1 of 4 scenarios captured) |

Project 2 builds on the Suricata sensor from project 1. Screenshots go in each project's `screenshots/` folder.

## Lab environment

```
Kali Linux (attacker)            Ubuntu (target + Suricata sensor + Splunk)
192.168.56.101      -------->    192.168.56.104
        VirtualBox host-only network 192.168.56.0/24
```

| Component | Detail |
|---|---|
| Hypervisor | Oracle VirtualBox, host-only network (`192.168.56.0/24`) plus a NAT adapter for updates |
| Target / sensor | Ubuntu 26.04, Suricata 8.0.3 in IDS mode (af-packet) on the host-only interface, with nginx and OpenSSH as targets |
| Attacker | Kali Linux with nmap, hydra, hping3 and ApacheBench |

---

# Project 1: Suricata IDS detection lab

Files: [`local.rules`](suricata-ids-lab/local.rules) (the four rules) and [`parse_eve.py`](suricata-ids-lab/parse_eve.py) (summarises alerts from `eve.json`).

## Detection rules

Each rule uses `threshold: type both`, so it raises **one alert per time window** while the condition holds.

| SID | Detects | Logic | Threshold |
|---|---|---|---|
| 10001 | TCP SYN port scan | SYN packets from one source to any port on HOME_NET | 30 in 5 s |
| 10002 | SSH connection burst (brute-force behaviour) | SYN packets from one source to port 22 | 4 in 30 s |
| 10003 | SYN flood | SYN packets to any port, counted per destination | 300 in 2 s |
| 10004 | HTTP request flood | Established `GET` requests from one source | 100 in 5 s |

## Attacks (from Kali, against `192.168.56.104`)

```bash
nmap -sS -p 1-1000 192.168.56.104                               # SID 10001
hydra -l labuser -P wordlist.txt ssh://192.168.56.104 -t 4 -V   # SID 10002
sudo hping3 -S -p 80 --faster -c 5000 192.168.56.104            # SID 10003
ab -n 2000 -c 20 http://192.168.56.104/                         # SID 10004
```

## Results

Source: alert events in Splunk (`index=suricata`, 24-hour window ending 20:51 on 24 Oct 2026). Times are local (UTC+05:30). The counts cover everything Splunk ingested in that window, so they combine all runs, not one attack each.

| Rule | Fired? | First alert | Last alert | Alerts logged |
|---|---|---|---|---|
| 10001 SYN port scan | Yes | 20:03:06 | 20:07:01 | 6 |
| 10002 SSH connection burst | Yes | 11:26:22 | 20:04:23 | 6 |
| 10003 SYN flood | Yes | 20:03:06 | 20:07:01 | 6 |
| 10004 HTTP request flood | Yes | 20:07:01 | 20:07:01 | 2 |

Observations:
- **SSH rule:** did not fire against Hydra until its threshold was lowered (see the tuning log). Hydra alerts were logged at 11:26:22 and 11:27:24. The first-alert time above is from the morning session and the last-alert time is from the evening session.
- **Scan and SYN flood rules overlap:** both logged their first alert at 20:03:06, and the flood alert was against destination port 188, so the nmap sweep tripped the flood rule.
- **`ab` run:** rules 10001, 10003 and 10004 all logged alerts at 20:07:01.
- **Alerts are per window, not per attack:** a sustained attack produces one alert per threshold window.

Not captured: time to first alert (attack start times were not recorded), a baseline false-positive check on normal traffic, and per-attack alert counts.

## Tuning log

1. **SSH rule (10002): threshold lowered to 4 connections in 30 s.** With its initial threshold (30 SYNs in 5 s, the same as the scan rule) it never fired against Hydra, which opens new connections slowly and reuses them. After the change, Hydra triggered it. Trade-off: bursts of legitimate SSH connections (scripts, `scp` loops, automation) can now trigger it.

## Observed rule overlap (not fixed in this run)

- A fast nmap sweep of ports 1-1000 tripped both the scan rule (10001) and the SYN flood rule (10003). Rule 10003 counts SYNs to any port.
- The `ab` HTTP flood run produced alerts from rules 10001, 10003 and 10004.
- Proposed mitigation (not applied or tested live): scope rule 10003 to the service ports it should protect, for example `$HOME_NET [80,443]`. Trade-off: floods against other ports would go undetected.

## Limitations

- **Thresholds count packets, not distinct ports.** The scan and flood rules overlap. An analyst separates the two by destination: alerts concentrated on one port suggest a flood, spread across many ports suggests a scan.
- **The SSH rule counts connection attempts, not failed logins.** It indicates a high connection rate. Reliable brute-force detection needs authentication log analysis (for example `Failed password` events in `auth.log` ingested into a SIEM).
- **Thresholds are tuned for a small lab network.** Production values depend on normal traffic volumes.
- **Signature thresholds miss low-and-slow activity** that stays under the counts.

## Reproduce

1. Create two VMs on a VirtualBox host-only network (Ubuntu target, Kali attacker).
2. On the target: `sudo apt install suricata nginx openssh-server jq`, then `sudo ethtool -K <iface> gro off lro off`.
3. In `/etc/suricata/suricata.yaml` set `HOME_NET`, set the `af-packet` interface to the host-only NIC, and add `- local.rules` under `rule-files`.
4. Copy `suricata-ids-lab/local.rules` to `/var/lib/suricata/rules/`, run `sudo suricata -T -c /etc/suricata/suricata.yaml`, then `sudo systemctl restart suricata`.
5. Watch `sudo tail -f /var/log/suricata/fast.log`, run the attacks from Kali, and summarise with `python3 suricata-ids-lab/parse_eve.py /var/log/suricata/eve.json`.

---

# Project 2: Splunk DoS detection dashboard

> **Status:** In progress. The single-source flood scenario is captured. The baseline, spoofed SYN flood and flash-crowd scenarios are pending.

Ingests Suricata's `eve.json` into Splunk and builds searches, a dashboard and an alert that help tell a **denial-of-service flood** apart from a **legitimate traffic spike**. All searches are in [`searches.md`](splunk-dos-dashboard/searches.md).

## Data flow

```
Suricata (IDS) --> /var/log/suricata/eve.json --> Splunk monitor input --> index "suricata" --> searches / dashboard / alert
```

Fields used:

| Event type | Fields |
|---|---|
| `alert` | `alert.signature`, `alert.signature_id`, `src_ip`, `dest_port` |
| `flow` | `tcp.state`, `flow.pkts_toserver`, `flow.pkts_toclient`, `src_ip`, `dest_port` |
| `http` | `http.url`, `http.http_user_agent`, `http.status`, `src_ip` |

## Detection approach

| Signal | Flood-like | Legitimate-spike-like |
|---|---|---|
| Distinct source IPs | Few (single attacker) or many spoofed | Many real clients |
| Requests per source | Very high | Low |
| Handshakes | Many half-open flows (SYN seen, never completed) | Handshakes complete |
| Suricata rules | 10003 / 10004 fire | Rules stay quiet |

## Dashboard panels and alert

1. Alert timeline by signature
2. Top alerting sources
3. Half-open vs completed connections over time
4. HTTP requests vs distinct sources
5. Flood vs flash-crowd classifier

Alert: search 6 in `searches.md`, scheduled every minute (`* * * * *`) over the last 2 minutes, triggering when the result count is greater than 0, with a 60-second throttle. Requires the Splunk Enterprise trial license (the Free license cannot run alerts).

## Test scenarios and results

Run from Kali against `192.168.56.104`, one at a time. "Expected" was written before testing.

| # | Scenario | Command | Expected |
|---|---|---|---|
| 1 | Baseline | A slow `curl` loop against the nginx page | No flood alerts; low request count, few sources |
| 2 | Single-source flood | `ab -n 5000 -c 20 http://192.168.56.104/` | Rule 10004 fires (10001 and 10003 may also fire); few sources, very high requests per source |
| 3 | Spoofed SYN flood | `sudo hping3 -S -p 80 --faster --rand-source -c 5000 192.168.56.104` | Rule 10003 fires; many sources, spike of half-open flows |
| 4 | Simulated flash crowd | See below | Flood rules stay quiet; completed requests from about 10 sources |

The 4,000 requests are all the HTTP events in the index for the window (24 hours ending about 20:54 on 24 Oct 2026), and all came from `192.168.56.101`.

Scenario 4 setup (alias IPs on Kali, host-only interface `eth1`):

```bash
for i in $(seq 111 120); do sudo ip addr add 192.168.56.$i/24 dev eth1; done
for i in $(seq 111 120); do (for n in $(seq 1 15); do curl -s -o /dev/null --interface 192.168.56.$i http://192.168.56.104/; done) & done; wait
# clean up afterwards
for i in $(seq 111 120); do sudo ip addr del 192.168.56.$i/24 dev eth1; done
```

## Findings

- **A single source dominates the flood.** One source sent all 4,000 HTTP requests, which is what a flood looks like in the sources-versus-requests view. The comparison with a multi-source spike (scenario 4) is not yet captured, so the flood-versus-flash-crowd contrast is untested.
- **"Unanswered connection" does not work as a SYN flood signal against a live listener.** All 16,133 TCP flows in the index had a server reply, because the target answers every SYN. The connection search now uses `tcp.state` to find half-open flows. It has not yet been validated against a spoofed SYN flood.
- **Rule overlap:** during the `ab` run, rules 10001, 10003 and 10004 all alerted at 20:07:01.

Pending: scenarios 1, 3 and 4, and recording the alert test.

## Limitations

- The thresholds are lab-scale starting points. A real deployment needs baselines learned from real traffic.
- A distributed flood that completes its handshakes looks like a flash crowd in these searches. This is a real detection gap.
- Only one attacker VM exists, so "distributed" traffic is simulated with spoofed sources and alias IP addresses.
- Suricata logs flow events when a flow expires, so the connection chart lags the traffic by up to a minute.
- The Splunk Enterprise trial lasts 60 days, after which the Free license cannot run alerts.

## Reproduce

1. Complete the Suricata sensor from project 1.
2. Install Splunk Enterprise on the sensor VM: `sudo dpkg -i splunk-*.deb`, then `sudo /opt/splunk/bin/splunk start --accept-license`.
3. Create the index and monitor the log:
   ```bash
   sudo /opt/splunk/bin/splunk add index suricata -auth admin:<password>
   sudo /opt/splunk/bin/splunk add monitor /var/log/suricata/eve.json -index suricata -sourcetype _json -auth admin:<password>
   ```
4. Verify ingestion: `index=suricata | stats count by event_type`
5. Run the scenarios, save the searches from `searches.md` as dashboard panels, and create the alert.

---

## Responsible use

All traffic was generated inside an isolated host-only network against VMs I own. Do not run these tools against systems you do not own or have written permission to test.
