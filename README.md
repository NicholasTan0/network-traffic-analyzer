# Passive Network Reconnaissance & Traffic Analysis Tool

network_traffic_analyzer.py is a passive network sniffer implemented in Python using the Scapy framework. It is designed to perform passive reconnaissance, allowing users to fingerprint services, detect automated scripts, and infer internal network infrastructure without actively interacting with targets.

---

## System Dependencies & Installation

network_traffic_analyzer.py requires a Linux environment (fully tested on a 64-bit Kali Linux virtual machine) and relies on Python 3 along with the Scapy network inspection framework.

To install all necessary dependencies using the native package manager on Kali Linux, run:

```bash
sudo apt update
sudo apt install -y python3 python3-scapy

```

---

## Technical Architecture

network_traffic_analyzer.py bypasses the limitation of standard port-based filtering. Instead of assuming protocol types by port number (e.g., port 80 for HTTP), it performs raw payload inspection to identify applications running on non-standard ports.

### Core Mechanisms

* **Deep Packet Dissection:** If a packet lacks explicit layer signatures but contains raw data, network_traffic_analyzer.py applies signature-matching heuristics. It scans TCP blocks for raw HTTP strings (`GET`, `POST`, `PUT`, `DELETE`) or TLS handshake identifiers (`0x16 0x03`). For UDP blocks, it tries to decode payloads natively into DNS queries.
* **HTTP Parsing:** Tracks HTTP/1.x `GET`, `POST`, and `PUT` methods. It monitors the `User-Agent` header for fingerprints containing `curl`, `wget`, or `python`, appending an `AUTOMATION` flag when found.
* **TLS SNI Extraction:** Parses the unencrypted `ClientHello` handshake packet to extract the Server Name Indication (SNI) field. If an SNI extension is absent, it reports `NO SNI`.
* **DNS Infrastructure Auditing:** Filters for cleartext UDP `A` record queries. If the requested domain target uses a top-level domain indicative of isolated internal staging environments (`.local`, `.corp`, `.internal`), it appends an `INTERNAL` warning flag.

---

## Usage Specification

### Command Syntax

```text
network_traffic_analyzer.py [-i interface] [-r tracefile] [expression]

```

| Argument | Description |
| --- | --- |
| `-i <interface>` | Specifies the live network interface to capture packets from (defaults to `eth0` if omitted). Runs continuously until manually terminated. |
| `-r <tracefile>` | Reads and analyzes packets from a saved pcap/tcpdump trace file. Overrides the live interface (`-i`) flag if both are supplied. |
| `expression` | Optional Berkeley Packet Filter (BPF) syntax string (e.g., `"host 192.168.0.123"`) to limit the captured scope. |

### Execution Examples

**Live sniffing on default interface (`eth0`):**

```bash
sudo python3 network_traffic_analyzer.py

```

**Live sniffing on a custom interface with a specific host filter:**

```bash
sudo python3 network_traffic_analyzer.py -i eth1 "src host 192.168.1.50"

```

**Analyzing a saved trace file offline:**

```bash
python3 network_traffic_analyzer.py -r network_capture.pcap

```

---

## Output Format

Outputs are written directly to `stdout` matching the format below:

```text
[TIMESTAMP] [PROTOCOL] [SRC_IP]:[SRC_PORT] -> [DST_IP]:[DST_PORT] [DETAILS]

```

### Sample Output Log

```text
2025-02-04 13:14:25.398317 DNS  192.168.190.128:35706 -> 8.8.8.8:53 api.global-tech.com
2025-02-04 13:14:25.398317 DNS  192.168.190.128:43054 -> 192.168.190.1:53 esxi1.local INTERNAL 
2025-02-04 13:14:33.224487 HTTP 192.168.190.128:36239 -> 93.184.216.34:80 api.global-tech.com GET /v1/telemetry
2025-02-04 13:14:33.224487 HTTP 192.168.190.128:41239 -> 104.18.27.120:8080 www.example.com GET / AUTOMATION curl/8.17.0
2025-02-04 13:14:24.494045 TLS  192.168.190.128:59330 -> 104.244.42.193:443 google.com
2025-02-04 13:14:24.494045 TLS  192.168.190.128:37741 -> 192.168.190.5:12345 NO SNI

```

---

## Limitations

* **No Stream Reassembly:** Packets are processed individually as standalone units. It does not handle IP defragmentation or complex TCP segment tracking.
* **Scope:** Restricted to cleartext IPv4 traffic. Encrypted variants like DoH/DoT, as well as IPv6 or QUIC (HTTP/3) structures, are explicitly ignored.
